#include "vpn.h"
#include "diagnostics.h"
#include "vpn_detection.h"

#include <SystemConfiguration/SystemConfiguration.h>
#include <arpa/inet.h>
#include <ifaddrs.h>
#include <net/if.h>
#include <sys/wait.h>
#include <unistd.h>
#include <cerrno>
#include <cstdio>
#include <cstring>
#include <stdexcept>
#include <string>

namespace {
std::string Utf8(const wxString& value) {
    const auto bytes = value.utf8_str();
    return std::string(bytes.data(), bytes.length());
}

void ValidateInterface(const wxString& value) {
    if (value.empty()) throw std::runtime_error("VPN interface name is empty.");
    for (wxUniChar character : value)
        if (!(character >= 'a' && character <= 'z') &&
            !(character >= 'A' && character <= 'Z') &&
            !(character >= '0' && character <= '9'))
            throw std::runtime_error("VPN interface name contains invalid characters.");
}

wxString RunAppleScript(const std::string& script) {
    int pipes[2];
    if (pipe(pipes) != 0) throw std::runtime_error(std::string("pipe failed: ") + std::strerror(errno));
    pid_t child = fork();
    if (child < 0) {
        close(pipes[0]); close(pipes[1]);
        throw std::runtime_error(std::string("fork failed: ") + std::strerror(errno));
    }
    if (child == 0) {
        dup2(pipes[1], STDOUT_FILENO); dup2(pipes[1], STDERR_FILENO);
        close(pipes[0]); close(pipes[1]);
        execl("/usr/bin/osascript", "osascript", "-e", script.c_str(), static_cast<char*>(nullptr));
        _exit(127);
    }
    close(pipes[1]);
    std::string output;
    char buffer[2048];
    ssize_t count;
    while ((count = read(pipes[0], buffer, sizeof(buffer))) > 0) output.append(buffer, static_cast<size_t>(count));
    close(pipes[0]);
    int status = 0;
    while (waitpid(child, &status, 0) < 0 && errno == EINTR) {}
    while (!output.empty() && (output.back() == '\n' || output.back() == '\r')) output.pop_back();
    if (!WIFEXITED(status) || WEXITSTATUS(status) != 0)
        throw std::runtime_error(output.empty() ? "macOS VPN authorization was cancelled or failed." : output);
    return output.empty() ? "osascript exit=0" : wxString::FromUTF8(output);
}

std::string ShellQuote(const wxString& value) {
    std::string input = Utf8(value), result = "'";
    for (char character : input) result += character == '\'' ? "'\\''" : std::string(1, character);
    return result + "'";
}

std::string AppleScriptQuote(const std::string& value) {
    std::string result = "\"";
    for (char character : value) {
        if (character == '\\' || character == '\"') result += '\\';
        result += character;
    }
    return result + "\"";
}

wxString PrimaryInterface() {
    SCDynamicStoreRef store = SCDynamicStoreCreate(nullptr, CFSTR("HelloAndByeDPI"), nullptr, nullptr);
    if (!store) return wxString();
    CFDictionaryRef value = static_cast<CFDictionaryRef>(
        SCDynamicStoreCopyValue(store, CFSTR("State:/Network/Global/IPv4")));
    CFRelease(store);
    if (!value) return wxString();
    CFStringRef name = static_cast<CFStringRef>(CFDictionaryGetValue(value, CFSTR("PrimaryInterface")));
    char bytes[IFNAMSIZ] = {};
    bool valid = name && CFStringGetCString(name, bytes, sizeof(bytes), kCFStringEncodingUTF8);
    CFRelease(value);
    return valid ? wxString::FromUTF8(bytes) : wxString();
}

wxString NetworkService(const wxString& interfaceName) {
    SCPreferencesRef preferences = SCPreferencesCreate(nullptr, CFSTR("HelloAndByeDPI"), nullptr);
    if (!preferences) throw std::runtime_error("Could not read network services.");
    CFArrayRef services = SCNetworkServiceCopyAll(preferences);
    wxString result;
    if (services) {
        for (CFIndex i = 0; i < CFArrayGetCount(services); ++i) {
            SCNetworkServiceRef service = static_cast<SCNetworkServiceRef>(const_cast<void*>(CFArrayGetValueAtIndex(services, i)));
            SCNetworkInterfaceRef interface = SCNetworkServiceGetInterface(service);
            CFStringRef bsd = interface ? SCNetworkInterfaceGetBSDName(interface) : nullptr;
            char name[IFNAMSIZ] = {}, label[1024] = {};
            CFStringRef display = SCNetworkServiceGetName(service);
            if (SCNetworkServiceGetEnabled(service) && bsd && display &&
                CFStringGetCString(bsd, name, sizeof(name), kCFStringEncodingUTF8) &&
                wxString::FromUTF8(name) == interfaceName &&
                CFStringGetCString(display, label, sizeof(label), kCFStringEncodingUTF8)) {
                result = wxString::FromUTF8(label); break;
            }
        }
        CFRelease(services);
    }
    CFRelease(preferences);
    if (result.empty()) throw std::runtime_error("Could not find the physical network service for DNS.");
    return result;
}
}

bool VpnIsAdministrator() { return geteuid() == 0; }
bool VpnRelaunchElevated(const wxString&, bool) { return false; }

wxString VpnFindActiveTunnel() {
    // Also catch connected split-tunnel services whose routes may not include
    // any of the public probe addresses below.
    SCPreferencesRef preferences = SCPreferencesCreate(nullptr, CFSTR("HelloAndByeDPI"), nullptr);
    CFArrayRef services = preferences ? SCNetworkServiceCopyAll(preferences) : nullptr;
    wxString connected;
    if (services) {
        for (CFIndex i = 0; i < CFArrayGetCount(services); ++i) {
            auto service = static_cast<SCNetworkServiceRef>(const_cast<void*>(CFArrayGetValueAtIndex(services, i)));
            auto interface = SCNetworkServiceGetInterface(service);
            auto type = interface ? SCNetworkInterfaceGetInterfaceType(interface) : nullptr;
            if (!type || !(CFEqual(type, kSCNetworkInterfaceTypePPP) ||
                CFEqual(type, kSCNetworkInterfaceTypeIPSec) || CFEqual(type, CFSTR("VPN")))) continue;
            auto connection = SCNetworkConnectionCreateWithServiceID(nullptr, SCNetworkServiceGetServiceID(service), nullptr, nullptr);
            if (!connection) continue;
            const auto state = SCNetworkConnectionGetStatus(connection);
            CFRelease(connection);
            if (state != kSCNetworkConnectionConnected && state != kSCNetworkConnectionConnecting) continue;
            char name[1024] = {};
            auto label = SCNetworkServiceGetName(service);
            connected = label && CFStringGetCString(label, name, sizeof(name), kCFStringEncodingUTF8)
                ? wxString::FromUTF8(name) : wxString("VPN");
            break;
        }
        CFRelease(services);
    }
    if (preferences) CFRelease(preferences);
    if (!connected.empty()) return connected;
    // Merely having utun interfaces is normal on macOS. Only block when one
    // actually routes public traffic; idle Apple/other VPN adapters are harmless.
    for (const char* destination : {"1.1.1.1", "208.67.222.222", "8.8.8.8"}) {
        const std::string command = std::string("/sbin/route -n get ") + destination + " 2>&1";
        FILE* pipe = popen(command.c_str(), "r");
        if (!pipe) throw std::runtime_error("Cannot query the routing table.");
        std::string output; char buffer[1024];
        while (fgets(buffer, sizeof(buffer), pipe)) output += buffer;
        const int status = pclose(pipe);
        const std::string interface = MacRouteInterface(output);
        if (status != 0 || interface.empty()) throw std::runtime_error("No IPv4 route for VPN preflight.");
        if (MacTunnelInterface(interface)) return wxString::FromUTF8(interface);
    }
    return "";
}

VpnPhysicalNetwork VpnFindPhysicalNetwork() {
    wxString preferred = PrimaryInterface();
    struct ifaddrs* addresses = nullptr;
    if (getifaddrs(&addresses) != 0) throw std::runtime_error(std::string("getifaddrs failed: ") + std::strerror(errno));
    VpnPhysicalNetwork result("", 0);
    for (auto item = addresses; item; item = item->ifa_next) {
        if (!item->ifa_addr || item->ifa_addr->sa_family != AF_INET) continue;
        wxString name = wxString::FromUTF8(item->ifa_name);
        const bool physical = (item->ifa_flags & IFF_UP) && (item->ifa_flags & IFF_RUNNING) &&
            !(item->ifa_flags & IFF_LOOPBACK) && !(item->ifa_flags & IFF_POINTOPOINT) &&
            !name.StartsWith("utun");
        if (!physical || (!result.address.empty() && name != preferred)) continue;
        char text[INET_ADDRSTRLEN] = {};
        auto address = reinterpret_cast<sockaddr_in*>(item->ifa_addr);
        if (!inet_ntop(AF_INET, &address->sin_addr, text, sizeof(text)) ||
            wxString::FromUTF8(text).StartsWith("169.254.")) continue;
        result = VpnPhysicalNetwork(wxString::FromUTF8(text), if_nametoindex(item->ifa_name), name);
        if (name == preferred) break;
    }
    freeifaddrs(addresses);
    if (result.address.empty()) throw std::runtime_error("The primary macOS interface has no IPv4 address.");
    return result;
}

bool VpnAdapterReady(const wxString& deviceName) {
    ValidateInterface(deviceName);
    return if_nametoindex(Utf8(deviceName).c_str()) != 0;
}

wxString VpnConfigure(const wxString& deviceName, const wxString&) {
    ValidateInterface(deviceName);
    const std::string device = Utf8(deviceName);
    const std::string commands =
        "/sbin/ifconfig " + device + " inet 198.18.0.1 198.18.0.1 up && "
        "/sbin/route -n add -net 0.0.0.0/1 -interface " + device + " && "
        "(/sbin/route -n add -net 128.0.0.0/1 -interface " + device +
        " || { /sbin/route -n delete -net 0.0.0.0/1 -interface " + device + "; exit 1; })";
    return RunAppleScript("do shell script \"" + commands + "\" with administrator privileges");
}

wxString VpnCleanup(const wxString&) {
    // macOS removes interface routes when tun2socks closes its utun device.
    return "utun routes are removed with the adapter";
}

wxString VpnMacTunnelScript(const wxString& tun2socks, const wxString& deviceName,
    const wxString& proxy, const wxString& physicalInterface, unsigned long parentPid,
    const wxString& stopFile, const wxString& statusFile, const wxString& logFile,
    const wxString& dnsServer) {
    ValidateInterface(deviceName); ValidateInterface(physicalInterface);
    const std::string tun = ShellQuote(tun2socks), device = ShellQuote(deviceName);
    const std::string stop = ShellQuote(stopFile), status = ShellQuote(statusFile);
    const std::string log = DiagnosticLogging() ? ShellQuote(logFile) : "/dev/null";
    std::string dnsSetup, dnsCleanup;
    if (!dnsServer.empty()) {
        in_addr parsed = {};
        if (inet_pton(AF_INET, Utf8(dnsServer).c_str(), &parsed) != 1)
            throw std::runtime_error("DNS must be an IPv4 address.");
        const std::string service = ShellQuote(NetworkService(physicalInterface)), dns = ShellQuote(dnsServer);
        dnsSetup = "old_dns=$(/usr/sbin/networksetup -getdnsservers " + service + ") || exit 1; "
            "echo 'Saving original DNS for ' " + service + "; printf '%s\\n' \"$old_dns\"; "
            "dns_changed=1; /usr/sbin/networksetup -setdnsservers " + service + " " + dns + " || exit 1; "
            "echo 'Applied DNS: ' " + dns + "; ";
        dnsCleanup = "if [ \"$dns_changed\" = 1 ]; then "
            "current_dns=$(/usr/sbin/networksetup -getdnsservers " + service + "); "
            "if [ \"$current_dns\" = " + dns + " ]; then "
            "case \"$old_dns\" in *'There aren'*|'') /usr/sbin/networksetup -setdnsservers " + service + " Empty ;; "
            "*) set -- $old_dns; /usr/sbin/networksetup -setdnsservers " + service + " \"$@\" ;; esac; "
            "dns_restore_status=$?; if [ \"$dns_restore_status\" = 0 ]; then echo 'Original DNS restored'; "
            "else echo 'ERROR: original DNS restore failed'; fi; "
            "else echo 'DNS changed externally; leaving current settings'; fi; fi; ";
    }
    const std::string physical = ShellQuote(physicalInterface);
    // IP_BOUND_IF sockets need an explicitly scoped route once the unscoped /1
    // routes point into utun. A plain default alone stops working at that point.
    const std::string routeSetup =
        "physical_route=$(/sbin/route -n get -ifscope " + physical + " default 2>&1); "
        "physical_gateway=$(printf '%s\\n' \"$physical_route\" | /usr/bin/awk '/gateway:/ {print $2}'); "
        "physical_device=$(printf '%s\\n' \"$physical_route\" | /usr/bin/awk '/interface:/ {print $2}'); "
        "[ -n \"$physical_gateway\" ] && [ \"$physical_device\" = " + physical +
        " ] || { echo 'ERROR: no physical IPv4 default gateway'; exit 1; }; "
        "case \"$physical_route\" in *IFSCOPE*) echo 'Reusing scoped physical default';; "
        "*) /sbin/route -n add -ifscope " + physical + " default \"$physical_gateway\" || exit 1; "
        "physical_route_added=1; echo 'Added scoped physical default via ' \"$physical_gateway\";; esac; ";
    const std::string routeCleanup =
        "if [ \"$physical_route_added\" = 1 ]; then "
        "/sbin/route -n delete -ifscope " + physical + " default \"$physical_gateway\"; "
        "if [ $? = 0 ]; then echo 'Scoped physical default removed'; "
        "else echo 'ERROR: scoped physical default cleanup failed'; fi; fi; ";
    const std::string cleanup = "[ -z \"$child\" ] || { kill $child 2>/dev/null; wait $child 2>/dev/null; }; " + dnsCleanup + routeCleanup + "echo stopped > " + status;
    const std::string command =
        "cd /; rm -f " + stop + " " + status + "; ( "
        "child=''; dns_changed=0; physical_route_added=0; trap " + ShellQuote(wxString::FromUTF8(cleanup)) + " EXIT TERM INT; " + routeSetup + dnsSetup +
        tun + " --device " + device + " --proxy " + ShellQuote(proxy) + " --interface " +
        ShellQuote(physicalInterface) + " --mtu 1500 --loglevel " +
        (DiagnosticLogging() ? "debug" : "silent") + " >> " + log + " 2>&1 & child=$!; "
        "i=0; while [ $i -lt 100 ] && ! /sbin/ifconfig " + device + " >/dev/null 2>&1; do "
        "kill -0 $child 2>/dev/null || exit 1; i=$((i+1)); sleep 0.1; done; "
        "kill -0 $child 2>/dev/null || exit 1; "
        "/sbin/ifconfig " + device + " inet 198.18.0.1 198.18.0.1 up && "
        "/sbin/route -n add -net 0.0.0.0/1 -interface " + device + " && "
        "(/sbin/route -n add -net 128.0.0.0/1 -interface " + device +
        " || { /sbin/route -n delete -net 0.0.0.0/1 -interface " + device + "; exit 1; }) || exit 1; "
        "physical_check=$(/sbin/route -n get -ifscope " + physical + " 1.1.1.1 2>&1); "
        "printf '%s\\n' \"$physical_check\"; "
        "physical_device=$(printf '%s\\n' \"$physical_check\" | /usr/bin/awk '/interface:/ {print $2}'); "
        "[ \"$physical_device\" = " + physical + " ] || { echo 'ERROR: physical egress route lost'; exit 1; }; "
        "echo ready > " + status + " || exit 1; "
        "while kill -0 $child 2>/dev/null && kill -0 " + std::to_string(parentPid) + " 2>/dev/null && [ ! -e " + stop + " ]; do sleep 1; done "
        ") >> " + log + " 2>&1 < /dev/null &";
    return wxString::FromUTF8(command);
}

wxString VpnStartMacTunnel(const wxString& tun2socks, const wxString& deviceName,
    const wxString& proxy, const wxString& physicalInterface, unsigned long parentPid,
    const wxString& stopFile, const wxString& statusFile, const wxString& logFile,
    const wxString& dnsServer) {
    return RunAppleScript("do shell script " + AppleScriptQuote(Utf8(VpnMacTunnelScript(tun2socks,
        deviceName, proxy, physicalInterface, parentPid, stopFile, statusFile, logFile, dnsServer))) +
        " with administrator privileges");
}

bool VpnMacTunnelReady(const wxString& statusFile) {
    FILE* file = std::fopen(Utf8(statusFile).c_str(), "r");
    if (!file) return false;
    char value[16] = {};
    const bool ready = std::fgets(value, sizeof(value), file) && std::string(value).find("ready") == 0;
    std::fclose(file);
    return ready;
}

bool VpnMacTunnelStopped(const wxString& statusFile) {
    FILE* file = std::fopen(Utf8(statusFile).c_str(), "r");
    if (!file) return false;
    char value[16] = {};
    const bool stopped = std::fgets(value, sizeof(value), file) && std::string(value).find("stopped") == 0;
    std::fclose(file); return stopped;
}

void VpnStopMacTunnel(const wxString& stopFile) {
    FILE* file = std::fopen(Utf8(stopFile).c_str(), "w");
    if (file) { std::fputs("stop\n", file); std::fclose(file); }
}
