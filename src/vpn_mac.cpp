#include "vpn.h"

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
}

bool VpnIsAdministrator() { return geteuid() == 0; }
bool VpnRelaunchElevated(const wxString&) { return false; }

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

wxString VpnStartMacTunnel(const wxString& tun2socks, const wxString& deviceName,
    const wxString& proxy, const wxString& physicalInterface, unsigned long parentPid,
    const wxString& stopFile, const wxString& statusFile, const wxString& logFile) {
    ValidateInterface(deviceName); ValidateInterface(physicalInterface);
    const std::string tun = ShellQuote(tun2socks), device = ShellQuote(deviceName);
    const std::string stop = ShellQuote(stopFile), status = ShellQuote(statusFile), log = ShellQuote(logFile);
    const std::string command =
        "rm -f " + stop + " " + status + "; ( "
        "trap 'kill $child 2>/dev/null; wait $child 2>/dev/null' EXIT TERM INT; " +
        tun + " --device " + device + " --proxy " + ShellQuote(proxy) + " --interface " +
        ShellQuote(physicalInterface) + " --mtu 1500 --loglevel warn >> " + log + " 2>&1 & child=$!; "
        "i=0; while [ $i -lt 100 ] && ! /sbin/ifconfig " + device + " >/dev/null 2>&1; do "
        "kill -0 $child 2>/dev/null || exit 1; i=$((i+1)); sleep 0.1; done; "
        "kill -0 $child 2>/dev/null || exit 1; "
        "/sbin/ifconfig " + device + " inet 198.18.0.1 198.18.0.1 up && "
        "/sbin/route -n add -net 0.0.0.0/1 -interface " + device + " && "
        "(/sbin/route -n add -net 128.0.0.0/1 -interface " + device +
        " || { /sbin/route -n delete -net 0.0.0.0/1 -interface " + device + "; exit 1; }) && "
        "echo ready > " + status + "; "
        "while kill -0 " + std::to_string(parentPid) + " 2>/dev/null && [ ! -e " + stop + " ]; do sleep 1; done "
        ") >> " + log + " 2>&1 < /dev/null &";
    return RunAppleScript("do shell script " + AppleScriptQuote(command) + " with administrator privileges");
}

bool VpnMacTunnelReady(const wxString& statusFile) {
    FILE* file = std::fopen(Utf8(statusFile).c_str(), "r");
    if (!file) return false;
    char value[16] = {};
    const bool ready = std::fgets(value, sizeof(value), file) && std::string(value).find("ready") == 0;
    std::fclose(file);
    return ready;
}

void VpnStopMacTunnel(const wxString& stopFile) {
    FILE* file = std::fopen(Utf8(stopFile).c_str(), "w");
    if (file) { std::fputs("stop\n", file); std::fclose(file); }
}
