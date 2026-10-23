#include "vpn.h"
#include "vpn_detection.h"
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <shellapi.h>
#include <iphlpapi.h>
#include <iptypes.h>
#include <wx/utils.h>
#include <vector>
#include <stdexcept>
#include <cstring>

namespace {
const wchar_t* AdapterName = L"HelloAndByeDPI";

std::runtime_error Error(const char* text, DWORD code = GetLastError()) {
    return std::runtime_error(std::string(text) + " (Windows error " + std::to_string(code) + ")");
}

wxString Run(const std::vector<wxString>& arguments, bool required) {
    wxString command;
    for (const auto& argument : arguments) command += wxString(command.empty() ? "" : " ") + "\"" + argument + "\"";
    SECURITY_ATTRIBUTES security = {sizeof(security), nullptr, TRUE};
    HANDLE readPipe = nullptr, writePipe = nullptr;
    if (!CreatePipe(&readPipe, &writePipe, &security, 65536)) throw Error("Could not create netsh output pipe");
    SetHandleInformation(readPipe, HANDLE_FLAG_INHERIT, 0);
    STARTUPINFOW startup = {}; startup.cb = sizeof(startup);
    startup.dwFlags = STARTF_USESTDHANDLES;
    startup.hStdOutput = writePipe; startup.hStdError = writePipe;
    PROCESS_INFORMATION process = {};
    std::vector<wchar_t> mutableCommand(command.length() + 1);
    memcpy(mutableCommand.data(), command.wc_str(), mutableCommand.size() * sizeof(wchar_t));
    BOOL started = CreateProcessW(nullptr, mutableCommand.data(), nullptr, nullptr, TRUE,
        CREATE_NO_WINDOW, nullptr, nullptr, &startup, &process);
    CloseHandle(writePipe);
    if (!started) { CloseHandle(readPipe); throw Error("Could not start netsh"); }
    DWORD wait = WaitForSingleObject(process.hProcess, 30000);
    if (wait == WAIT_TIMEOUT) {
        TerminateProcess(process.hProcess, 124);
        WaitForSingleObject(process.hProcess, 3000);
    }
    DWORD exitCode = 1;
    GetExitCodeProcess(process.hProcess, &exitCode);
    CloseHandle(process.hThread); CloseHandle(process.hProcess);
    std::string output;
    char bytes[4096]; DWORD count = 0;
    while (ReadFile(readPipe, bytes, sizeof(bytes), &count, nullptr) && count) output.append(bytes, count);
    CloseHandle(readPipe);
    int wideLength = output.empty() ? 0 : MultiByteToWideChar(CP_OEMCP, 0, output.data(), static_cast<int>(output.size()), nullptr, 0);
    std::vector<wchar_t> wide(wideLength);
    if (wideLength) MultiByteToWideChar(CP_OEMCP, 0, output.data(), static_cast<int>(output.size()), wide.data(), wideLength);
    wxString diagnostic = wideLength ? wxString(wide.data(), wideLength) : wxString();
    diagnostic.Trim();
    if (required && exitCode != 0)
        throw std::runtime_error("netsh exited with code " + std::to_string(exitCode) + ": " + diagnostic.ToStdString(wxConvUTF8));
    return wxString::Format("netsh exit=%lu", static_cast<unsigned long>(exitCode)) +
        (wait == WAIT_TIMEOUT ? ": timed out" : diagnostic.empty() ? "" : ": " + diagnostic);
}

std::vector<wxString> Netsh(std::initializer_list<const wchar_t*> tail) {
    std::vector<wxString> result{L"netsh.exe"};
    for (auto item : tail) result.push_back(item);
    return result;
}
}

bool VpnIsAdministrator() {
    BOOL member = FALSE;
    SID_IDENTIFIER_AUTHORITY authority = SECURITY_NT_AUTHORITY;
    PSID administrators = nullptr;
    if (AllocateAndInitializeSid(&authority, 2, SECURITY_BUILTIN_DOMAIN_RID,
        DOMAIN_ALIAS_RID_ADMINS, 0, 0, 0, 0, 0, 0, &administrators)) {
        CheckTokenMembership(nullptr, administrators, &member);
        FreeSid(administrators);
    }
    return member != FALSE;
}

bool VpnRelaunchElevated(const wxString& executable, bool policyTests) {
    HINSTANCE result = ShellExecuteW(nullptr, L"runas", executable.wc_str(), policyTests ? L"--test-vpn" : L"--start-vpn",
        wxString(executable).BeforeLast('\\').wc_str(), SW_SHOWNORMAL);
    return reinterpret_cast<INT_PTR>(result) > 32;
}

wxString VpnFindActiveTunnel() {
    ULONG size = 16384, status = ERROR_BUFFER_OVERFLOW;
    std::vector<unsigned char> storage;
    for (int attempt = 0; attempt < 3 && status == ERROR_BUFFER_OVERFLOW; ++attempt) {
        storage.resize(size);
        status = GetAdaptersAddresses(AF_INET, GAA_FLAG_INCLUDE_PREFIX, nullptr,
            reinterpret_cast<PIP_ADAPTER_ADDRESSES>(storage.data()), &size);
    }
    if (status != NO_ERROR) throw Error("Could not inspect active VPN adapters", status);
    std::vector<DWORD> routed;
    for (const char* target : {"1.1.1.1", "208.67.222.222", "8.8.8.8"}) {
        in_addr address = {}; inet_pton(AF_INET, target, &address);
        MIB_IPFORWARDROW route = {};
        status = GetBestRoute(address.s_addr, 0, &route);
        if (status != NO_ERROR) throw Error("Could not check the current route", status);
        routed.push_back(route.dwForwardIfIndex);
    }
    for (auto item = reinterpret_cast<PIP_ADAPTER_ADDRESSES>(storage.data()); item; item = item->Next) {
        if (item->OperStatus != IfOperStatusUp || !item->FirstUnicastAddress) continue;
        const wxString name = item->FriendlyName ? wxString(item->FriendlyName) : "";
        const wxString description = item->Description ? wxString(item->Description) : "";
        const std::string label = (name + " " + description).ToStdString(wxConvUTF8);
        const bool selected = std::find(routed.begin(), routed.end(), item->IfIndex) != routed.end();
        // Ignore unrelated built-in transition tunnels (e.g. Teredo), but catch
        // connected named VPN adapters even when they use split routing.
        if (WindowsTunnelAdapter(selected ? item->IfType : 0, label) || item->IfType == IF_TYPE_PPP)
            return name.empty() ? description : name;
    }
    return "";
}

VpnPhysicalNetwork VpnFindPhysicalNetwork() {
    MIB_IPFORWARDROW route = {};
    in_addr destination = {};
    inet_pton(AF_INET, "1.1.1.1", &destination);
    DWORD routeStatus = GetBestRoute(destination.s_addr, 0, &route);
    if (routeStatus != NO_ERROR) throw Error("Could not find the physical default route", routeStatus);
    ULONG size = 0;
    GetIpAddrTable(nullptr, &size, FALSE);
    std::vector<unsigned char> storage(size);
    auto table = reinterpret_cast<PMIB_IPADDRTABLE>(storage.data());
    DWORD status = GetIpAddrTable(table, &size, FALSE);
    if (status != NO_ERROR) throw Error("Could not read physical interface addresses", status);
    for (DWORD i = 0; i < table->dwNumEntries; ++i) if (table->table[i].dwIndex == route.dwForwardIfIndex) {
        in_addr address = {}; address.s_addr = table->table[i].dwAddr;
        char text[INET_ADDRSTRLEN] = {};
        if (inet_ntop(AF_INET, &address, text, sizeof(text)) && std::string(text) != "0.0.0.0")
            return {wxString::FromUTF8(text), route.dwForwardIfIndex};
    }
    throw std::runtime_error("Physical interface has no IPv4 address.");
}

bool VpnAdapterReady(const wxString&) {
    ULONG size = 16384;
    std::vector<unsigned char> storage(size);
    auto adapters = reinterpret_cast<PIP_ADAPTER_ADDRESSES>(storage.data());
    ULONG status = GetAdaptersAddresses(AF_INET, GAA_FLAG_INCLUDE_PREFIX, nullptr, adapters, &size);
    if (status == ERROR_BUFFER_OVERFLOW) {
        storage.resize(size); adapters = reinterpret_cast<PIP_ADAPTER_ADDRESSES>(storage.data());
        status = GetAdaptersAddresses(AF_INET, GAA_FLAG_INCLUDE_PREFIX, nullptr, adapters, &size);
    }
    if (status != NO_ERROR) return false;
    for (auto item = adapters; item; item = item->Next)
        if (item->FriendlyName && _wcsicmp(item->FriendlyName, AdapterName) == 0) return true;
    return false;
}

wxString VpnConfigure(const wxString&, const wxString& dnsServer) {
    wxString log;
    log += Run(Netsh({L"interface", L"ipv4", L"set", L"address", L"name=HelloAndByeDPI",
        L"source=static", L"address=198.18.0.1", L"mask=255.255.255.0", L"gateway=none"}), true) + "\n";
    std::vector<wxString> dns{L"netsh.exe", L"interface", L"ipv4", L"set", L"dnsservers",
        L"name=HelloAndByeDPI", L"source=static", "address=" + dnsServer, L"register=none", L"validate=no"};
    if (dnsServer.empty()) dns = Netsh({L"interface", L"ipv4", L"set", L"dnsservers", L"name=HelloAndByeDPI", L"source=dhcp"});
    log += Run(dns, true) + "\n";
    log += Run(Netsh({L"interface", L"ipv4", L"add", L"route", L"prefix=0.0.0.0/1",
        L"interface=HelloAndByeDPI", L"nexthop=198.18.0.1", L"metric=1", L"store=active"}), true) + "\n";
    log += Run(Netsh({L"interface", L"ipv4", L"add", L"route", L"prefix=128.0.0.0/1",
        L"interface=HelloAndByeDPI", L"nexthop=198.18.0.1", L"metric=1", L"store=active"}), true);
    return log;
}

wxString VpnCleanup(const wxString&) {
    wxString log;
    log += Run(Netsh({L"interface", L"ipv4", L"delete", L"route", L"prefix=0.0.0.0/1",
        L"interface=HelloAndByeDPI", L"store=active"}), false) + "\n";
    log += Run(Netsh({L"interface", L"ipv4", L"delete", L"route", L"prefix=128.0.0.0/1",
        L"interface=HelloAndByeDPI", L"store=active"}), false);
    return log;
}
