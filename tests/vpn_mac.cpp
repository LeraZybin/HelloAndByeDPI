#include "vpn.h"
#include <iostream>
#include <wx/filename.h>
#include <wx/ffile.h>
#include <unistd.h>
#include <sys/wait.h>

static void Write(const wxString& path, const wxString& contents) {
    wxFFile file(path, "wb");
    auto bytes = contents.utf8_str();
    if (!file.IsOpened() || !file.Write(bytes.data(), bytes.length()))
        throw std::runtime_error("Cannot write shell fixture");
}

// Execute the real supervisor with fake OS commands. No routes, DNS settings or
// privileged processes are changed. Cover ownership and setup failure cleanup.
static bool CheckRouteLifecycle(const wxString& physical, const wxString& mode) {
    wxString dir = wxFileName::CreateTempFileName("byedpi-route-");
    wxRemoveFile(dir); wxFileName::Mkdir(dir);
    const wxString stop = dir + "/stop", status = dir + "/status", log = dir + "/log";
    Write(dir + "/route", "#!/bin/sh\necho \"$*\" >> '" + dir + "/calls'\n"
        "case \"$2\" in\nget)\n"
        "if [ '" + mode + "' = lost ] && [ \"$5\" = 1.1.1.1 ]; then exit 0; fi\n"
        "echo 'gateway: 192.168.3.1'\necho 'interface: " + physical + "'\n"
        "if [ '" + mode + "' = existing ]; then echo 'flags: <UP,GATEWAY,IFSCOPE>'; fi;;\n"
        "add) if [ '" + mode + "' = fail ]; then exit 1; fi;;\nesac\n");
    Write(dir + "/tun", "#!/bin/sh\nexec /bin/sleep 10\n");
    auto script = VpnMacTunnelScript(dir + "/tun", "utun249", "socks5://127.0.0.1:19583",
        physical, getpid(), stop, status, log);
    script.Replace("/sbin/route", "/bin/sh '" + dir + "/route'");
    script.Replace("/sbin/ifconfig", "/usr/bin/true");
    script.Replace("'" + dir + "/tun' --device", "/bin/sh '" + dir + "/tun' --device");
    Write(dir + "/supervisor", script);
    pid_t child = fork();
    if (child == 0) { execl("/bin/sh", "sh", (dir + "/supervisor").utf8_str().data(), static_cast<char*>(nullptr)); _exit(127); }
    int result = 0;
    if (child < 0 || waitpid(child, &result, 0) != child) return false;
    bool ready = false, stopped = false;
    for (int i = 0; i < 100; ++i) {
        if (VpnMacTunnelReady(status)) { ready = true; VpnStopMacTunnel(stop); }
        if (VpnMacTunnelStopped(status)) { stopped = true; break; }
        usleep(50000);
    }
    wxString calls; { wxFFile file(dir + "/calls", "rb"); file.ReadAll(&calls); }
    const bool expectedReady = mode == "new" || mode == "existing";
    const bool owned = mode == "new" || mode == "lost";
    const bool ok = stopped && ready == expectedReady &&
        calls.Contains("delete -ifscope") == owned &&
        calls.Contains("add -ifscope") == (mode != "existing") &&
        (!expectedReady || calls.Find("get -ifscope " + physical + " 1.1.1.1") != wxNOT_FOUND);
    if (!ok) std::cerr << "Route lifecycle failed: " << mode.ToStdString() << "\n";
    wxFileName::Rmdir(dir, wxPATH_RMDIR_RECURSIVE);
    return ok;
}

int main(int argc, char** argv) {
    try {
        if (argc == 2 && std::string(argv[1]) == "--preflight-only") {
            const auto conflict = VpnFindActiveTunnel();
            std::cout << (conflict.empty() ? "No active VPN" : "Blocked: " + conflict.ToStdString()) << "\n";
            return 0;
        }
        if (!VpnAdapterReady("lo0")) return 1;
        auto physical = VpnFindPhysicalNetwork();
        if (physical.address.empty() || physical.interfaceName.empty() ||
            physical.interfaceName.StartsWith("utun") || physical.interfaceIndex == 0) return 2;
        for (const char* dns : {"", "1.1.1.1"}) {
            auto script = VpnMacTunnelScript("/tmp/test ' tunnel", "utun249", "socks5://127.0.0.1:19583",
                physical.interfaceName, getpid(), "/tmp/test ' stop", "/tmp/test ' status", "/tmp/test ' log", dns);
            wxString path = wxFileName::CreateTempFileName("byedpi-vpn-shell-");
            { wxFFile file(path, "wb"); auto bytes = script.utf8_str(); if (!file.Write(bytes.data(), bytes.length())) return 4; }
            pid_t child = fork();
            if (child == 0) { execl("/bin/sh", "sh", "-n", path.utf8_str().data(), static_cast<char*>(nullptr)); _exit(127); }
            int status = 0; if (child < 0 || waitpid(child, &status, 0) != child) return 5;
            wxRemoveFile(path);
            if (!WIFEXITED(status) || WEXITSTATUS(status) != 0) return 6;
        }
        for (const char* mode : {"new", "existing", "fail", "lost"})
            if (!CheckRouteLifecycle(physical.interfaceName, mode)) return 7;
        std::cout << physical.interfaceName.ToStdString() << " " << physical.address.ToStdString() << "\n";
        return 0;
    } catch (const std::exception& error) {
        std::cerr << error.what() << "\n";
        return 3;
    }
}
