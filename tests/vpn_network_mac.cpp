#include "vpn.h"
#include "http_probe.h"
#include "diagnostics.h"
#include <wx/init.h>
#include <wx/filename.h>
#include <unistd.h>
#include <sys/wait.h>
#include <signal.h>
#include <chrono>
#include <thread>
#include <iostream>

namespace {
void Pause() { std::this_thread::sleep_for(std::chrono::milliseconds(100)); }
struct Session {
    pid_t engine = -1;
    wxString device, stop, status;
    bool authorized = false;
    ~Session() {
        if (!stop.empty()) {
            VpnStopMacTunnel(stop);
            for (int i = 0; i < 150 && (VpnAdapterReady(device) || (authorized && !VpnMacTunnelStopped(status))); ++i) Pause();
        }
        if (engine > 0) { kill(engine, SIGKILL); waitpid(engine, nullptr, 0); }
    }
};
bool Check(const char* label, const std::string& url, int port) {
    ProbeBatch batch({url}, 1, 12, 1, port, "", true);
    bool success = false;
    while (!batch.Done()) {
        for (const auto& result : batch.Poll()) {
            std::cout << label << ": HTTP=" << result.http << " available=" << result.available
                      << " code=" << result.transportCode << " local=" << result.localAddress
                      << " remote=" << result.remoteAddress << " effective=" << result.effectiveUrl
                      << " dns_ms=" << result.dnsMilliseconds << " connect_ms=" << result.connectMilliseconds
                      << " tls_ms=" << result.tlsMilliseconds << " total_ms=" << result.milliseconds
                      << " error=" << result.error << '\n' << result.diagnostic << std::endl;
            success = result.available;
        }
        Pause();
    }
    return success;
}
}

// Explicit network integration test, excluded from CTest: it requires one
// administrator authorization and briefly installs full IPv4 tunnel routes.
int main(int argc, char** argv) {
    if (argc != 4) return 2; // engine, tun2socks, external HTTPS URL
    wxInitializer init;
    if (!init) return 3;
    Session session;
    std::cout << "Probe runtime: " << ProbeRuntime() << std::endl;
    try {
        const auto physical = VpnFindPhysicalNetwork();
        const std::string address = physical.address.ToStdString();
        std::cout << "Physical: " << physical.interfaceName << " " << address << std::endl;
        session.engine = fork();
        if (session.engine == 0) {
            execl(argv[1], argv[1], "--ip", "127.0.0.1", "--port", "19583", "--debug", "1",
                  "--conn-ip", address.c_str(), static_cast<char*>(nullptr));
            _exit(127);
        }
        if (session.engine < 0) return 4;
        Pause();
        if (!Check("SOCKS before VPN", argv[3], 19583)) return 5;
        session.device = "utun233";
        for (int unit = 233; unit < 250 && VpnAdapterReady(session.device); ++unit)
            session.device = wxString::Format("utun%d", unit + 1);
        if (VpnAdapterReady(session.device)) return 6;
        wxString prefix = DiagnosticDirectory("/tmp") + wxString::Format("/org.helloandbyedpi.network.%ld", static_cast<long>(getpid()));
        std::cout << "Tunnel log: " << prefix << ".log" << std::endl;
        session.stop = prefix + ".stop";
        wxString status = prefix + ".status"; session.status = status;
        wxString dns; wxGetEnv("HELLOBYE_TEST_DNS", &dns);
        std::cout << VpnStartMacTunnel(wxString::FromUTF8(argv[2]), session.device,
            "socks5://127.0.0.1:19583", physical.interfaceName, getpid(), session.stop, status,
            prefix + ".log", dns) << std::endl;
        session.authorized = true;
        bool ready = false;
        for (int i = 0; i < 150; ++i) {
            if (VpnAdapterReady(session.device) && VpnMacTunnelReady(status)) { ready = true; break; }
            Pause();
        }
        if (!ready) return 7;
        // ByeDPI resolves SOCKS hostnames synchronously. While system DNS is
        // routed through this same engine that would block its event loop on
        // its own DNS traffic. Test the actual VPN path (curl resolves before
        // connecting), keeping hostname SOCKS checks outside the tunnel.
        bool routed = Check("OS-routed HTTPS during VPN", argv[3], 0);
        if (!routed) return 8;
        VpnStopMacTunnel(session.stop);
        for (int i = 0; i < 100 && (VpnAdapterReady(session.device) || !VpnMacTunnelStopped(status)); ++i) Pause();
        if (VpnAdapterReady(session.device)) return 9;
        if (!Check("SOCKS after VPN", argv[3], 19583)) return 10;
        std::cout << "External HTTPS through VPN and cleanup passed" << std::endl;
        return 0;
    } catch (const std::exception& error) {
        std::cerr << error.what() << std::endl;
        return 11;
    }
}
