#include "vpn_detection.h"
#include <iostream>

int main() {
    if (MacRouteInterface("route to: 1.1.1.1\n interface: utun13\n flags: <UP>\n") != "utun13") return 1;
    if (!MacRouteInterface("route: writing to routing socket: not in table\n").empty()) return 2;
    if (MacRouteInterface("interface: en0\n") != "en0") return 3;
    for (const char* name : {"utun13", "tun0", "tap0", "ppp0", "ipsec0"})
        if (!MacTunnelInterface(name)) return 4;
    for (const char* name : {"en0", "en7", "lo0", "bridge0"})
        if (MacTunnelInterface(name)) return 5;
    if (!WindowsTunnelAdapter(23, "Work") || !WindowsTunnelAdapter(131, "Tunnel")) return 6;
    for (const char* label : {"Wintun Userspace Tunnel", "WireGuard Tunnel", "TAP-Windows Adapter V9", "Tailscale", "OpenVPN"})
        if (!WindowsTunnelAdapter(6, label)) return 7;
    for (const char* label : {"Intel Wi-Fi", "Realtek Ethernet", "Hyper-V Virtual Ethernet Adapter", "VirtualBox Host-Only Ethernet Adapter"})
        if (WindowsTunnelAdapter(6, label)) return 8;
    std::cout << "VPN route and adapter detection passed\n";
}
