#pragma once
#include <algorithm>
#include <cctype>
#include <sstream>
#include <string>

inline std::string MacRouteInterface(const std::string& output) {
    std::istringstream input(output);
    std::string word;
    while (input >> word) if (word == "interface:") { input >> word; return word; }
    return "";
}
inline bool MacTunnelInterface(const std::string& name) {
    return name.compare(0, 4, "utun") == 0 || name.compare(0, 3, "tun") == 0 ||
        name.compare(0, 3, "tap") == 0 || name.compare(0, 3, "ppp") == 0 ||
        name.compare(0, 5, "ipsec") == 0;
}
inline bool WindowsTunnelAdapter(unsigned long type, std::string description) {
    if (type == 23 || type == 131) return true; // PPP and IP tunnel.
    std::transform(description.begin(), description.end(), description.begin(),
        [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    for (const char* marker : {"vpn", "wintun", "wireguard", "tap-windows", "tailscale",
            "zerotier", "amnezia", "sing-box", "tun2socks"})
        if (description.find(marker) != std::string::npos) return true;
    return false;
}
