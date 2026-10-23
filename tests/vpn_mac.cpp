#include "vpn.h"
#include <iostream>

int main() {
    try {
        if (!VpnAdapterReady("lo0")) return 1;
        auto physical = VpnFindPhysicalNetwork();
        if (physical.address.empty() || physical.interfaceName.empty() ||
            physical.interfaceName.StartsWith("utun") || physical.interfaceIndex == 0) return 2;
        std::cout << physical.interfaceName.ToStdString() << " " << physical.address.ToStdString() << "\n";
        return 0;
    } catch (const std::exception& error) {
        std::cerr << error.what() << "\n";
        return 3;
    }
}
