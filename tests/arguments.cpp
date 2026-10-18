#include "arguments.h"
#include <iostream>
#include <cstdlib>
void require(bool ok) { if (!ok) { std::cerr << "Assertion failed\n"; std::exit(1); } }
void rejects(const std::string& args, bool mac = false) {
    try { parseArguments(args, mac); } catch (const std::runtime_error&) { return; }
    std::cerr << "Unexpected acceptance: " << args << "\n"; std::exit(1);
}
int main() {
    require(parseArguments("-s1 --tlsrec=1+s -U", false) ==
        std::vector<std::string>({"-s", "1", "-r", "1+s", "-U"}));
    require(parseArguments("--hosts \"C:\\my files\\hosts.txt\" -f -1", false)[1] == "C:\\my files\\hosts.txt");
    require(parseArguments("--oob-data '\\n'", false)[1] == "\\n");
    require(parseArguments("", true).empty());
    rejects("--ip 0.0.0.0"); rejects("-p1080"); rejects("--daemon");
    rejects("-D"); rejects("--transparent"); rejects("--split");
    rejects("--hosts 'oops"); rejects("--no-udp=yes"); rejects("-UN");
    rejects("--split 1 ; calc.exe"); rejects("--fake -1", true);
    rejects("-T3", true); rejects("--unknown 1");
    std::cout << "Argument validation passed\n";
}
