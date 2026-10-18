#include "http_probe.h"
#include "arguments.h"
#include <fstream>
#include <iostream>
#include <cstdlib>
void check(bool ok) { if (!ok) { std::cerr << "Check failed\n"; std::exit(1); } }
int main(int argc, char** argv) {
    auto sites = ParseSites("\xef\xbb\xbf# comment\nExample.COM\nhttps://example.com/\nhttps://example.com/Case#fragment\nhttp://localhost:1234/x?q=1\n");
    check(sites.size() == 3 && sites[0] == "https://example.com/" && sites[1] == "https://example.com/Case");
    for (auto bad : {"file:///tmp/test", "ftp://host", "https://", "https://user:password@host", "https://a b"}) {
        bool threw = false; try { ParseSites(bad); } catch (...) { threw = true; } check(threw);
    }
    check(Median({}) == -1 && Median({4, 2, 1}) == 2 && Median({1, 5, 3, 7}) == 4);
    check(CsvCell("a\"b") == "\"a\"\"b\"" && CsvCell("=formula") == "\"'=formula\"");
    check(argc == 2); std::ifstream file(argv[1]); check(file.good());
    std::string line; int count = 0, mac = 0, win = 0;
    while (std::getline(file, line)) {
        if (line.empty()) continue; ++count;
        size_t at; while ((at = line.find("{sni}")) != std::string::npos) line.replace(at, 5, "google.com");
        try { parseArguments(line, true); ++mac; } catch (...) {}
        try { parseArguments(line, false); ++win; } catch (...) {}
    }
    check(count == 60 && mac > 0 && mac < 60 && win >= mac);
    std::cout << "60 policies; compatible: macOS " << mac << ", Windows " << win << '\n';
}
