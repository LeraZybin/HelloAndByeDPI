#include "http_probe.h"
#include <chrono>
#include <thread>
#include <iostream>
#include <map>
#include <cstdlib>
int main(int argc, char** argv) {
    if (argc != 4) return 1;
    std::string base = argv[1], tls = argv[3]; int port = std::atoi(argv[2]);
    for (int proxy : {0, port}) {
        std::vector<std::string> urls;
        for (auto path : {"/ok", "/denied", "/missing", "/redirect", "/large", "/partial", "/slow"}) urls.push_back(base + path);
        urls.push_back(tls);
        ProbeBatch batch(urls, 1, 1, 4, proxy);
        std::map<std::string, ProbeResult> all;
        auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(20);
        while (!batch.Done()) {
            for (auto& r : batch.Poll()) all[r.url] = r;
            if (std::chrono::steady_clock::now() > deadline) return 2;
            std::this_thread::sleep_for(std::chrono::milliseconds(10));
        }
        if (all.size() != 8) return 3;
        for (auto path : {"/ok", "/redirect", "/large"}) if (!all[base + path].available) { std::cerr << path << ": " << all[base + path].error << '\n'; return 4; }
        for (auto path : {"/denied", "/missing"}) if (all[base + path].available || !all[base + path].responded) return 5;
        for (auto path : {"/partial", "/slow"}) if (all[base + path].available || all[base + path].responded) return 6;
        if (all[tls].available || all[tls].transportCode == 0) return 7;
        if (!all[base + "/large"].sampleLimited) return 8;
        // Destruction cancels active requests without waiting for their deadline.
        auto started = std::chrono::steady_clock::now();
        { ProbeBatch cancel({base + "/slow"}, 5, 30, 2, proxy); cancel.Poll(); }
        if (std::chrono::steady_clock::now() - started > std::chrono::seconds(1)) return 9;
    }
    std::cout << "Direct and SOCKS5: HTTP classification, redirects, body cap, truncation, timeout, TLS verification and cancellation passed\n";
}
