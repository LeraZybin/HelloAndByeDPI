#pragma once
#include <memory>
#include <string>
#include <vector>

struct ProbeResult {
    std::string url, error;
    int attempt = 0, transportCode = 0;
    long http = 0;
    double milliseconds = 0;
    bool available = false, responded = false, sampleLimited = false;
    std::string remoteAddress, localAddress, effectiveUrl, diagnostic;
    double dnsMilliseconds = 0, connectMilliseconds = 0, tlsMilliseconds = 0;
};
std::string ProbeRuntime();
// sampleLimited is set only by our body callback when it deliberately stops
// reading after enough response bytes have been received.
void ClassifyProbeResult(ProbeResult& result, const std::string& transportError);
std::vector<std::string> ParseSites(const std::string& text);
double Median(std::vector<double> values);
std::string CsvCell(const std::string& text);

// All transfers are explicitly direct or through the given SOCKS5 port.
// Poll from the UI timer; no worker threads touch UI controls.
class ProbeBatch {
    struct Impl;
    std::unique_ptr<Impl> impl_;
public:
    ProbeBatch(const std::vector<std::string>& sites, int attempts, int timeoutSeconds,
               int concurrency, int socksPort, const std::string& dnsServer = "", bool ipv4Only = false); // 0 = OS routing
    ~ProbeBatch();
    std::vector<ProbeResult> Poll();
    bool Done() const;
};
