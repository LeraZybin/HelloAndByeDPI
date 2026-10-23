#include "http_probe.h"
#include "diagnostic_mode.h"
#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windns.h>
#endif
#include <curl/curl.h>
#include <algorithm>
#include <cctype>
#include <map>
#include <set>
#include <sstream>
#include <stdexcept>

std::vector<std::string> ParseSites(const std::string& text) {
    std::istringstream input(text);
    std::vector<std::string> result;
    std::set<std::string> seen;
    std::string line;
    while (std::getline(input, line)) {
        if (line.compare(0, 3, "\xef\xbb\xbf") == 0) line.erase(0, 3);
        size_t first = line.find_first_not_of(" \t\r"), last = line.find_last_not_of(" \t\r");
        if (first == std::string::npos) continue;
        line = line.substr(first, last - first + 1);
        if (line[0] == '#') continue;
        if (line.find("://") == std::string::npos) line = "https://" + line;
        size_t start;
        if (line.compare(0, 8, "https://") == 0) start = 8;
        else if (line.compare(0, 7, "http://") == 0) start = 7;
        else throw std::runtime_error("Разрешены только http:// и https://: " + line);
        if (line.find_first_of(" \t\r\n\\") != std::string::npos || line.size() > 4096)
            throw std::runtime_error("Неверный адрес сайта: " + line);
        for (unsigned char ch : line) if (ch < 32 || ch == 127)
            throw std::runtime_error("Управляющий символ в адресе сайта.");
        size_t end = line.find_first_of("/?#", start);
        std::string authority = line.substr(start, end == std::string::npos ? end : end - start);
        if (authority.empty() || authority.find('@') != std::string::npos)
            throw std::runtime_error("Нужен адрес сайта без логина и пароля: " + line);
        // Canonicalize only the host, preserving case-sensitive paths.
        std::transform(authority.begin(), authority.end(), authority.begin(), [](unsigned char c) { return std::tolower(c); });
        line.replace(start, authority.size(), authority);
        size_t hash = line.find('#'); if (hash != std::string::npos) line.erase(hash);
        if (line.find('/', start) == std::string::npos && line.find('?', start) == std::string::npos) line += '/';
        if (seen.insert(line).second) result.push_back(line);
        if (result.size() > 1000) throw std::runtime_error("Не более 1000 сайтов за один тест.");
    }
    return result;
}
double Median(std::vector<double> values) {
    if (values.empty()) return -1;
    std::sort(values.begin(), values.end());
    size_t middle = values.size() / 2;
    return values.size() % 2 ? values[middle] : (values[middle - 1] + values[middle]) / 2;
}
std::string CsvCell(const std::string& text) {
    std::string result = "\"";
    if (!text.empty() && (text[0] == '=' || text[0] == '+' || text[0] == '-' || text[0] == '@')) result += '\'';
    for (char ch : text) { if (ch == '"') result += '"'; result += ch; }
    return result + '"';
}

void ClassifyProbeResult(ProbeResult& result, const std::string& transportError) {
    // Apple's system curl can report receive error 56 instead of write error
    // 23 when our callback stops a large HTTP/2 response at the body cap.
    // Only our callback can set sampleLimited. Uncapped network/TLS failures
    // and truncated responses must still fail even if HTTP 200 was received.
    const bool transferred = result.transportCode == CURLE_OK || result.sampleLimited;
    result.responded = transferred && result.http > 0;
    result.available = result.responded && result.http >= 200 && result.http < 400;
    result.error.clear();
    if (!transferred) result.error = transportError;
    else if (!result.available) result.error = "HTTP " + std::to_string(result.http);
}

std::string ProbeRuntime() { return curl_version(); }

namespace {
struct CurlLifetime {
    CurlLifetime() { if (curl_global_init(CURL_GLOBAL_DEFAULT) != CURLE_OK) throw std::runtime_error("Не удалось инициализировать HTTPS."); }
    ~CurlLifetime() { curl_global_cleanup(); }
};
struct Job {
    CURL* handle = nullptr;
    curl_slist* resolve = nullptr;
    ProbeResult result;
    char error[CURL_ERROR_SIZE] = {};
    size_t bytes = 0;
    static int Debug(CURL*, curl_infotype type, char* data, size_t size, void* userdata) {
        auto job = static_cast<Job*>(userdata);
        // Connection and TLS diagnostics only; exclude HTTP headers and bodies.
        if (type == CURLINFO_TEXT && job->result.diagnostic.size() < 8192)
            job->result.diagnostic.append(data, std::min(size, 8192 - job->result.diagnostic.size()));
        return 0;
    }
    ~Job() { if (handle) curl_easy_cleanup(handle); if (resolve) curl_slist_free_all(resolve); }
    static size_t Receive(char*, size_t size, size_t count, void* userdata) {
        auto job = static_cast<Job*>(userdata);
        size_t length = size * count;
        if (length > 65536 - job->bytes) { job->result.sampleLimited = true; return 0; }
        job->bytes += length;
        return length;
    }
};
}
struct ProbeBatch::Impl {
    CURLM* multi = nullptr;
    std::map<CURL*, std::unique_ptr<Job>> jobs;
    std::vector<std::string> sites;
    int attempts, timeout, concurrency, port;
    std::string dnsServer;
    bool ipv4Only;
    std::vector<ProbeResult> immediate;
    size_t next = 0;
    Impl(const std::vector<std::string>& s, int a, int t, int c, int p, const std::string& dns, bool ipv4) :
        sites(s), attempts(a), timeout(t), concurrency(c), port(p), dnsServer(dns), ipv4Only(ipv4) {
        if (a < 1 || a > 5 || t < 1 || t > 60 || c < 1 || c > 20 || p < 0 || p > 65535)
            throw std::runtime_error("Неверные настройки теста.");
        static CurlLifetime curl;
        multi = curl_multi_init();
        if (!multi) throw std::runtime_error("Не удалось создать HTTPS-тестер.");
    }
    ~Impl() {
        for (auto& entry : jobs) curl_multi_remove_handle(multi, entry.first);
        jobs.clear();
        curl_multi_cleanup(multi);
    }
    template<class T> void Option(CURL* handle, CURLoption key, T value) {
        auto code = curl_easy_setopt(handle, key, value);
        if (code != CURLE_OK) throw std::runtime_error(curl_easy_strerror(code));
    }
#ifdef _WIN32
    static std::string Host(const std::string& url) {
        size_t begin = url.find("://"); begin = begin == std::string::npos ? 0 : begin + 3;
        size_t end = url.find_first_of("/?#", begin);
        std::string host = url.substr(begin, end == std::string::npos ? end : end - begin);
        size_t colon = host.rfind(':'); if (colon != std::string::npos) host.erase(colon);
        return host;
    }
    static std::string Resolve(const std::string& host, const std::string& server, std::string& error) {
        static std::map<std::string, std::string> cache;
        in_addr literal = {};
        if (inet_pton(AF_INET, host.c_str(), &literal) == 1) return host;
        std::string key = server + "\n" + host;
        auto found = cache.find(key); if (found != cache.end()) return found->second;
        IP4_ARRAY servers = {}; PIP4_ARRAY serverList = nullptr;
        if (!server.empty()) {
            in_addr address = {};
            if (inet_pton(AF_INET, server.c_str(), &address) != 1) { error = "Invalid DNS server: " + server; return ""; }
            servers.AddrCount = 1; servers.AddrArray[0] = address.s_addr; serverList = &servers;
        }
        PDNS_RECORD records = nullptr;
        DNS_STATUS status = DnsQuery_A(host.c_str(), DNS_TYPE_A,
            DNS_QUERY_BYPASS_CACHE | DNS_QUERY_NO_NETBT, serverList, &records, nullptr);
        std::string result;
        if (status == 0) for (PDNS_RECORD record = records; record; record = record->pNext) {
            if (record->wType != DNS_TYPE_A) continue;
            char text[INET_ADDRSTRLEN] = {};
            if (inet_ntop(AF_INET, &record->Data.A.IpAddress, text, sizeof(text))) { result = text; break; }
        }
        if (records) DnsRecordListFree(records, DnsFreeRecordList);
        if (result.empty()) error = "DNS " + (server.empty() ? std::string("system") : server) + ": " + std::to_string(status);
        else cache[key] = result;
        return result;
    }
#endif
    void StartMore() {
        while (jobs.size() < static_cast<size_t>(concurrency) && next < sites.size() * attempts) {
            std::unique_ptr<Job> job(new Job());
            job->result.url = sites[next / attempts];
            job->result.attempt = static_cast<int>(next % attempts) + 1;
#ifdef _WIN32
            std::string dnsError;
            std::string host = Host(job->result.url);
            std::string ip = Resolve(host, dnsServer, dnsError);
            if (ip.empty()) {
                job->result.error = dnsError; immediate.push_back(job->result); ++next; continue;
            }
#endif
            job->handle = curl_easy_init();
            if (!job->handle) throw std::runtime_error("Не удалось создать HTTP-запрос.");
            auto h = job->handle;
            Option(h, CURLOPT_URL, job->result.url.c_str());
            if (DiagnosticLogging()) {
                Option(h, CURLOPT_VERBOSE, 1L);
                Option(h, CURLOPT_DEBUGFUNCTION, &Job::Debug);
                Option(h, CURLOPT_DEBUGDATA, job.get());
            }
            if (ipv4Only) Option(h, CURLOPT_IPRESOLVE, static_cast<long>(CURL_IPRESOLVE_V4));
            Option(h, CURLOPT_ERRORBUFFER, job->error);
            Option(h, CURLOPT_WRITEFUNCTION, &Job::Receive);
            Option(h, CURLOPT_WRITEDATA, job.get());
            Option(h, CURLOPT_NOSIGNAL, 1L);
            Option(h, CURLOPT_TIMEOUT_MS, static_cast<long>(timeout) * 1000);
            Option(h, CURLOPT_CONNECTTIMEOUT_MS, static_cast<long>(timeout) * 1000);
            Option(h, CURLOPT_FOLLOWLOCATION, 1L);
            Option(h, CURLOPT_MAXREDIRS, 5L);
            Option(h, CURLOPT_PROTOCOLS, static_cast<long>(CURLPROTO_HTTP | CURLPROTO_HTTPS));
            Option(h, CURLOPT_REDIR_PROTOCOLS, static_cast<long>(CURLPROTO_HTTP | CURLPROTO_HTTPS));
            Option(h, CURLOPT_SSL_VERIFYPEER, 1L);
            Option(h, CURLOPT_SSL_VERIFYHOST, 2L);
            Option(h, CURLOPT_FRESH_CONNECT, 1L);
            Option(h, CURLOPT_FORBID_REUSE, 1L);
            Option(h, CURLOPT_USERAGENT, "ByeDPI-Desktop-Policy-Test/0.3");
            Option(h, CURLOPT_NOPROXY, ""); // Ignore environment exclusions, including localhost.
#ifdef _WIN32
            int targetPort = job->result.url.compare(0, 8, "https://") == 0 ? 443 : 80;
            std::string mapping = host + ":" + std::to_string(targetPort) + ":" + ip;
            job->resolve = curl_slist_append(nullptr, mapping.c_str());
            if (!job->resolve) throw std::runtime_error("Could not allocate DNS result.");
            Option(h, CURLOPT_RESOLVE, job->resolve);
#endif
            if (port) {
                Option(h, CURLOPT_PROXY, "127.0.0.1");
                Option(h, CURLOPT_PROXYPORT, static_cast<long>(port));
#ifdef _WIN32
                // ByeDPI's Windows resolver can fail for otherwise valid host names
                // ("not resolved"). Resolve with the system DNS client and send the
                // resulting address through SOCKS5; curl still retains the URL host
                // for TLS certificate verification and HTTP Host/SNI.
                Option(h, CURLOPT_PROXYTYPE, static_cast<long>(CURLPROXY_SOCKS5));
#else
                Option(h, CURLOPT_PROXYTYPE, static_cast<long>(CURLPROXY_SOCKS5_HOSTNAME));
#endif
            } else Option(h, CURLOPT_PROXY, ""); // Direct baseline ignores ALL_PROXY and HTTPS_PROXY.
            if (curl_multi_add_handle(multi, h) != CURLM_OK) throw std::runtime_error("Не удалось запустить HTTP-запрос.");
            jobs.emplace(h, std::move(job)); ++next;
        }
    }
};
ProbeBatch::ProbeBatch(const std::vector<std::string>& sites, int attempts, int timeout, int concurrency, int port, const std::string& dnsServer, bool ipv4Only) :
    impl_(new Impl(sites, attempts, timeout, concurrency, port, dnsServer, ipv4Only)) {}
ProbeBatch::~ProbeBatch() = default;
bool ProbeBatch::Done() const { return impl_->jobs.empty() && impl_->immediate.empty() && impl_->next == impl_->sites.size() * impl_->attempts; }
std::vector<ProbeResult> ProbeBatch::Poll() {
    impl_->StartMore();
    int running = 0;
    auto code = curl_multi_perform(impl_->multi, &running);
    if (code != CURLM_OK) throw std::runtime_error(curl_multi_strerror(code));
    std::vector<ProbeResult> completed; completed.swap(impl_->immediate);
    int queued;
    while (auto message = curl_multi_info_read(impl_->multi, &queued)) {
        if (message->msg != CURLMSG_DONE) continue;
        auto entry = impl_->jobs.find(message->easy_handle);
        if (entry == impl_->jobs.end()) continue;
        Job& job = *entry->second;
        double seconds = 0;
        curl_easy_getinfo(job.handle, CURLINFO_RESPONSE_CODE, &job.result.http);
        curl_easy_getinfo(job.handle, CURLINFO_TOTAL_TIME, &seconds);
        job.result.milliseconds = seconds * 1000;
        job.result.transportCode = message->data.result;
        char* value = nullptr;
        if (curl_easy_getinfo(job.handle, CURLINFO_PRIMARY_IP, &value) == CURLE_OK && value) job.result.remoteAddress = value;
        if (curl_easy_getinfo(job.handle, CURLINFO_LOCAL_IP, &value) == CURLE_OK && value) job.result.localAddress = value;
        if (curl_easy_getinfo(job.handle, CURLINFO_EFFECTIVE_URL, &value) == CURLE_OK && value) job.result.effectiveUrl = value;
        curl_easy_getinfo(job.handle, CURLINFO_NAMELOOKUP_TIME, &seconds); job.result.dnsMilliseconds = seconds * 1000;
        curl_easy_getinfo(job.handle, CURLINFO_CONNECT_TIME, &seconds); job.result.connectMilliseconds = seconds * 1000;
        curl_easy_getinfo(job.handle, CURLINFO_APPCONNECT_TIME, &seconds); job.result.tlsMilliseconds = seconds * 1000;
        ClassifyProbeResult(job.result, job.error[0] ? job.error : curl_easy_strerror(message->data.result));
        completed.push_back(job.result);
        curl_multi_remove_handle(impl_->multi, job.handle);
        impl_->jobs.erase(entry);
    }
    return completed;
}
