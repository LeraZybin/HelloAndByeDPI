#include "system_proxy.h"
#include <windows.h>
#include <wininet.h>
#include <wx/base64.h>
#include <vector>

namespace {
struct Settings {
    DWORD flags = PROXY_TYPE_DIRECT;
    wxString server, bypass, autoConfig;
};

std::runtime_error WinError(const char* message) {
    DWORD code = GetLastError();
    wchar_t* buffer = nullptr;
    DWORD length = FormatMessageW(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM |
        FORMAT_MESSAGE_IGNORE_INSERTS, nullptr, code, 0, reinterpret_cast<wchar_t*>(&buffer), 0, nullptr);
    wxString detail = length && buffer ? wxString(buffer, length) : wxString();
    if (buffer) LocalFree(buffer);
    detail.Trim();
    return std::runtime_error(std::string(message) + " (Windows error " +
        std::to_string(static_cast<unsigned long>(code)) + (detail.empty() ? ")" : ": " + detail.ToStdString(wxConvUTF8) + ")"));
}

std::string Describe(const Settings& settings) {
    return "flags=" + std::to_string(static_cast<unsigned long>(settings.flags)) +
        ", server=\"" + settings.server.ToStdString(wxConvUTF8) + "\", bypass=\"" +
        settings.bypass.ToStdString(wxConvUTF8) + "\", autoConfig=\"" +
        settings.autoConfig.ToStdString(wxConvUTF8) + "\"";
}

Settings Read() {
    INTERNET_PER_CONN_OPTIONW options[4] = {};
    options[0].dwOption = INTERNET_PER_CONN_FLAGS_UI;
    options[1].dwOption = INTERNET_PER_CONN_PROXY_SERVER;
    options[2].dwOption = INTERNET_PER_CONN_PROXY_BYPASS;
    options[3].dwOption = INTERNET_PER_CONN_AUTOCONFIG_URL;
    INTERNET_PER_CONN_OPTION_LISTW list = {};
    list.dwSize = sizeof(list);
    list.pszConnection = nullptr;
    list.dwOptionCount = 4;
    list.pOptions = options;
    DWORD size = sizeof(list);
    if (!InternetQueryOptionW(nullptr, INTERNET_OPTION_PER_CONNECTION_OPTION, &list, &size)) {
        options[0].dwOption = INTERNET_PER_CONN_FLAGS;
        size = sizeof(list);
        if (!InternetQueryOptionW(nullptr, INTERNET_OPTION_PER_CONNECTION_OPTION, &list, &size))
            throw WinError("Не удалось прочитать системный прокси Windows.");
    }
    Settings result;
    result.flags = options[0].Value.dwValue;
    if (options[1].Value.pszValue) result.server = options[1].Value.pszValue;
    if (options[2].Value.pszValue) result.bypass = options[2].Value.pszValue;
    if (options[3].Value.pszValue) result.autoConfig = options[3].Value.pszValue;
    for (int i = 1; i < 4; ++i)
        if (options[i].Value.pszValue) GlobalFree(options[i].Value.pszValue);
    return result;
}

void NotifyAllApplications() {
    if (!InternetSetOptionW(nullptr, INTERNET_OPTION_SETTINGS_CHANGED, nullptr, 0) ||
        !InternetSetOptionW(nullptr, INTERNET_OPTION_REFRESH, nullptr, 0))
        throw WinError("Не удалось уведомить Windows об изменении прокси.");
#ifdef INTERNET_OPTION_PROXY_SETTINGS_CHANGED
    InternetSetOptionW(nullptr, INTERNET_OPTION_PROXY_SETTINGS_CHANGED, nullptr, 0);
#endif
    DWORD_PTR ignored = 0;
    SendMessageTimeoutW(HWND_BROADCAST, WM_SETTINGCHANGE, 0,
        reinterpret_cast<LPARAM>(L"Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings"),
        SMTO_ABORTIFHUNG, 2000, &ignored);
}

void Write(const Settings& settings) {
    std::wstring server = settings.server.ToStdWstring();
    std::wstring bypass = settings.bypass.ToStdWstring();
    std::wstring autoConfig = settings.autoConfig.ToStdWstring();
    INTERNET_PER_CONN_OPTIONW options[4] = {};
    options[0].dwOption = INTERNET_PER_CONN_FLAGS;
    options[0].Value.dwValue = settings.flags;
    options[1].dwOption = INTERNET_PER_CONN_PROXY_SERVER;
    options[1].Value.pszValue = const_cast<wchar_t*>(server.c_str());
    options[2].dwOption = INTERNET_PER_CONN_PROXY_BYPASS;
    options[2].Value.pszValue = const_cast<wchar_t*>(bypass.c_str());
    options[3].dwOption = INTERNET_PER_CONN_AUTOCONFIG_URL;
    options[3].Value.pszValue = const_cast<wchar_t*>(autoConfig.c_str());
    INTERNET_PER_CONN_OPTION_LISTW list = {};
    list.dwSize = sizeof(list);
    list.pszConnection = nullptr;
    list.dwOptionCount = 4;
    list.pOptions = options;
    if (!InternetSetOptionW(nullptr, INTERNET_OPTION_PER_CONNECTION_OPTION, &list, sizeof(list)))
        throw WinError("Windows не разрешила изменить системный прокси.");
    NotifyAllApplications();
}

std::string B64(const wxString& value) {
    auto bytes = value.utf8_str();
    return wxBase64Encode(bytes.data(), bytes.length()).ToStdString();
}

wxString UnB64(const std::string& value) {
    auto bytes = wxBase64Decode(wxString::FromUTF8(value.c_str()));
    return wxString::FromUTF8(static_cast<const char*>(bytes.GetData()), bytes.GetDataLen());
}

std::string Encode(const Settings& settings) {
    return "v2:" + std::to_string(settings.flags) + ":" + B64(settings.server) + ":" +
        B64(settings.bypass) + ":" + B64(settings.autoConfig);
}

Settings Decode(const std::string& text) {
    if (text.compare(0, 3, "v2:") != 0) {
        // Backwards compatibility with the 0.4.0 journal: flags:base64(server).
        size_t separator = text.find(':');
        if (separator == std::string::npos) throw std::runtime_error("Неверная резервная копия прокси.");
        size_t count = 0;
        unsigned long flags = std::stoul(text.substr(0, separator), &count);
        if (count != separator) throw std::runtime_error("Неверные флаги в резервной копии прокси.");
        Settings result;
        result.flags = static_cast<DWORD>(flags);
        result.server = UnB64(text.substr(separator + 1));
        return result;
    }
    std::vector<std::string> parts;
    size_t begin = 3;
    while (true) {
        size_t end = text.find(':', begin);
        parts.push_back(text.substr(begin, end == std::string::npos ? end : end - begin));
        if (end == std::string::npos) break;
        begin = end + 1;
    }
    if (parts.size() != 4) throw std::runtime_error("Неверная резервная копия прокси.");
    size_t count = 0;
    unsigned long flags = std::stoul(parts[0], &count);
    if (count != parts[0].size()) throw std::runtime_error("Неверные флаги в резервной копии прокси.");
    Settings result;
    result.flags = static_cast<DWORD>(flags);
    result.server = UnB64(parts[1]);
    result.bypass = UnB64(parts[2]);
    result.autoConfig = UnB64(parts[3]);
    return result;
}

bool Applied(const Settings& actual, const Settings& expected) {
    return (actual.flags & PROXY_TYPE_PROXY) &&
        actual.server.CmpNoCase(expected.server) == 0;
}

class WindowsProxy : public ProxyBackend {
public:
    ProxySnapshot Prepare(int port) override {
        Settings before = Read();
        Settings after;
        after.flags = PROXY_TYPE_DIRECT | PROXY_TYPE_PROXY;
        // WinINET does not persist the URI-qualified SOCKS5 value on every
        // supported Windows release. Its HTTP/HTTPS proxy form is stable and
        // browsers use HTTP CONNECT for HTTPS through ByeDPI's HTTP listener.
        after.server = wxString::Format("http=127.0.0.1:%d;https=127.0.0.1:%d", port, port);
        after.bypass = "<local>";
        return {Encode(before), Encode(after)};
    }
    void Apply(const ProxySnapshot& snapshot) override {
        Settings current = Read();
        if (Encode(current) != snapshot.before)
            throw std::runtime_error("Системный прокси изменился. Повторите подключение. Сейчас: " + Describe(current));
        Settings after = Decode(snapshot.after);
        Write(after);
        Settings actual = Read();
        if (!Applied(actual, after)) {
            Write(Decode(snapshot.before));
            throw std::runtime_error("Windows не сохранила настройки HTTP/HTTPS-прокси. Изменения отменены. Ожидалось: " +
                Describe(after) + "; прочитано после записи: " + Describe(actual));
        }
    }
    void Restore(const ProxySnapshot& snapshot) override {
        Settings current = Read(), before = Decode(snapshot.before), after = Decode(snapshot.after);
        if (!Applied(current, after)) return;
        Write(before);
        if (Applied(Read(), after))
            throw std::runtime_error("Windows не восстановила прежние настройки прокси.");
    }
};
}

std::unique_ptr<ProxyBackend> MakeSystemProxy() {
    return std::unique_ptr<ProxyBackend>(new WindowsProxy());
}
