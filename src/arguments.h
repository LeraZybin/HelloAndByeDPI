#pragma once
#include <cctype>
#include <map>
#include <stdexcept>
#include <string>
#include <vector>

// Parse arguments without ever invoking a command shell. Backslashes in paths
// and ByeDPI byte escapes are literal; quotes group whitespace.
inline std::vector<std::string> parseArguments(const std::string& text, bool mac) {
    std::vector<std::string> tokens;
    std::string word;
    char quote = 0;
    bool started = false;
    for (char ch : text) {
        if (quote) {
            if (ch == quote) quote = 0;
            else word += ch;
        } else if (ch == '\'' || ch == '"') {
            quote = ch; started = true;
        } else if (std::isspace(static_cast<unsigned char>(ch))) {
            if (started) { tokens.push_back(word); word.clear(); started = false; }
        } else { word += ch; started = true; }
    }
    if (quote) throw std::runtime_error("Незакрытая кавычка в параметрах.");
    if (started) tokens.push_back(word);
    const std::map<std::string, char> names = {
        {"split",'s'}, {"disorder",'d'}, {"oob",'o'}, {"disoob",'q'},
        {"tlsrec",'r'}, {"auto",'A'}, {"auto-mode",'L'}, {"timeout",'T'},
        {"fake",'f'}, {"fake-sni",'n'}, {"ttl",'t'}, {"def-ttl",'g'},
        {"fake-offset",'O'}, {"fake-data",'l'}, {"fake-tls-mod",'Q'},
        {"oob-data",'e'}, {"mod-http",'M'}, {"tlsminor",'m'},
        {"udp-fake",'a'}, {"proto",'K'}, {"hosts",'H'}, {"ipset",'j'},
        {"pf",'V'}, {"round",'R'}, {"cache-ttl",'u'}, {"max-conn",'c'},
        {"buf-size",'b'}, {"no-domain",'N'}, {"no-udp",'U'}, {"no-ipv6",'X'}
    };
    const std::string flags = "NUX";
    const std::string values = "sdoqrALTfntgOlQeMmaKHjVRucb";
    std::vector<std::string> result;
    for (size_t i = 0; i < tokens.size(); ++i) {
        const std::string& token = tokens[i];
        char key = 0;
        std::string value;
        bool attached = false;
        if (token.compare(0, 2, "--") == 0) {
            auto equal = token.find('=');
            auto found = names.find(token.substr(2, equal == std::string::npos ? equal : equal - 2));
            if (found != names.end()) key = found->second;
            if (equal != std::string::npos) { value = token.substr(equal + 1); attached = true; }
        } else if (token.size() >= 2 && token[0] == '-') {
            key = token[1];
            if (token.size() > 2) { value = token.substr(2); attached = true; }
        }
        if (key == 'S' || token == "--md5sig" || key == 'Y' || token == "--drop-sack")
            throw std::runtime_error("Параметры --md5sig и --drop-sack доступны только на Linux/Android.");
        if (!key || (flags.find(key) == std::string::npos && values.find(key) == std::string::npos))
            throw std::runtime_error("Неподдерживаемый параметр: " + token + ". Адрес, порт и процесс управляются приложением.");
        if (mac && (key == 'f' || key == 'n' || key == 'T'))
            throw std::runtime_error("Эта сборка ByeDPI для macOS не поддерживает --fake, --fake-sni и --timeout.");
        result.push_back(std::string("-") + key);
        if (flags.find(key) != std::string::npos) {
            if (attached) throw std::runtime_error("У флага не должно быть значения: " + token);
        } else {
            if (!attached) {
                if (++i == tokens.size()) throw std::runtime_error("Не указано значение: " + token);
                value = tokens[i];
            }
            if (value.empty()) throw std::runtime_error("Пустое значение: " + token);
            result.push_back(value);
        }
    }
    return result;
}
