#include "system_proxy.h"
#include <SystemConfiguration/SystemConfiguration.h>
#include <Security/Authorization.h>
#include <wx/base64.h>
#include <vector>

namespace {
template<class T> class Ref {
    T p_;
public:
    explicit Ref(T p = nullptr) : p_(p) {}
    ~Ref() { if (p_) CFRelease(p_); }
    Ref(const Ref&) = delete;
    Ref& operator=(const Ref&) = delete;
    Ref(Ref&& r) : p_(r.p_) { r.p_ = nullptr; }
    operator T() const { return p_; }
};
Ref<CFMutableDictionaryRef> Dictionary(CFDictionaryRef source = nullptr) {
    return Ref<CFMutableDictionaryRef>(source ? CFDictionaryCreateMutableCopy(nullptr, 0, source) :
        CFDictionaryCreateMutable(nullptr, 0, &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks));
}
bool Equal(CFTypeRef a, CFTypeRef b) { return a == b || (a && b && CFEqual(a, b)); }
void Number(CFMutableDictionaryRef d, CFStringRef key, int value) {
    Ref<CFNumberRef> n(CFNumberCreate(nullptr, kCFNumberIntType, &value));
    CFDictionarySetValue(d, key, n);
}
std::vector<const void*> Keys(CFDictionaryRef d) {
    std::vector<const void*> keys(CFDictionaryGetCount(d));
    if (!keys.empty()) CFDictionaryGetKeysAndValues(d, keys.data(), nullptr);
    return keys;
}
std::string Encode(CFDictionaryRef dictionary) {
    Ref<CFDataRef> data(CFPropertyListCreateData(nullptr, dictionary, kCFPropertyListBinaryFormat_v1_0, 0, nullptr));
    if (!data) throw std::runtime_error("Не удалось сохранить сетевые настройки.");
    return wxBase64Encode(CFDataGetBytePtr(data), CFDataGetLength(data)).ToStdString();
}
Ref<CFDictionaryRef> Decode(const std::string& text) {
    auto bytes = wxBase64Decode(wxString::FromUTF8(text.c_str()));
    Ref<CFDataRef> data(CFDataCreate(nullptr, static_cast<const UInt8*>(bytes.GetData()), bytes.GetDataLen()));
    CFPropertyListRef value = CFPropertyListCreateWithData(nullptr, data, kCFPropertyListImmutable, nullptr, nullptr);
    if (!value || CFGetTypeID(value) != CFDictionaryGetTypeID()) {
        if (value) CFRelease(value);
        throw std::runtime_error("Неверная резервная копия сетевых настроек.");
    }
    Ref<CFDictionaryRef> result(static_cast<CFDictionaryRef>(value));
    for (auto key : Keys(result)) {
        if (CFGetTypeID(key) != CFStringGetTypeID() ||
            CFGetTypeID(CFDictionaryGetValue(result, key)) != CFDictionaryGetTypeID())
            throw std::runtime_error("Неверная структура резервной копии.");
    }
    return result;
}
void Check(bool ok) {
    if (!ok) throw std::runtime_error(std::string("Не удалось изменить сетевые настройки: ") + SCErrorString(SCError()));
}
class Lock {
    SCPreferencesRef prefs_;
public:
    explicit Lock(SCPreferencesRef p) : prefs_(p) { Check(SCPreferencesLock(p, false)); }
    ~Lock() { SCPreferencesUnlock(prefs_); }
};
const CFStringRef managedKeys[] = {
    kSCPropNetProxiesSOCKSEnable, kSCPropNetProxiesSOCKSProxy, kSCPropNetProxiesSOCKSPort,
    CFSTR("SOCKSUser"), kSCPropNetProxiesHTTPEnable, kSCPropNetProxiesHTTPSEnable,
    kSCPropNetProxiesProxyAutoConfigEnable, kSCPropNetProxiesProxyAutoDiscoveryEnable
};
Ref<CFMutableDictionaryRef> RestoreValues(CFDictionaryRef old, CFDictionaryRef installed, CFDictionaryRef current) {
    auto restored = Dictionary(current);
    if (!Equal(CFDictionaryGetValue(current, kSCPropNetProxiesSOCKSProxy), CFDictionaryGetValue(installed, kSCPropNetProxiesSOCKSProxy)) ||
        !Equal(CFDictionaryGetValue(current, kSCPropNetProxiesSOCKSPort), CFDictionaryGetValue(installed, kSCPropNetProxiesSOCKSPort))) return restored;
    for (auto field : managedKeys) {
        auto was = CFDictionaryGetValue(old, field);
        auto ours = CFDictionaryGetValue(installed, field);
        if (!Equal(was, ours) && Equal(CFDictionaryGetValue(current, field), ours)) {
            if (was) CFDictionarySetValue(restored, field, was);
            else CFDictionaryRemoveValue(restored, field);
        }
    }
    return restored;
}

class MacProxy : public ProxyBackend {
    AuthorizationRef authorization_ = nullptr;
    Ref<SCPreferencesRef> Session(bool writable) {
        if (writable && !authorization_) {
            if (AuthorizationCreate(nullptr, kAuthorizationEmptyEnvironment, kAuthorizationFlagDefaults,
                                    &authorization_) != errAuthorizationSuccess)
                throw std::runtime_error("Не удалось запросить разрешение на изменение сети.");
        }
        if (writable) {
            AuthorizationItem item = {"system.preferences.network", 0, nullptr, 0};
            AuthorizationRights rights = {1, &item};
            OSStatus result = AuthorizationCopyRights(authorization_, &rights, kAuthorizationEmptyEnvironment,
                kAuthorizationFlagInteractionAllowed | kAuthorizationFlagExtendRights | kAuthorizationFlagPreAuthorize, nullptr);
            if (result != errAuthorizationSuccess)
                throw std::runtime_error("macOS не разрешила изменить прокси. Подтвердите доступ администратора или отключите автоматическую настройку.");
        }
        Ref<SCPreferencesRef> prefs(writable ?
            SCPreferencesCreateWithAuthorization(nullptr, CFSTR("ByeDPI Desktop"), nullptr, authorization_) :
            SCPreferencesCreate(nullptr, CFSTR("ByeDPI Desktop"), nullptr));
        Check(prefs != nullptr);
        return prefs;
    }
    Ref<CFMutableDictionaryRef> Changes(SCPreferencesRef prefs, CFDictionaryRef before, CFDictionaryRef after, bool restore) {
        auto changes = Dictionary();
        for (auto key : Keys(after)) {
            auto old = static_cast<CFDictionaryRef>(CFDictionaryGetValue(before, key));
            auto installed = static_cast<CFDictionaryRef>(CFDictionaryGetValue(after, key));
            if (!old) throw std::runtime_error("Неполная резервная копия сети.");
            Ref<SCNetworkServiceRef> service(SCNetworkServiceCopy(prefs, static_cast<CFStringRef>(key)));
            Ref<SCNetworkProtocolRef> protocol(service ? SCNetworkServiceCopyProtocol(service, kSCNetworkProtocolTypeProxies) : nullptr);
            if (!protocol) {
                if (restore) continue; // A deleted network service has nothing to restore.
                throw std::runtime_error("Сетевая служба изменилась. Повторите подключение.");
            }
            auto current = Dictionary(SCNetworkProtocolGetConfiguration(protocol));
            if (!restore) {
                if (!CFEqual(current, old)) throw std::runtime_error("Настройки сети изменились во время подключения. Повторите попытку.");
                CFDictionarySetValue(changes, key, installed);
                continue;
            }
            auto restored = RestoreValues(old, installed, current);
            if (!CFEqual(current, restored)) CFDictionarySetValue(changes, key, restored);
        }
        return changes;
    }
    void Update(const ProxySnapshot& state, bool restore) {
        auto before = Decode(state.before), after = Decode(state.after);
        auto prefs = Session(true);
        Lock lock(prefs);
        auto changes = Changes(prefs, before, after, restore);
        for (auto key : Keys(changes)) {
            Ref<SCNetworkServiceRef> service(SCNetworkServiceCopy(prefs, static_cast<CFStringRef>(key)));
            Ref<SCNetworkProtocolRef> protocol(service ? SCNetworkServiceCopyProtocol(service, kSCNetworkProtocolTypeProxies) : nullptr);
            Check(protocol && SCNetworkProtocolSetConfiguration(protocol, static_cast<CFDictionaryRef>(CFDictionaryGetValue(changes, key))));
        }
        if (CFDictionaryGetCount(changes)) {
            Check(SCPreferencesCommitChanges(prefs));
        }
        // Re-apply even when the saved configuration is already restored:
        // a previous attempt may have committed successfully but failed to apply.
        Check(SCPreferencesApplyChanges(prefs));
    }
public:
    ~MacProxy() override { if (authorization_) AuthorizationFree(authorization_, kAuthorizationFlagDefaults); }
    ProxySnapshot Prepare(int port) override {
        // Request permission before writing a recovery journal, so cancelling
        // the authorization dialog cannot trigger a second rollback prompt.
        auto prefs = Session(true);
        Ref<SCNetworkSetRef> set(SCNetworkSetCopyCurrent(prefs));
        Ref<CFArrayRef> services(set ? SCNetworkSetCopyServices(set) : nullptr);
        if (!services) throw std::runtime_error("Не найдены сетевые службы macOS.");
        auto before = Dictionary(), after = Dictionary();
        for (CFIndex i = 0; i < CFArrayGetCount(services); ++i) {
            auto service = static_cast<SCNetworkServiceRef>(CFArrayGetValueAtIndex(services, i));
            if (!SCNetworkServiceGetEnabled(service)) continue;
            Ref<SCNetworkProtocolRef> protocol(SCNetworkServiceCopyProtocol(service, kSCNetworkProtocolTypeProxies));
            if (!protocol || !SCNetworkProtocolGetEnabled(protocol)) continue;
            auto old = Dictionary(SCNetworkProtocolGetConfiguration(protocol));
            auto changed = Dictionary(old);
            Number(changed, kSCPropNetProxiesSOCKSEnable, 1);
            Number(changed, kSCPropNetProxiesSOCKSPort, port);
            CFDictionarySetValue(changed, kSCPropNetProxiesSOCKSProxy, CFSTR("127.0.0.1"));
            CFDictionaryRemoveValue(changed, CFSTR("SOCKSUser"));
            Number(changed, kSCPropNetProxiesHTTPEnable, 0);
            Number(changed, kSCPropNetProxiesHTTPSEnable, 0);
            Number(changed, kSCPropNetProxiesProxyAutoConfigEnable, 0);
            Number(changed, kSCPropNetProxiesProxyAutoDiscoveryEnable, 0);
            auto id = SCNetworkServiceGetServiceID(service);
            CFDictionarySetValue(before, id, old);
            CFDictionarySetValue(after, id, changed);
        }
        if (!CFDictionaryGetCount(before)) throw std::runtime_error("Не найдены сетевые службы с настройками прокси.");
        return {Encode(before), Encode(after)};
    }
    void Apply(const ProxySnapshot& s) override { Update(s, false); }
    void Restore(const ProxySnapshot& s) override { Update(s, true); }
};
}
std::unique_ptr<ProxyBackend> MakeSystemProxy() { return std::unique_ptr<ProxyBackend>(new MacProxy()); }

#ifdef BYEDPI_PROXY_TEST
// Pure value tests: no preferences session, authorization or network writes.
int main() {
    auto before = Dictionary();
    Number(before, kSCPropNetProxiesHTTPEnable, 1);
    CFDictionarySetValue(before, CFSTR("ExceptionsList"), CFSTR("keep me"));
    auto after = Dictionary(before);
    Number(after, kSCPropNetProxiesHTTPEnable, 0);
    Number(after, kSCPropNetProxiesSOCKSEnable, 1);
    Number(after, kSCPropNetProxiesSOCKSPort, 1080);
    CFDictionarySetValue(after, kSCPropNetProxiesSOCKSProxy, CFSTR("127.0.0.1"));
    auto restored = RestoreValues(before, after, after);
    if (!CFEqual(restored, before)) return 1;
    auto changed = Dictionary(after);
    CFDictionarySetValue(changed, CFSTR("ExceptionsList"), CFSTR("user changed bypass list"));
    auto merged = RestoreValues(before, after, changed);
    if (!Equal(CFDictionaryGetValue(merged, CFSTR("ExceptionsList")), CFSTR("user changed bypass list"))) return 2;
    CFDictionarySetValue(changed, kSCPropNetProxiesSOCKSProxy, CFSTR("another proxy"));
    auto untouched = RestoreValues(before, after, changed);
    if (!CFEqual(untouched, changed)) return 3;
    auto services = Dictionary(); CFDictionarySetValue(services, CFSTR("test-service"), before);
    auto roundtrip = Decode(Encode(services));
    if (!CFEqual(roundtrip, services)) return 4;
    try { Decode("invalid"); return 5; } catch (const std::exception&) {}
    return 0;
}
#endif
