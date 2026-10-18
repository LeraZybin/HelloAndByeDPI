#include "proxy_transaction.h"
#include <iostream>
#include <cstdlib>
void check(bool ok) { if (!ok) std::exit(1); }
struct Journal : ProxyJournal {
    bool exists = false, failSave = false;
    ProxySnapshot value;
    bool Exists() override { return exists; }
    ProxySnapshot Load() override { return value; }
    void Save(const ProxySnapshot& s) override {
        if (failSave) throw std::runtime_error("disk full");
        value = s; exists = true;
    }
    void Clear() override { exists = false; }
};
struct Backend : ProxyBackend {
    Journal& journal;
    bool failApply = false, failRestore = false;
    std::string current = "corporate proxy";
    explicit Backend(Journal& j) : journal(j) {}
    ProxySnapshot Prepare(int) override { return {current, "local proxy"}; }
    void Apply(const ProxySnapshot& s) override {
        check(journal.Exists()); current = s.after;
        if (failApply) throw std::runtime_error("partial apply");
    }
    void Restore(const ProxySnapshot& s) override {
        if (failRestore) throw std::runtime_error("permission denied");
        if (current == s.after) current = s.before;
    }
};
template<class F> void throws(F f) { try { f(); } catch (...) { return; } std::exit(1); }
int main() {
    Journal j; Backend b(j); ProxyTransaction t(b, j);
    t.Enable(1080); check(b.current == "local proxy" && j.Exists());
    t.Recover(); check(b.current == "corporate proxy" && !j.Exists());
    j.failSave = true; throws([&] { t.Enable(1080); });
    check(b.current == "corporate proxy"); j.failSave = false;
    b.failApply = true; throws([&] { t.Enable(1080); });
    check(b.current == "corporate proxy" && !j.Exists());
    b.failRestore = true; throws([&] { t.Enable(1080); });
    check(j.Exists());
    throws([&] { t.Recover(); }); check(j.Exists());
    b.failApply = false; b.failRestore = false;
    ProxyTransaction restarted(b, j); restarted.Recover();
    check(b.current == "corporate proxy" && !j.Exists());
    t.Enable(1080); b.current = "user changed proxy"; t.Recover();
    check(b.current == "user changed proxy" && !j.Exists());
    std::cout << "Proxy rollback, crash recovery and journal failures passed\n";
}
