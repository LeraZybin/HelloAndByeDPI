#pragma once
#include <string>
#include <stdexcept>
#include <utility>

struct ProxySnapshot { std::string before, after; };
class ProxyBackend {
public:
    virtual ~ProxyBackend() {}
    virtual ProxySnapshot Prepare(int port) = 0;
    virtual void Apply(const ProxySnapshot&) = 0;
    virtual void Restore(const ProxySnapshot&) = 0;
};
class ProxyJournal {
public:
    virtual ~ProxyJournal() {}
    virtual bool Exists() = 0;
    virtual ProxySnapshot Load() = 0;
    virtual void Save(const ProxySnapshot&) = 0;
    virtual void Clear() = 0;
};
class ProxyTransaction {
    ProxyBackend& backend_;
    ProxyJournal& journal_;
public:
    ProxyTransaction(ProxyBackend& backend, ProxyJournal& journal) : backend_(backend), journal_(journal) {}
    bool Pending() { return journal_.Exists(); }
    void Recover() {
        if (!Pending()) return;
        backend_.Restore(journal_.Load());
        journal_.Clear(); // Only discard the backup after successful restoration.
    }
    void Enable(int port) {
        Recover();
        ProxySnapshot state = backend_.Prepare(port);
        journal_.Save(state); // Persist before the first network mutation.
        try { backend_.Apply(state); }
        catch (...) {
            // A failed apply may already have changed some settings.
            // Keep the recovery journal when rollback also fails.
            try { Recover(); } catch (...) {}
            throw;
        }
    }
};
