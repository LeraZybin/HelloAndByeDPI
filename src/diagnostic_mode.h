#pragma once
#include <cstdlib>
#include <cstring>
#include <atomic>

inline std::atomic<bool>& LoggingState() {
    static std::atomic<bool> enabled([] {
        const char* value = std::getenv("HELLOBYE_DIAGNOSTICS");
        return value && std::strcmp(value, "1") == 0;
    }());
    return enabled;
}
inline bool DiagnosticLogging() { return LoggingState().load(); }
inline void SetDiagnosticLogging(bool enabled) { LoggingState().store(enabled); }
