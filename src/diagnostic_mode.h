#pragma once
#include <cstdlib>
#include <cstring>

inline bool DiagnosticLogging() {
    const char* value = std::getenv("HELLOBYE_DIAGNOSTICS");
    return value && std::strcmp(value, "1") == 0;
}
