#pragma once
#include "diagnostic_mode.h"
#include <wx/utils.h>

inline wxString DiagnosticDirectory(const wxString& fallback) {
    wxString directory;
    if (DiagnosticLogging() && wxGetEnv("HELLOBYE_DIAGNOSTIC_DIR", &directory) && !directory.empty())
        return directory;
    return fallback;
}
