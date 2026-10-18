#pragma once
#include <wx/filename.h>
#include <wx/stdpaths.h>

inline wxString ApplicationRoot() {
    wxFileName executable(wxStandardPaths::Get().GetExecutablePath());
    wxFileName directory;
    directory.AssignDir(executable.GetPath());
#ifdef __WXMSW__
    const wxArrayString& parts = directory.GetDirs();
    if (!parts.empty() && parts.Last().CmpNoCase("lib") == 0) directory.RemoveLastDir();
#endif
    return directory.GetPath();
}
