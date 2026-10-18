#pragma once
#include <wx/string.h>
class wxWindow;
struct PolicyChoice { bool selected; wxString arguments; };
PolicyChoice ShowPolicyTests(wxWindow* parent);
int RunPolicyUISmoke(wxWindow* parent, const wxString& localBaseURL, bool applyEarly = false);
