#pragma once
#include <wx/string.h>
class wxWindow;
struct PolicyChoice {
    bool selected; wxString arguments; bool vpn; wxString dns;
    PolicyChoice(bool selectedValue = false, const wxString& args = "", bool vpnValue = false, const wxString& dnsValue = "")
        : selected(selectedValue), arguments(args), vpn(vpnValue), dns(dnsValue) {}
};
PolicyChoice ShowPolicyTests(wxWindow* parent, bool vpn = false, const wxString& dns = "");
int RunPolicyUISmoke(wxWindow* parent, const wxString& localBaseURL, bool applyEarly = false, bool vpn = false);
