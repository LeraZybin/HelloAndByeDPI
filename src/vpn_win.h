#pragma once
#include <wx/string.h>

struct VpnPhysicalNetwork {
    wxString address;
    unsigned long interfaceIndex;
    VpnPhysicalNetwork(const wxString& value, unsigned long index) : address(value), interfaceIndex(index) {}
};

bool VpnIsAdministrator();
bool VpnRelaunchElevated(const wxString& executable);
VpnPhysicalNetwork VpnFindPhysicalNetwork();
bool VpnAdapterReady();
wxString VpnConfigure(const wxString& dnsServer);
wxString VpnCleanup();
