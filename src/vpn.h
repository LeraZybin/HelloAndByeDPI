#pragma once
#include <wx/string.h>

struct VpnPhysicalNetwork {
    wxString address;
    wxString interfaceName;
    unsigned long interfaceIndex;
    VpnPhysicalNetwork(const wxString& value, unsigned long index, const wxString& name = wxString())
        : address(value), interfaceName(name), interfaceIndex(index) {}
};

bool VpnIsAdministrator();
bool VpnRelaunchElevated(const wxString& executable);
VpnPhysicalNetwork VpnFindPhysicalNetwork();
bool VpnAdapterReady(const wxString& deviceName);
wxString VpnConfigure(const wxString& deviceName, const wxString& dnsServer);
wxString VpnCleanup(const wxString& deviceName);

#ifdef __APPLE__
wxString VpnStartMacTunnel(const wxString& tun2socks, const wxString& deviceName,
    const wxString& proxy, const wxString& physicalInterface, unsigned long parentPid,
    const wxString& stopFile, const wxString& statusFile, const wxString& logFile);
bool VpnMacTunnelReady(const wxString& statusFile);
void VpnStopMacTunnel(const wxString& stopFile);
#endif
