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
bool VpnRelaunchElevated(const wxString& executable, bool policyTests = false);
VpnPhysicalNetwork VpnFindPhysicalNetwork();
// Empty when no active VPN is found; throws when the check cannot be completed.
wxString VpnFindActiveTunnel();
bool VpnAdapterReady(const wxString& deviceName);
wxString VpnConfigure(const wxString& deviceName, const wxString& dnsServer);
wxString VpnCleanup(const wxString& deviceName);

#ifdef __APPLE__
// Build separately so shell syntax can be checked without executing privileged operations.
wxString VpnMacTunnelScript(const wxString& tun2socks, const wxString& deviceName,
    const wxString& proxy, const wxString& physicalInterface, unsigned long parentPid,
    const wxString& stopFile, const wxString& statusFile, const wxString& logFile,
    const wxString& dnsServer = "");
wxString VpnStartMacTunnel(const wxString& tun2socks, const wxString& deviceName,
    const wxString& proxy, const wxString& physicalInterface, unsigned long parentPid,
    const wxString& stopFile, const wxString& statusFile, const wxString& logFile,
    const wxString& dnsServer = "");
bool VpnMacTunnelReady(const wxString& statusFile);
bool VpnMacTunnelStopped(const wxString& statusFile);
void VpnStopMacTunnel(const wxString& stopFile);
#endif
