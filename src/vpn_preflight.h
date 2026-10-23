#pragma once
#include "vpn.h"
#include "ui.h"
#include <stdexcept>

// Called before elevation, engine launch, or any network setting changes.
inline bool VpnPreflight(wxWindow* parent, wxString& diagnostic) {
    try {
        const wxString conflict = VpnFindActiveTunnel();
        if (conflict.empty()) return true;
        diagnostic = "Start blocked: another VPN is active: " + conflict;
        wxMessageBox(L("Обнаружен включённый сторонний VPN. Выключите его перед запуском VPN или теста стратегий и повторите попытку."),
            L("Сторонний VPN включён"), wxOK | wxICON_INFORMATION, parent);
    } catch (const std::exception& error) {
        diagnostic = "VPN preflight failed: " + wxString::FromUTF8(error.what());
        wxMessageBox(L("Не удалось проверить, включён ли сторонний VPN. Проверьте подключение к сети и повторите попытку."),
            L("Проверка подключения"), wxOK | wxICON_INFORMATION, parent);
    }
    return false;
}
