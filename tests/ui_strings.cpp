#include "ui.h"
#include <wx/init.h>
#include <iostream>

int main() {
    wxInitializer init;
    if (!init) return 1;
    SetEnglish(false, false);
    if (L("Включить") != wxString::FromUTF8("Включить")) return 2;
    if (L("Полная версия") != wxString::FromUTF8("Полная версия")) return 3;
    if (L("Русский") != wxString::FromUTF8("Русский")) return 5;
    if (L("Медиана, мс") != wxString::FromUTF8("Медиана, мс")) return 6;
    const char* vpnMessage = "Обнаружен включённый сторонний VPN. Выключите его перед запуском VPN или теста стратегий и повторите попытку.";
    if (L(vpnMessage) != wxString::FromUTF8(vpnMessage)) return 7;
    SetEnglish(true, false);
    if (L("Включить") != "Turn on" || L("Полная версия") != "Full version") return 4;
    if (L("Сторонний VPN включён") != "Another VPN is active" ||
        L(vpnMessage) != "Another VPN is active. Turn it off before starting the VPN or strategy tests, then try again.") return 8;
    if (L("Проверка подключения") != "Connection check" ||
        L("Не удалось проверить, включён ли сторонний VPN. Проверьте подключение к сети и повторите попытку.") !=
        "Could not check whether another VPN is active. Check your network connection and try again.") return 9;
    SetEnglish(false, false);
    std::cout << "UTF-8 Russian and English UI strings passed\n";
    return 0;
}
