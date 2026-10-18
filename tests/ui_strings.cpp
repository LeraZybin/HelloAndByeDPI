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
    SetEnglish(true, false);
    if (L("Включить") != "Turn on" || L("Полная версия") != "Full version") return 4;
    SetEnglish(false, false);
    std::cout << "UTF-8 Russian and English UI strings passed\n";
    return 0;
}
