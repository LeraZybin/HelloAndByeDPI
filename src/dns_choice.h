#pragma once
#include "ui.h"
#include <wx/choice.h>
#include <sstream>
#include <vector>
#include <stdexcept>

inline const std::vector<wxString>& DnsValues() {
    static const std::vector<wxString> values{"", "8.8.8.8", "1.1.1.1", "9.9.9.9", "77.88.8.8", "custom"};
    return values;
}
inline void TranslateDnsChoice(wxChoice* choice) {
    choice->SetString(0, L("Системный")); choice->SetString(1, "Google (8.8.8.8)");
    choice->SetString(2, "Cloudflare (1.1.1.1)"); choice->SetString(3, "Quad9 (9.9.9.9)");
    choice->SetString(4, L("Яндекс") + " (77.88.8.8)"); choice->SetString(5, L("Пользовательский"));
}
inline int FillDnsChoice(wxChoice* choice, const wxString& saved) {
    for (size_t i = 0; i < DnsValues().size(); ++i) choice->Append(" ");
    TranslateDnsChoice(choice);
    int selected = 5;
    for (size_t i = 0; i + 1 < DnsValues().size(); ++i) if (saved == DnsValues()[i]) selected = static_cast<int>(i);
    choice->SetSelection(selected); return selected;
}
inline wxString ValidateDns(const wxString& input) {
    wxString value = input; value.Trim().Trim(false);
    if (value.empty()) return value;
    for (auto ch : value) if (!((ch >= '0' && ch <= '9') || ch == '.'))
        throw std::runtime_error("Invalid DNS IPv4 address.");
    std::istringstream stream(value.ToStdString());
    int octet; char dot;
    wxString normalized;
    for (int i = 0; i < 4; ++i) {
        if (!(stream >> octet) || octet < 0 || octet > 255 || (i < 3 && (!(stream >> dot) || dot != '.')))
            throw std::runtime_error("DNS: enter an IPv4 address, for example 1.1.1.1.");
        if (i) normalized += "."; normalized += wxString::Format("%d", octet);
    }
    if (stream.peek() != std::char_traits<char>::eof()) throw std::runtime_error("Invalid DNS IPv4 address.");
    return normalized;
}
