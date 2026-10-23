#pragma once
#include <wx/wx.h>
#include <wx/config.h>
#include <wx/listctrl.h>
#include <wx/file.h>
#include "app_paths.h"
#include <wx/filename.h>
#include <wx/stdpaths.h>
#include <wx/tokenzr.h>
#include <algorithm>
#include <cstring>
inline bool& English() { static bool value = false; return value; }
inline void LoadLanguage() { wxConfig c("ByeDPI Desktop"); English() = c.ReadBool("english", false); }
inline void SetEnglish(bool value, bool save = true) { English() = value; if (save) { wxConfig c("ByeDPI Desktop"); c.Write("english", value); c.Flush(); } }
// Source files are UTF-8.  Never let wxWidgets interpret these bytes using the
// active Windows code page (which turns Russian text into "Рџ...").
inline wxString L(const char* text) {
    static const char* dictionary[][2] = {
    {"Вести логи", "Enable logging"},
    {"Менять настройку можно при отключённом соединении. Логи помогают при диагностике.", "Change this setting while disconnected. Logs help with troubleshooting."},
    {"Сторонний VPN включён", "Another VPN is active"},
    {"Обнаружен включённый сторонний VPN. Выключите его перед запуском VPN или теста стратегий и повторите попытку.", "Another VPN is active. Turn it off before starting the VPN or strategy tests, then try again."},
    {"Проверка подключения", "Connection check"},
    {"Не удалось проверить, включён ли сторонний VPN. Проверьте подключение к сети и повторите попытку.", "Could not check whether another VPN is active. Check your network connection and try again."},
    {"Включить", "Turn on"},
    {"Отключить", "Turn off"},
    {"Полная версия", "Full version"},
    {"Простая версия", "Simple version"},
    {"Текущая стратегия", "Current strategy"},
    {"Все стратегии и параметры", "All strategies and arguments"},
    {"Ввести свою стратегию…", "Enter custom strategy…"},
    {"Введите параметры стратегии", "Enter strategy arguments"},
    {"Добавить стратегию", "Add strategy"},
    {"Добавить стратегию…", "Add strategy…"},
    {"Сохранить стратегию", "Save strategy"},
    {"Свернуть добавление стратегии", "Collapse strategy editor"},
    {"Свои сайты…", "Custom sites…"},
    {"Свернуть свои сайты", "Collapse custom sites"},
    {"В избранное", "Add to favorites"},
    {"Тест стратегий", "Test strategies"},
    {"Прежние настройки системного прокси восстановлены.\n", "Previous system proxy settings restored.\n"},
    {"Не удалось восстановить сеть — нажмите «Восстановить сеть»", "Could not restore the network — click Restore network"},
    {"Проверьте параметры", "Check arguments"},
    {"Не найден движок ByeDPI:\n", "ByeDPI engine not found:\n"},
    {"Ошибка", "Error"},
    {"Порт уже занят. Выберите другой порт.", "Port is already in use. Choose another port."},
    {"Не удалось запустить", "Could not start"},
    {"Не удалось запустить движок. Проверьте права и архитектуру сборки.", "Could not start the engine. Check permissions and build architecture."},
    {"Запуск прокси…", "Starting proxy…"},
    {"\nЗапуск ByeDPI на ", "\nStarting ByeDPI at "},
    {"Остановка…", "Stopping…"},
    {"Процесс ещё работает. Повторная попытка остановки.\n", "Process is still running. Trying to stop again.\n"},
    {"Включение системного прокси…", "Enabling system proxy…"},
    {"Подключено — системный прокси включён", "Connected — system proxy enabled"},
    {"Системный прокси включён автоматически.\n", "System proxy enabled automatically.\n"},
    {"Прокси запущен — ручной режим", "Proxy running — manual mode"},
    {"Ручной режим: SOCKS5 — ", "Manual mode: SOCKS5 — "},
    {"Движок не открыл порт за 10 секунд. Остановка.\n", "Engine did not open its port within 10 seconds. Stopping.\n"},
    {"Движок завершён, код: %d\n", "Engine exited with code: %d\n"},
    {"Движок остановлен приложением, код: %d\n", "Engine was stopped by the application, code: %d\n"},
    {"Движок неожиданно завершён, код: %d\n", "Engine exited unexpectedly, code: %d\n"},
    {"Прокси остановлен", "Disconnected"},
    {"Движок завершил работу — проверьте журнал", "Engine exited — check the log"},
    {"Копировать адрес", "Copy address"},
    {"Порт:", "Port:"},
    {"Свои параметры", "Custom arguments"},
    {"Разделение TCP", "TCP splitting"},
    {"Разделение TLS", "TLS splitting"},
    {"Без обхода (диагностика)", "No bypass (diagnostics)"},
    {"Автоматически настраивать системный прокси", "Configure system proxy automatically"},
    {"Параметры ByeDPI (можно вставить с Android):", "ByeDPI arguments (can be pasted from Android):"},
    {"Импорт параметров…", "Import arguments…"},
    {"Восстановить сеть", "Restore network"},
    {"Текстовый файл с параметрами", "Text file with arguments"},
    {"Файл должен быть меньше 64 КБ.", "File must be smaller than 64 KB."},
    {"Выбранная политика сохранена. Нажмите «Включить».\n", "Selected strategy saved. Click Turn on.\n"},
    {"Настройки сети восстановлены", "Network settings restored"},
    {"ByeDPI уже запущен. Используйте открытое окно приложения.", "HelloAndByeDPI is already running. Use the existing window."},
    {"Не удалось прочитать файл: ", "Could not read file: "},
    {"Укажите домен SNI, например ya.ru.", "Enter an SNI domain, for example ya.ru."},
    {"SNI должен содержать только доменное имя (латиница, цифры, точки и дефисы).", "SNI must contain a domain name only (letters, digits, dots and hyphens)."},
    {"Общий", "General"},
    {"Соцсети", "Social networks"},
    {"Турция", "Türkiye"},
    {"Не проверено", "Not tested"},
    {"Доступен", "Available"},
    {"Нестабильно", "Unstable"},
    {"HTTP-ошибка", "HTTP error"},
    {"Ошибка соединения", "Connection error"},
    {" · завершено %d/%d", " · completed %d/%d"},
    {"Выберите хотя бы один список сайтов или добавьте свои адреса.", "Select at least one site list or add your own URLs."},
    {"Напрямую (контроль)", "Direct (baseline)"},
    {"Ожидает", "Waiting"},
    {"Прокси без обхода (контроль)", "Proxy without bypass (baseline)"},
    {"Политика %02d", "Strategy %02d"},
    {"Выберите хотя бы одну политику.", "Select at least one strategy."},
    {"Тест политик", "Test strategies"},
    {"Остановлено. Частичные результаты сохранены в таблице.", "Stopped. Partial results remain in the table."},
    {"Готово. Нажмите на стратегию, чтобы применить.", "Done. Click a strategy to apply it."},
    {"Не удалось выбрать свободный тестовый порт.", "Could not allocate a test port."},
    {"Не найден ciadpi рядом с приложением.", "ciadpi not found next to the application."},
    {"Не удалось запустить движок.", "Could not start the engine."},
    {"Запуск движка", "Starting engine"},
    {"Проверка сайтов", "Testing sites"},
    {"Не поддерживается", "Not supported"},
    {"Движок не открыл тестовый порт.", "Engine did not open the test port."},
    {"%zu/%zu · %s · запросов %zu/%zu", "%zu/%zu · %s · requests %zu/%zu"},
    {"Завершено", "Completed"},
    {"Ошибка теста", "Test error"},
    {"Движок завершился (%d)", "Engine exited (%d)"},
    {"Прервано", "Interrupted"},
    {"Остановка теста…", "Stopping test…"},
    {"Сохранить подробные результаты", "Save detailed results"},
    {"Не удалось сохранить CSV.", "Could not save CSV."},
    {"HelloAndByeDPI · Тест стратегий", "HelloAndByeDPI · Test strategies"},
    {"Политики: %zu · совместимы с этой ОС: %d", "Strategies: %zu · supported on this OS: %d"},
    {"[не поддерживается] ", "[not supported] "},
    {"Списки сайтов (можно выбрать несколько)", "Site lists (select one or more)"},
    {"Совместимые", "Compatible"},
    {"Снять выбор", "Clear selection"},
    {"Таймаут, с", "Timeout, s"},
    {"Попыток", "Attempts"},
    {"Параллельно", "Concurrent"},
    {"Свои сайты:\nпо одному в строке", "Custom sites:\none per line"},
    {"Импорт .txt / .sites", "Import .txt / .sites"},
    {"60 политик и 8 списков: romanvht/ByeByeDPI (GPL-3.0). Выберите строку, чтобы увидеть параметры.", "60 strategies and 8 lists: romanvht/ByeByeDPI (GPL-3.0). Select a row to inspect arguments."},
    {"Политика", "Strategy"},
    {"Параметры", "Arguments"},
    {"Системный", "System"},
    {"Пользовательский", "Custom"},
    {"Яндекс", "Yandex"},
    {"Доступно", "Available"},
    {"Ответ есть", "Responded"},
    {"Медиана, мс", "Median, ms"},
    {"Состояние", "Status"},
    {"Сайт выбранной политики", "Site for selected strategy"},
    {"Успех / попытки", "Success / attempts"},
    {"Мс", "Ms"},
    {"Результат / ошибка", "Result / error"},
    {"Нажмите на завершённую стратегию, чтобы применить её.", "Click a completed strategy to apply it."},
    {"Начать тест", "Start test"},
    {"Остановить", "Stop"},
    {"Применить выбранную", "Apply selected"},
    {"Экспорт CSV", "Export CSV"},
    {"Закрыть", "Close"},
    {"Список сайтов", "Site list"},
    {"Своя стратегия", "Custom strategy"},
    {"Без обхода", "No bypass"},
    {"Избранные стратегии", "Favorite strategies"},
    {"Режим подключения", "Connection mode"},
    {"Системный прокси", "System proxy"},
    {"SOCKS5-прокси", "SOCKS5 proxy"},
    {"VPN без обхода (контроль)", "VPN without bypass (baseline)"},
    {"VPN — все приложения", "VPN — all applications"},
    {"Для VPN-режима нужны права администратора.", "VPN mode requires administrator rights."},
    {"Создание VPN-адаптера…", "Creating VPN adapter…"},
    {"VPN подключён — весь IPv4-трафик направлен через ByeDPI", "VPN connected — all IPv4 traffic is routed through ByeDPI"},
    {"Нажмите «Включить» — браузеры с системными настройками используют прокси.\nПри отключении прежние настройки сети восстанавливаются.\nПриложения со своими настройками прокси могут игнорировать системные.", "Click Turn on — browsers using system settings will use the proxy.\nPrevious network settings are restored when you disconnect.\nApplications with their own proxy settings may ignore system settings."},
    {"Списки (*.txt;*.sites)|*.txt;*.sites|Все файлы|*", "Lists (*.txt;*.sites)|*.txt;*.sites|All files|*"},
    };
    for (auto& pair : dictionary) if (!std::strcmp(text, pair[0]) || !std::strcmp(text, pair[1]))
        return wxString::FromUTF8(pair[English() ? 1 : 0]);
    return wxString::FromUTF8(text);
}
inline wxString Translate(const wxString& text) { return L(text.utf8_str()); }
inline void TranslateWindow(wxWindow* window) {
    // Editable text, engine logs and identifiers must never be translated.
    if (dynamic_cast<wxButton*>(window) || dynamic_cast<wxStaticText*>(window) || dynamic_cast<wxCheckBox*>(window)) window->SetLabel(Translate(window->GetLabel()));
    if (auto text = dynamic_cast<wxTextCtrl*>(window)) if (!text->IsEditable()) {
        auto translated = Translate(text->GetValue()); if (translated != text->GetValue()) text->ChangeValue(translated);
    }
    if (auto dialog = dynamic_cast<wxDialog*>(window)) dialog->SetTitle(Translate(dialog->GetTitle()));
    if (auto list = dynamic_cast<wxListCtrl*>(window)) for (int i = 0; i < list->GetColumnCount(); ++i) {
        wxListItem column; column.SetMask(wxLIST_MASK_TEXT);
        if (list->GetColumn(i, column)) { column.SetText(Translate(column.GetText())); list->SetColumn(i, column); }
    }
    for (auto child : window->GetChildren()) TranslateWindow(child);
}
inline wxString StrategyName(const wxString& arguments) {
    wxFile file(ApplicationRoot() + "/data/byebyedpi/proxytest_strategies.list");
    wxString catalog;
    if (file.IsOpened() && file.ReadAll(&catalog, wxConvUTF8)) {
        auto lines = wxStringTokenize(catalog, "\n", wxTOKEN_STRTOK);
        for (size_t i = 0; i < lines.size(); ++i) {
        auto line = lines[i]; line.Trim().Trim(false); line.Replace("{sni}", "ya.ru");
            if (line == arguments) return wxString::Format(L("Политика %02d"), static_cast<int>(i + 1));
        }
    }
    if (arguments == "--split 1+s") return L("Разделение TCP");
    if (arguments == "--tlsrec 1+s") return L("Разделение TLS");
    if (arguments.empty()) return L("Без обхода");
    // A stable short fingerprint distinguishes custom favorites without exposing editable arguments.
    unsigned hash = 2166136261u;
    for (auto c : arguments.ToStdString(wxConvUTF8)) { hash ^= static_cast<unsigned char>(c); hash *= 16777619u; }
    return L("Своя стратегия") + wxString::FromUTF8(" · ") + wxString::Format("%04X", hash & 0xffffu);
}
