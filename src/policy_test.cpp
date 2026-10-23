#include "policy_test.h"
#include "arguments.h"
#include "http_probe.h"
#include "ui.h"
#include "app_paths.h"
#include <wx/wx.h>
#include <wx/checklst.h>
#include <wx/config.h>
#include <wx/file.h>
#include <wx/filename.h>
#include <wx/listctrl.h>
#include <wx/process.h>
#include <wx/socket.h>
#include <wx/spinctrl.h>
#include <wx/stdpaths.h>
#include <wx/tokenzr.h>
#include <algorithm>
#include <set>
#include <sstream>

namespace {
wxString W(const std::string& s) { return wxString::FromUTF8(s.c_str()); }
std::string U(const wxString& s) { return s.ToStdString(wxConvUTF8); }
bool IsMac() {
#ifdef __APPLE__
    return true;
#else
    return false;
#endif
}
wxString ReadFile(const wxString& path) {
    wxFile file(path);
    wxString text;
    if (!file.IsOpened() || file.Length() > 1024 * 1024 || !file.ReadAll(&text, wxConvUTF8))
        throw std::runtime_error(U(L("Не удалось прочитать файл: ") + path));
    return text;
}
wxString DataPath() {
    return ApplicationRoot() + "/data/byebyedpi/";
}
struct Policy { int id; wxString arguments, reason; };
struct Group { wxString name, filename, text; };
struct Run {
    int id;
    wxString name, arguments, status, diagnostic;
    bool complete = false, failed = false;
    std::vector<ProbeResult> results;
    int Count(bool success) const {
        std::set<std::string> sites;
        for (auto& r : results) if (success ? r.available : r.responded) sites.insert(r.url);
        return static_cast<int>(sites.size());
    }
    double Time() const {
        std::vector<double> times;
        for (auto& r : results) if (r.available) times.push_back(r.milliseconds);
        return Median(times);
    }
};
class Tester : public wxDialog {
    enum Phase { Idle, Next, Starting, Probing, Stopping } phase_ = Idle;
    wxCheckListBox *policiesBox_, *groupsBox_;
    wxTextCtrl *custom_, *sni_, *description_, *customPolicy_, *customDns_;
    wxSpinCtrl *timeout_, *attempts_, *parallel_;
    wxListCtrl *summary_, *details_;
    wxButton *start_, *cancel_, *apply_, *export_, *import_, *all_, *none_, *addPolicy_;
    wxButton *customSitesToggle_, *customPolicyToggle_;
    wxStaticText *progress_, *catalogLabel_;
    wxGauge* gauge_;
    wxChoice *language_, *dns_;
    wxButton* mode_;
    wxBoxSizer* root_;
    wxSizerItem *customSitesItem_ = nullptr, *customPolicyItem_ = nullptr;
    std::vector<wxSizerItem*> advanced_;
    std::vector<wxString> dnsValues_;
    bool full_ = false, applying_ = false;
    bool customSitesExpanded_ = false, customPolicyExpanded_ = false;
    void Presentation() {
        for (auto item : advanced_) item->Show(full_);
        if (customSitesItem_) customSitesItem_->Show(full_ && customSitesExpanded_);
        if (customPolicyItem_) customPolicyItem_->Show(full_ && customPolicyExpanded_);
        if (customSitesToggle_) customSitesToggle_->SetLabel(L(customSitesExpanded_ ? "Свернуть свои сайты" : "Свои сайты…"));
        if (customPolicyToggle_) customPolicyToggle_->SetLabel(L(customPolicyExpanded_ ? "Свернуть добавление стратегии" : "Добавить стратегию…"));
        for (auto item : root_->GetChildren()) item->SetBorder(full_ ? 4 : 12);
        start_->SetMinSize(wxSize(-1, full_ ? 36 : 64));
        apply_->Show(full_); export_->Show(full_);
        mode_->SetLabel(L(full_ ? "Простая версия" : "Полная версия"));
        summary_->SetColumnWidth(0, full_ ? 150 : 125);
        summary_->SetColumnWidth(1, full_ ? 360 : 245);
        summary_->SetColumnWidth(2, 95); summary_->SetColumnWidth(3, full_ ? 100 : 0);
        summary_->SetColumnWidth(4, full_ ? 110 : 0); summary_->SetColumnWidth(5, full_ ? 250 : 170);
        SetMinSize(wxSize(full_ ? 920 : 500, full_ ? 620 : 420));
        auto screen = wxGetClientDisplayRect();
        SetSize(std::min(full_ ? 1100 : 550, screen.width - 30), std::min(full_ ? 740 : 540, screen.height - 40));
        Layout();
    }
    void LanguageChanged() {
        TranslateWindow(this);
        language_->SetSelection(English() ? 1 : 0);
#ifdef __WXMSW__
        dns_->SetString(0, L("Системный"));
        dns_->SetString(1, "Google (8.8.8.8)"); dns_->SetString(2, "Cloudflare (1.1.1.1)");
        dns_->SetString(3, "Quad9 (9.9.9.9)"); dns_->SetString(4, L("Яндекс") + " (77.88.8.8)");
        dns_->SetString(5, L("Пользовательский"));
#endif
        int supported = 0; for (auto& policy : policies_) supported += policy.reason.empty();
        catalogLabel_->SetLabel(wxString::Format(L("Политики: %zu · совместимы с этой ОС: %d"), policies_.size(), supported));
        for (size_t i = 0; i < groups_.size(); ++i) groupsBox_->SetString(i, Translate(groups_[i].name) + wxString::FromUTF8(" · ") + wxString::Format("%zu", ParseSites(U(groups_[i].text)).size()));
        for (size_t i = 0; i < policies_.size(); ++i) policiesBox_->SetString(i, wxString::Format("%02d", policies_[i].id) + wxString::FromUTF8(" · ") + (policies_[i].reason.empty() ? "" : L("[не поддерживается] ")) + policies_[i].arguments.Left(90));
        for (auto& run : runs_) { run.name = run.id > 0 ? wxString::Format(L("Политика %02d"), run.id) : Translate(run.name); run.status = Translate(run.status); }
        Summary(); Presentation();
    }
    void ApplySelected() {
        if (selected_ < 0 || static_cast<size_t>(selected_) >= runs_.size()) return;
        auto& run = runs_[selected_];
        if (run.id <= 0 || !run.complete || run.failed) return;
        chosen_ = run.arguments; SaveSettings();
        if (phase_ == Idle) EndModal(wxID_OK);
        else { applying_ = true; Cancel(); }
    }
    wxTimer timer_;
    wxConfig config_{"ByeDPI Policy Tests"};
    std::vector<Policy> policies_;
    std::vector<Group> groups_;
    std::vector<Run> runs_;
    std::vector<std::string> sites_;
    std::unique_ptr<ProbeBatch> batch_;
    wxProcess* process_ = nullptr;
    long pid_ = 0;
    size_t current_ = 0;
    int selected_ = -1, port_ = 0, ticks_ = 0, runAttempts_ = 1;
    int sortColumn_ = 2;
    bool sortAscending_ = false;
    bool cancelled_ = false, closing_ = false, updating_ = false;
    wxString timestamp_;
    wxString chosen_;
    bool smoke_ = false, earlySmoke_ = false;
    int smokeResult_ = 1;
    std::vector<std::string> Arguments(const wxString& text) {
        return parseArguments(U(text), IsMac());
    }
    wxString DnsServer() const {
        int selected = dns_->GetSelection();
        if (selected < 0 || static_cast<size_t>(selected) >= dnsValues_.size()) return "";
        wxString result = dnsValues_[selected] == "custom" ? customDns_->GetValue() : dnsValues_[selected];
        result.Trim().Trim(false); return result;
    }
    wxString Resolve(const wxString& text) {
        wxString host = sni_->GetValue(); host.Trim().Trim(false);
        if (host.empty() || host.length() > 253) throw std::runtime_error(U(L("Укажите домен SNI, например ya.ru.")));
        for (auto ch : U(host)) if (!(std::isalnum(static_cast<unsigned char>(ch)) || ch == '.' || ch == '-'))
            throw std::runtime_error(U(L("SNI должен содержать только доменное имя (латиница, цифры, точки и дефисы).")));
        wxString result = text; result.Replace("{sni}", host);
        return result;
    }
    void LoadCatalog() {
        auto lines = wxStringTokenize(ReadFile(DataPath() + "proxytest_strategies.list"), "\n", wxTOKEN_STRTOK);
        for (auto line : lines) {
            line.Trim().Trim(false); if (line.empty()) continue;
            Policy p{static_cast<int>(policies_.size()) + 1, line, ""};
            wxString resolved = line; resolved.Replace("{sni}", "ya.ru");
            try { Arguments(resolved); }
            catch (const std::exception& e) { p.reason = W(e.what()); }
            policies_.push_back(p);
        }
        const std::pair<wxString, wxString> names[] = {
            {L("Общий"), "general"}, {"YouTube", "youtube"}, {"Googlevideo", "googlevideo"},
            {"Discord", "discord"}, {"Telegram", "telegram"}, {L("Соцсети"), "social"},
            {"Cloudflare", "cloudflare"}, {L("Турция"), wxString::FromUTF8("türkiye")}
        };
        for (auto entry : names) {
            wxString filename = "proxytest_" + entry.second + ".sites";
            groups_.push_back({entry.first, filename, ReadFile(DataPath() + filename)});
        }
        wxString customPolicy = config_.Read("custom_policy", ""); customPolicy.Trim().Trim(false);
        if (!customPolicy.empty()) {
            Policy p{static_cast<int>(policies_.size()) + 1, customPolicy, ""};
            wxString resolved = customPolicy; resolved.Replace("{sni}", "ya.ru");
            try { Arguments(resolved); } catch (const std::exception& e) { p.reason = W(e.what()); }
            policies_.push_back(p);
        }
    }
    void Controls(bool idle) {
        policiesBox_->Enable(idle); groupsBox_->Enable(idle); custom_->Enable(idle);
        timeout_->Enable(idle); attempts_->Enable(idle); parallel_->Enable(idle); sni_->Enable(idle);
        start_->Enable(idle); import_->Enable(idle); all_->Enable(idle); none_->Enable(idle);
        customPolicy_->Enable(idle); addPolicy_->Enable(idle); dns_->Enable(idle);
        customSitesToggle_->Enable(idle); customPolicyToggle_->Enable(idle);
        customDns_->Enable(idle && !dnsValues_.empty() && dnsValues_.back() == "custom" &&
            dns_->GetSelection() == static_cast<int>(dnsValues_.size() - 1));
        cancel_->Enable(!idle); export_->Enable(idle && !runs_.empty());
        apply_->Enable(idle && selected_ >= 0 && runs_[selected_].id > 0 && runs_[selected_].complete && !runs_[selected_].failed);
    }
    void SaveSettings() {
        if (smoke_) return;
        config_.Write("custom_sites", custom_->GetValue());
        config_.Write("sni", sni_->GetValue());
        config_.Write("timeout", timeout_->GetValue());
        config_.Write("attempts", attempts_->GetValue());
        config_.Write("parallel", parallel_->GetValue());
        config_.Write("custom_policy", customPolicy_->GetValue());
        config_.Write("dns_server", DnsServer());
        for (size_t i = 0; i < groups_.size(); ++i) config_.Write(groups_[i].filename, groupsBox_->IsChecked(i));
        config_.Flush();
    }
    void Details() {
        details_->DeleteAllItems();
        if (selected_ < 0 || static_cast<size_t>(selected_) >= runs_.size()) return;
        auto& run = runs_[selected_];
        description_->SetValue(run.arguments + (run.diagnostic.empty() ? "" : "\n" + run.diagnostic));
        for (auto& site : sites_) {
            int success = 0, received = 0, completed = 0;
            std::set<long> codes; std::vector<double> times; wxString error;
            for (auto& result : run.results) if (result.url == site) {
                ++completed; success += result.available; received += result.responded;
                if (result.http) codes.insert(result.http);
                if (result.available) times.push_back(result.milliseconds);
                if (!result.error.empty()) error = W(result.error);
            }
            long row = details_->InsertItem(details_->GetItemCount(), W(site));
            details_->SetItem(row, 1, wxString::Format("%d/%d", success, runAttempts_));
            wxString http; for (auto code : codes) { if (!http.empty()) http += ", "; http += wxString::Format("%ld", code); }
            details_->SetItem(row, 2, http);
            double time = Median(times); details_->SetItem(row, 3, time >= 0 ? wxString::Format("%.0f", time) : wxString::FromUTF8("—"));
            wxString state;
            if (completed == 0) state = run.failed ? run.status : wxString(L("Не проверено"));
            else state = success == runAttempts_ ? L("Доступен") : success > 0 ? L("Нестабильно") : received > 0 ? L("HTTP-ошибка") : L("Ошибка соединения");
            if (completed < runAttempts_ && completed > 0) state += wxString::Format(L(" · завершено %d/%d"), completed, runAttempts_);
            if (!error.empty()) state += wxString::FromUTF8(" · ") + error;
            details_->SetItem(row, 4, state);
        }
        Controls(phase_ == Idle);
    }
    void SortHeader() {
        const char* labels[] = {"Политика", "Параметры", "Доступно", "Ответ есть", "Медиана, мс", "Состояние"};
        for (int column = 0; column < 6; ++column) {
            wxListItem item; item.SetMask(wxLIST_MASK_TEXT);
            item.SetText(L(labels[column]) + (column == sortColumn_ ? wxString::FromUTF8(sortAscending_ ? " ▲" : " ▼") : ""));
            summary_->SetColumn(column, item);
        }
    }
    void Summary() {
        // Never programmatically select a simple-mode row: selection is its Apply action.
        updating_ = true; summary_->DeleteAllItems();
        std::vector<size_t> order;
        for (size_t i = 0; i < runs_.size(); ++i) order.push_back(i);
        std::stable_sort(order.begin(), order.end(), [this](size_t a, size_t b) {
            auto& x = runs_[a]; auto& y = runs_[b];
            int comparison = 0;
            switch (sortColumn_) {
                case 0: comparison = x.name.CmpNoCase(y.name); break;
                case 1: comparison = x.arguments.CmpNoCase(y.arguments); break;
                case 2: comparison = x.Count(true) - y.Count(true); break;
                case 3: comparison = x.Count(false) - y.Count(false); break;
                case 4: {
                    double xt = x.Time(), yt = y.Time();
                    if (xt < 0 || yt < 0) {
                        if (xt < 0 && yt >= 0) return false;
                        if (xt >= 0 && yt < 0) return true;
                    }
                    comparison = xt < yt ? -1 : xt > yt ? 1 : 0;
                    break;
                }
                case 5: comparison = x.status.CmpNoCase(y.status); break;
            }
            if (comparison == 0 && sortColumn_ == 2) {
                bool xc = x.complete && !x.failed, yc = y.complete && !y.failed;
                if (xc != yc) return xc;
                double xt = x.Time(), yt = y.Time();
                if (xt != yt) return (xt < 0 ? 1e20 : xt) < (yt < 0 ? 1e20 : yt);
            }
            if (comparison == 0) comparison = x.id - y.id;
            return sortAscending_ ? comparison < 0 : comparison > 0;
        });
        for (auto index : order) {
            auto& run = runs_[index];
            if (!full_ && run.id <= 0) continue;
            long row = summary_->InsertItem(summary_->GetItemCount(), run.name);
            summary_->SetItemData(row, index);
            summary_->SetItem(row, 1, run.arguments);
            summary_->SetItem(row, 2, sites_.empty() ? wxString::FromUTF8("—") : wxString::Format("%d/%zu", run.Count(true), sites_.size()));
            summary_->SetItem(row, 3, wxString::Format("%d/%zu", run.Count(false), sites_.size()));
            double time = run.Time(); summary_->SetItem(row, 4, time >= 0 ? wxString::Format("%.0f", time) : wxString::FromUTF8("—"));
            summary_->SetItem(row, 5, run.status);
            if (full_ && selected_ == static_cast<int>(index)) summary_->SetItemState(row, wxLIST_STATE_SELECTED, wxLIST_STATE_SELECTED);
        }
        SortHeader(); updating_ = false; Details();
    }
    void Begin() {
        try {
            wxString allSites = custom_->GetValue() + "\n";
            for (size_t i = 0; i < groups_.size(); ++i) if (groupsBox_->IsChecked(i)) allSites += groups_[i].text + "\n";
            auto sites = ParseSites(U(allSites));
            if (sites.empty()) throw std::runtime_error(U(L("Выберите хотя бы один список сайтов или добавьте свои адреса.")));
            std::vector<Run> runs;
            Run direct; direct.id = 0; direct.name = L("Напрямую (контроль)"); direct.status = L("Ожидает"); runs.push_back(direct);
            Run plain; plain.id = -1; plain.name = L("Прокси без обхода (контроль)"); plain.status = L("Ожидает"); runs.push_back(plain);
            for (size_t i = 0; i < policies_.size(); ++i) if (policiesBox_->IsChecked(i)) {
                Run run; run.id = policies_[i].id; run.name = wxString::Format(L("Политика %02d"), run.id);
                run.arguments = Resolve(policies_[i].arguments); run.status = L("Ожидает");
                try { Arguments(run.arguments); }
                catch (const std::exception& e) { run.failed = true; run.diagnostic = W(e.what()); }
                runs.push_back(run);
            }
            if (runs.size() == 2) throw std::runtime_error(U(L("Выберите хотя бы одну политику.")));
            SaveSettings(); sites_ = std::move(sites); runs_ = std::move(runs);
            runAttempts_ = attempts_->GetValue(); selected_ = 0; current_ = 0;
            cancelled_ = false; closing_ = false; applying_ = false;
            timestamp_ = wxDateTime::Now().FormatISOCombined(' ');
            phase_ = Next; Controls(false); gauge_->SetValue(0);
            Summary(); timer_.Start(75);
        } catch (const std::exception& e) { wxMessageBox(W(e.what()), L("Тест политик"), wxOK | wxICON_WARNING, this); }
    }
    void Finish() {
        timer_.Stop(); batch_.reset(); phase_ = Idle;
        progress_->SetLabel(cancelled_ ? L("Остановлено. Частичные результаты сохранены в таблице.") : L("Готово. Нажмите на стратегию, чтобы применить."));
        if (!cancelled_) gauge_->SetValue(1000);
        Summary(); Controls(true);
        if (smoke_) {
            bool valid = runs_.size() == 3 && (earlySmoke_ ? cancelled_ && applying_ && !chosen_.empty() : !cancelled_);
            for (auto& run : runs_) valid = valid && run.complete && !run.failed && run.results.size() == 2 && run.Count(true) == 1 && run.Count(false) == 2;
            if (valid) {
                smokeResult_ = 0;
                if (earlySmoke_) { EndModal(wxID_OK); return; }
                selected_ = 2; Details();
                wxCommandEvent apply(wxEVT_BUTTON, apply_->GetId()); apply_->GetEventHandler()->ProcessEvent(apply);
            } else {
                for (auto& run : runs_) fprintf(stderr, "%s: %s %s\n", U(run.name).c_str(), U(run.status).c_str(), U(run.diagnostic).c_str());
                EndModal(wxID_CANCEL);
            }
            return;
        }
        if (applying_) EndModal(wxID_OK);
        else if (closing_) EndModal(wxID_CANCEL);
    }
    void StartEngine() {
        wxIPV4address endpoint; endpoint.Hostname("127.0.0.1"); endpoint.Service(0);
        { wxSocketServer reserve(endpoint, wxSOCKET_NOWAIT);
          if (!reserve.IsOk() || !reserve.GetLocal(endpoint)) throw std::runtime_error(U(L("Не удалось выбрать свободный тестовый порт.")));
          port_ = endpoint.Service(); }
        wxFileName engine(ApplicationRoot() + "/ciadpi");
#ifdef __WXMSW__
        engine.SetFullName("ciadpi.exe");
#else
        engine.SetFullName("ciadpi");
#endif
        if (!engine.IsFileExecutable()) throw std::runtime_error(U(L("Не найден ciadpi рядом с приложением.")));
        auto parsed = Arguments(runs_[current_].arguments);
        std::vector<wxString> args{engine.GetFullPath(), "--ip", "127.0.0.1", "--port", wxString::Format("%d", port_)};
#ifdef __WXMSW__
        args.push_back("--debug"); args.push_back("0");
        args.push_back("--wait-send");
#endif
        for (auto& argument : parsed) args.push_back(W(argument));
        std::vector<const wchar_t*> argv; for (auto& argument : args) argv.push_back(argument.wc_str()); argv.push_back(nullptr);
        process_ = new wxProcess(this); process_->Redirect();
        pid_ = wxExecute(argv.data(), wxEXEC_ASYNC | wxEXEC_HIDE_CONSOLE, process_);
        if (!pid_) { delete process_; process_ = nullptr; throw std::runtime_error(U(L("Не удалось запустить движок."))); }
        process_->CloseOutput(); ticks_ = 0; phase_ = Starting;
        runs_[current_].status = L("Запуск движка");
    }
    void StartBatch() {
        batch_.reset(new ProbeBatch(sites_, runAttempts_, timeout_->GetValue(), parallel_->GetValue(), runs_[current_].id == 0 ? 0 : port_, U(DnsServer())));
        runs_[current_].status = L("Проверка сайтов"); phase_ = Probing;
    }
    void StopEngine() {
        batch_.reset();
        if (pid_) { phase_ = Stopping; ticks_ = 0; wxProcess::Kill(pid_, wxSIGTERM); }
        else if (cancelled_) Finish();
        else { ++current_; phase_ = Next; }
    }
    void Drain(wxInputStream* stream) {
        if (!stream) return;
        char data[4096];
        for (int i = 0; i < 8 && stream->CanRead(); ++i) {
            stream->Read(data, sizeof(data)); size_t n = stream->LastRead(); if (!n) break;
            auto& log = runs_[current_].diagnostic;
            if (log.size() < 16000) log += wxString::FromUTF8(data, n);
        }
    }
    void Tick(wxTimerEvent&) {
        try {
            if (process_) { Drain(process_->GetInputStream()); Drain(process_->GetErrorStream()); }
            if (phase_ == Next) {
                while (current_ < runs_.size() && runs_[current_].failed) {
                    runs_[current_].complete = true; runs_[current_].status = L("Не поддерживается"); ++current_;
                }
                if (current_ == runs_.size()) { Finish(); return; }
                if (runs_[current_].id == 0) StartBatch(); else StartEngine();
                Summary();
            } else if (phase_ == Starting) {
                wxIPV4address endpoint; endpoint.Hostname("127.0.0.1"); endpoint.Service(port_);
                wxSocketClient connection; connection.SetTimeout(1);
                if (connection.Connect(endpoint, true)) { StartBatch(); Summary(); }
                else if (++ticks_ >= 65) throw std::runtime_error(U(L("Движок не открыл тестовый порт.")));
            } else if (phase_ == Probing) {
                auto completed = batch_->Poll();
                auto& run = runs_[current_]; run.results.insert(run.results.end(), completed.begin(), completed.end());
                size_t planned = sites_.size() * runAttempts_;
                progress_->SetLabel(wxString::Format(L("%zu/%zu · %s · запросов %zu/%zu"), current_ + 1, runs_.size(), run.name, run.results.size(), planned));
                gauge_->SetValue(static_cast<int>(1000 * (current_ + static_cast<double>(run.results.size()) / planned) / runs_.size()));
                if (!completed.empty()) Summary();
                if (batch_->Done()) {
                    run.complete = true; run.status = L("Завершено"); StopEngine(); Summary();
                    if (earlySmoke_ && run.id > 0) {
                        for (long row = 0; row < summary_->GetItemCount(); ++row) if (summary_->GetItemData(row) == current_) {
                            // Generate the same selection notification as a single click.
                            summary_->SetItemState(row, wxLIST_STATE_SELECTED, wxLIST_STATE_SELECTED); break;
                        }
                    }
                }
            } else if (phase_ == Stopping && ++ticks_ >= 25) {
                wxProcess::Kill(pid_, wxSIGKILL); ticks_ = 0;
            }
        } catch (const std::exception& e) {
            auto& run = runs_[current_]; run.failed = true; run.complete = true;
            run.status = L("Ошибка теста"); run.diagnostic += W(e.what()); StopEngine(); Summary();
        }
    }
    void End(wxProcessEvent& event) {
        if (event.GetPid() != pid_) return;
        Drain(process_->GetInputStream()); Drain(process_->GetErrorStream());
        delete process_; process_ = nullptr; pid_ = 0;
        if (phase_ != Stopping) {
            auto& run = runs_[current_]; run.failed = true; run.complete = true;
            run.status = wxString::Format(L("Движок завершился (%d)"), event.GetExitCode()); batch_.reset();
        }
        if (cancelled_) Finish(); else { ++current_; phase_ = Next; Summary(); }
    }
    void Cancel() {
        if (phase_ == Idle) return;
        cancelled_ = true;
        if (current_ < runs_.size() && !runs_[current_].complete) runs_[current_].status = L("Прервано");
        cancel_->Disable(); progress_->SetLabel(L("Остановка теста…"));
        StopEngine();
    }
    void Export() {
        wxFileDialog dialog(this, L("Сохранить подробные результаты"), "", "byedpi-policy-results.csv", "CSV (*.csv)|*.csv", wxFD_SAVE | wxFD_OVERWRITE_PROMPT);
        if (dialog.ShowModal() != wxID_OK) return;
        std::ostringstream out;
        out << "\xef\xbb\xbf" "date,policy,arguments,site,attempt,http,available,responded,milliseconds,error,sample_limited,policy_status\r\n";
        for (auto& run : runs_) {
            for (auto& site : sites_) {
                bool any = false;
                for (auto& r : run.results) if (r.url == site) {
                    any = true;
                    out << CsvCell(U(timestamp_)) << ',' << CsvCell(U(run.name)) << ',' << CsvCell(U(run.arguments)) << ',' << CsvCell(site)
                        << ',' << r.attempt << ',' << r.http << ',' << r.available << ',' << r.responded << ',' << r.milliseconds
                        << ',' << CsvCell(r.error) << ',' << r.sampleLimited << ',' << CsvCell(U(run.status)) << "\r\n";
                }
                if (!any) out << CsvCell(U(timestamp_)) << ',' << CsvCell(U(run.name)) << ',' << CsvCell(U(run.arguments)) << ',' << CsvCell(site)
                    << ",,,,,," << CsvCell(U(run.diagnostic)) << ",," << CsvCell(U(run.status)) << "\r\n";
            }
        }
        auto text = out.str(); wxFile file(dialog.GetPath(), wxFile::write);
        if (!file.IsOpened() || file.Write(text.data(), text.size()) != text.size()) wxMessageBox(L("Не удалось сохранить CSV."));
    }
public:
    explicit Tester(wxWindow* parent, const wxString& smokeURL = "", bool applyEarly = false) : wxDialog(parent, wxID_ANY, L("HelloAndByeDPI · Тест стратегий"), wxDefaultPosition, wxSize(1100, 740), wxDEFAULT_DIALOG_STYLE | wxRESIZE_BORDER), timer_(this) {
        smoke_ = !smokeURL.empty(); earlySmoke_ = applyEarly; SetEscapeId(wxID_NONE);
        LoadCatalog(); SetMinSize(wxSize(920, 620));
        auto root = new wxBoxSizer(wxVERTICAL); root_ = root;
        auto header = new wxBoxSizer(wxHORIZONTAL); header->AddStretchSpacer();
        language_ = new wxChoice(this, wxID_ANY); language_->Append(L("Русский")); language_->Append("English");
        language_->SetSelection(English() ? 1 : 0); header->Add(language_, 0, wxRIGHT, 8);
        mode_ = new wxButton(this, wxID_ANY, L("Полная версия")); header->Add(mode_);
        root->Add(header, 0, wxEXPAND | wxALL, 18);
        start_ = new wxButton(this, wxID_ANY, L("Начать тест"), wxDefaultPosition, wxSize(-1, 64));
        start_->SetFont(start_->GetFont().Larger().Bold());
        root->Add(start_, 0, wxEXPAND | wxLEFT | wxRIGHT | wxBOTTOM, 18);
        auto selection = new wxBoxSizer(wxHORIZONTAL);
        auto policyColumn = new wxBoxSizer(wxVERTICAL);
        int supported = 0; for (auto& p : policies_) supported += p.reason.empty();
        catalogLabel_ = new wxStaticText(this, wxID_ANY, wxString::Format(L("Политики: %zu · совместимы с этой ОС: %d"), policies_.size(), supported));
        policyColumn->Add(catalogLabel_, 0, wxBOTTOM, 4);
        policiesBox_ = new wxCheckListBox(this, wxID_ANY, wxDefaultPosition, wxSize(540, 145));
        for (auto& p : policies_) {
            policiesBox_->Append(wxString::Format("%02d", p.id) + wxString::FromUTF8(" · ") + (p.reason.empty() ? "" : L("[не поддерживается] ")) + p.arguments.Left(90));
            policiesBox_->Check(p.id - 1, p.reason.empty());
        }
        policyColumn->Add(policiesBox_, 1, wxEXPAND); selection->Add(policyColumn, 2, wxRIGHT | wxEXPAND, 12);
        auto groupColumn = new wxBoxSizer(wxVERTICAL);
        groupColumn->Add(new wxStaticText(this, wxID_ANY, L("Списки сайтов (можно выбрать несколько)")), 0, wxBOTTOM, 4);
        groupsBox_ = new wxCheckListBox(this, wxID_ANY, wxDefaultPosition, wxSize(300, 145));
        for (auto& group : groups_) {
            auto count = ParseSites(U(group.text)).size();
            int i = groupsBox_->Append(group.name + wxString::FromUTF8(" · ") + wxString::Format("%zu", count));
            bool checked; config_.Read(group.filename, &checked, group.name == "YouTube"); groupsBox_->Check(i, checked);
        }
        groupColumn->Add(groupsBox_, 1, wxEXPAND); selection->Add(groupColumn, 1, wxEXPAND);
        root->Add(selection, 0, wxEXPAND | wxALL, 10); advanced_.push_back(root->GetItem(root->GetItemCount() - 1));
        customPolicyToggle_ = new wxButton(this, wxID_ANY, L("Добавить стратегию…"));
        root->Add(customPolicyToggle_, 0, wxEXPAND | wxLEFT | wxRIGHT | wxBOTTOM, 10); advanced_.push_back(root->GetItem(root->GetItemCount() - 1));
        auto customPolicyRow = new wxBoxSizer(wxHORIZONTAL);
        customPolicy_ = new wxTextCtrl(this, wxID_ANY, config_.Read("custom_policy", ""));
        addPolicy_ = new wxButton(this, wxID_ANY, L("Сохранить стратегию"));
        customPolicyRow->Add(customPolicy_, 1, wxRIGHT, 8); customPolicyRow->Add(addPolicy_);
        root->Add(customPolicyRow, 0, wxEXPAND | wxLEFT | wxRIGHT | wxBOTTOM, 10); customPolicyItem_ = root->GetItem(root->GetItemCount() - 1); advanced_.push_back(customPolicyItem_);
        auto options = new wxBoxSizer(wxHORIZONTAL);
        all_ = new wxButton(this, wxID_ANY, L("Совместимые")); none_ = new wxButton(this, wxID_ANY, L("Снять выбор"));
        options->Add(all_, 0, wxRIGHT, 5); options->Add(none_, 0, wxRIGHT, 12);
        auto spin = [&](const wxString& label, int low, int high, const wxString& key, int value) {
            options->Add(new wxStaticText(this, wxID_ANY, label), 0, wxALIGN_CENTER_VERTICAL | wxRIGHT, 4);
            auto control = new wxSpinCtrl(this, wxID_ANY, "", wxDefaultPosition, wxSize(65, -1), wxSP_ARROW_KEYS, low, high, value);
            control->SetValue(config_.ReadLong(key, value)); options->Add(control, 0, wxRIGHT, 10); return control;
        };
        timeout_ = spin(L("Таймаут, с"), 1, 60, "timeout", 5);
        attempts_ = spin(L("Попыток"), 1, 5, "attempts", 1);
        parallel_ = spin(L("Параллельно"), 1, 12, "parallel", 6);
        options->Add(new wxStaticText(this, wxID_ANY, "SNI"), 0, wxALIGN_CENTER_VERTICAL | wxRIGHT, 4);
        wxString savedSni = config_.Read("sni", "ya.ru");
        if (savedSni == "google.com") savedSni = "ya.ru";
        sni_ = new wxTextCtrl(this, wxID_ANY, savedSni, wxDefaultPosition, wxSize(135, -1)); options->Add(sni_, 1);
        root->Add(options, 0, wxEXPAND | wxLEFT | wxRIGHT | wxBOTTOM, 10); advanced_.push_back(root->GetItem(root->GetItemCount() - 1));
        auto dnsRow = new wxBoxSizer(wxHORIZONTAL);
        dnsRow->Add(new wxStaticText(this, wxID_ANY, "DNS"), 0, wxALIGN_CENTER_VERTICAL | wxRIGHT, 8);
        dns_ = new wxChoice(this, wxID_ANY);
#ifdef __WXMSW__
        dnsValues_ = {"", "8.8.8.8", "1.1.1.1", "9.9.9.9", "77.88.8.8", "custom"};
        dns_->Append(L("Системный")); dns_->Append("Google (8.8.8.8)");
        dns_->Append("Cloudflare (1.1.1.1)"); dns_->Append("Quad9 (9.9.9.9)");
        dns_->Append(L("Яндекс") + " (77.88.8.8)"); dns_->Append(L("Пользовательский"));
        wxString savedDns = config_.Read("dns_server", "1.1.1.1");
        int dnsSelection = static_cast<int>(dnsValues_.size()) - 1;
        for (size_t i = 0; i + 1 < dnsValues_.size(); ++i) if (savedDns == dnsValues_[i]) dnsSelection = static_cast<int>(i);
        dns_->SetSelection(dnsSelection);
        customDns_ = new wxTextCtrl(this, wxID_ANY, dnsSelection == static_cast<int>(dnsValues_.size()) - 1 ? savedDns : "", wxDefaultPosition, wxSize(150, -1));
#else
        dnsValues_ = {""}; dns_->Append(L("Системный")); dns_->SetSelection(0);
        customDns_ = new wxTextCtrl(this, wxID_ANY, "", wxDefaultPosition, wxSize(150, -1));
#endif
        dnsRow->Add(dns_, 0, wxRIGHT, 8); dnsRow->Add(customDns_, 0);
        customDns_->Show(!dnsValues_.empty() && dnsValues_.back() == "custom" && dns_->GetSelection() == static_cast<int>(dnsValues_.size() - 1));
        root->Add(dnsRow, 0, wxEXPAND | wxLEFT | wxRIGHT | wxBOTTOM, 10); advanced_.push_back(root->GetItem(root->GetItemCount() - 1));
        customSitesToggle_ = new wxButton(this, wxID_ANY, L("Свои сайты…"));
        root->Add(customSitesToggle_, 0, wxEXPAND | wxLEFT | wxRIGHT | wxBOTTOM, 10); advanced_.push_back(root->GetItem(root->GetItemCount() - 1));
        auto customRow = new wxBoxSizer(wxHORIZONTAL);
        customRow->Add(new wxStaticText(this, wxID_ANY, L("Свои сайты:\nпо одному в строке")), 0, wxALIGN_CENTER_VERTICAL | wxRIGHT, 8);
        custom_ = new wxTextCtrl(this, wxID_ANY, config_.Read("custom_sites", ""), wxDefaultPosition, wxSize(-1, 45), wxTE_MULTILINE);
        customRow->Add(custom_, 1, wxRIGHT, 8); import_ = new wxButton(this, wxID_ANY, L("Импорт .txt / .sites")); customRow->Add(import_, 0, wxALIGN_CENTER_VERTICAL);
        root->Add(customRow, 0, wxEXPAND | wxLEFT | wxRIGHT | wxBOTTOM, 10); customSitesItem_ = root->GetItem(root->GetItemCount() - 1); advanced_.push_back(customSitesItem_);
        description_ = new wxTextCtrl(this, wxID_ANY, L("60 политик и 8 списков: romanvht/ByeByeDPI (GPL-3.0). Выберите строку, чтобы увидеть параметры."), wxDefaultPosition, wxSize(-1, 40), wxTE_READONLY | wxTE_MULTILINE);
        root->Add(description_, 0, wxEXPAND | wxLEFT | wxRIGHT | wxBOTTOM, 10); advanced_.push_back(root->GetItem(root->GetItemCount() - 1));
        summary_ = new wxListCtrl(this, wxID_ANY, wxDefaultPosition, wxSize(-1, 125), wxLC_REPORT | wxLC_SINGLE_SEL);
        summary_->InsertColumn(0, L("Политика"), wxLIST_FORMAT_LEFT, 150);
        summary_->InsertColumn(1, L("Параметры"), wxLIST_FORMAT_LEFT, 360);
        summary_->InsertColumn(2, L("Доступно"), wxLIST_FORMAT_LEFT, 95);
        summary_->InsertColumn(3, L("Ответ есть"), wxLIST_FORMAT_LEFT, 100);
        summary_->InsertColumn(4, L("Медиана, мс"), wxLIST_FORMAT_LEFT, 110);
        summary_->InsertColumn(5, L("Состояние"), wxLIST_FORMAT_LEFT, 250);
        root->Add(summary_, 1, wxEXPAND | wxLEFT | wxRIGHT | wxBOTTOM, 10);
        details_ = new wxListCtrl(this, wxID_ANY, wxDefaultPosition, wxSize(-1, 115), wxLC_REPORT | wxLC_SINGLE_SEL);
        details_->InsertColumn(0, L("Сайт выбранной политики"), wxLIST_FORMAT_LEFT, 290);
        details_->InsertColumn(1, L("Успех / попытки"), wxLIST_FORMAT_LEFT, 125);
        details_->InsertColumn(2, "HTTP", wxLIST_FORMAT_LEFT, 80);
        details_->InsertColumn(3, L("Мс"), wxLIST_FORMAT_LEFT, 75);
        details_->InsertColumn(4, L("Результат / ошибка"), wxLIST_FORMAT_LEFT, 420);
        root->Add(details_, 1, wxEXPAND | wxLEFT | wxRIGHT | wxBOTTOM, 10); advanced_.push_back(root->GetItem(root->GetItemCount() - 1));
        progress_ = new wxStaticText(this, wxID_ANY, L("Нажмите на завершённую стратегию, чтобы применить её."));
        root->Add(progress_, 0, wxLEFT | wxRIGHT | wxBOTTOM, 10);
        gauge_ = new wxGauge(this, wxID_ANY, 1000, wxDefaultPosition, wxSize(-1, 10)); root->Add(gauge_, 0, wxEXPAND | wxLEFT | wxRIGHT | wxBOTTOM, 10);
        auto buttons = new wxBoxSizer(wxHORIZONTAL);
        cancel_ = new wxButton(this, wxID_ANY, L("Остановить"));
        apply_ = new wxButton(this, wxID_ANY, L("Применить выбранную")); export_ = new wxButton(this, wxID_ANY, L("Экспорт CSV"));
        auto close = new wxButton(this, wxID_ANY, L("Закрыть"));
        buttons->Add(cancel_, 0, wxRIGHT, 8); buttons->Add(apply_, 0, wxRIGHT, 8);
        buttons->Add(export_, 0, wxRIGHT, 8); buttons->AddStretchSpacer(); buttons->Add(close);
        root->Add(buttons, 0, wxEXPAND | wxLEFT | wxRIGHT | wxBOTTOM, 10); SetSizer(root);
        mode_->Bind(wxEVT_BUTTON, [this](wxCommandEvent&) { full_ = !full_; Presentation(); Summary(); });
        language_->Bind(wxEVT_CHOICE, [this](wxCommandEvent&) { SetEnglish(language_->GetSelection() == 1, !smoke_); LanguageChanged(); });
        customPolicyToggle_->Bind(wxEVT_BUTTON, [this](wxCommandEvent&) { customPolicyExpanded_ = !customPolicyExpanded_; Presentation(); });
        customSitesToggle_->Bind(wxEVT_BUTTON, [this](wxCommandEvent&) { customSitesExpanded_ = !customSitesExpanded_; Presentation(); });
        dns_->Bind(wxEVT_CHOICE, [this](wxCommandEvent&) {
            bool custom = !dnsValues_.empty() && dnsValues_.back() == "custom" && dns_->GetSelection() == static_cast<int>(dnsValues_.size() - 1);
            customDns_->Show(custom); customDns_->Enable(custom && phase_ == Idle); Layout();
        });
        Controls(true);
        all_->Bind(wxEVT_BUTTON, [this](wxCommandEvent&) { for (size_t i = 0; i < policies_.size(); ++i) policiesBox_->Check(i, policies_[i].reason.empty()); });
        none_->Bind(wxEVT_BUTTON, [this](wxCommandEvent&) { for (size_t i = 0; i < policies_.size(); ++i) policiesBox_->Check(i, false); });
        addPolicy_->Bind(wxEVT_BUTTON, [this](wxCommandEvent&) {
            wxString arguments = customPolicy_->GetValue(); arguments.Trim().Trim(false);
            if (arguments.empty()) return;
            try {
                Arguments(Resolve(arguments));
                size_t index = policies_.size();
                if (index > 0 && policies_.back().id > 60) {
                    policies_.back().arguments = arguments; policies_.back().reason.clear(); index = policies_.size() - 1;
                    policiesBox_->SetString(index, wxString::Format("%02d", policies_[index].id) + wxString::FromUTF8(" · ") + arguments.Left(90));
                } else {
                    policies_.push_back({static_cast<int>(policies_.size()) + 1, arguments, ""});
                    policiesBox_->Append(wxString::Format("%02d", policies_.back().id) + wxString::FromUTF8(" · ") + arguments.Left(90));
                }
                policiesBox_->Check(index, true); config_.Write("custom_policy", arguments); config_.Flush();
                bool found = false;
                for (auto& run : runs_) if (run.id == policies_[index].id) { run.arguments = arguments; found = true; }
                if (!found) { Run run; run.id = policies_[index].id; run.name = wxString::Format(L("Политика %02d"), run.id); run.arguments = arguments; run.status = L("Ожидает"); runs_.push_back(run); }
                LanguageChanged();
            } catch (const std::exception& e) { wxMessageBox(W(e.what()), L("Проверьте параметры"), wxOK | wxICON_WARNING, this); }
        });
        policiesBox_->Bind(wxEVT_LISTBOX, [this](wxCommandEvent& e) { auto& p = policies_[e.GetSelection()]; description_->SetValue(p.arguments + "\n" + p.reason); });
        start_->Bind(wxEVT_BUTTON, [this](wxCommandEvent&) { Begin(); });
        cancel_->Bind(wxEVT_BUTTON, [this](wxCommandEvent&) { Cancel(); });
        export_->Bind(wxEVT_BUTTON, [this](wxCommandEvent&) { Export(); });
        import_->Bind(wxEVT_BUTTON, [this](wxCommandEvent&) {
            wxFileDialog file(this, L("Список сайтов"), "", "", L("Списки (*.txt;*.sites)|*.txt;*.sites|Все файлы|*"), wxFD_OPEN | wxFD_FILE_MUST_EXIST);
            if (file.ShowModal() == wxID_OK) try {
                auto sites = ParseSites(U(ReadFile(file.GetPath()))); wxString text = custom_->GetValue();
                for (auto& site : sites) text += "\n" + W(site); custom_->SetValue(text);
            } catch (const std::exception& e) { wxMessageBox(W(e.what())); }
        });
        summary_->Bind(wxEVT_LIST_ITEM_SELECTED, [this](wxListEvent& e) { if (!updating_) { selected_ = static_cast<int>(e.GetData()); Details(); if (!full_) ApplySelected(); } });
        summary_->Bind(wxEVT_LIST_COL_CLICK, [this](wxListEvent& e) {
            int column = e.GetColumn();
            if (sortColumn_ == column) sortAscending_ = !sortAscending_;
            else { sortColumn_ = column; sortAscending_ = column < 2 || column == 5; }
            Summary();
        });
        apply_->Bind(wxEVT_BUTTON, [this](wxCommandEvent&) { ApplySelected(); });
        close->Bind(wxEVT_BUTTON, [this](wxCommandEvent&) { Close(); });
        Bind(wxEVT_TIMER, &Tester::Tick, this); Bind(wxEVT_END_PROCESS, &Tester::End, this);
        Bind(wxEVT_CLOSE_WINDOW, [this](wxCloseEvent& e) {
            SaveSettings();
            if (phase_ != Idle && e.CanVeto()) { e.Veto(); closing_ = true; Cancel(); }
            else { if (pid_) { wxProcess::Kill(pid_, wxSIGKILL); process_->Detach(); process_ = nullptr; } EndModal(wxID_CANCEL); }
        });
        for (auto& policy : policies_) if (policy.reason.empty()) {
            Run run; run.id = policy.id; run.name = wxString::Format(L("Политика %02d"), run.id);
            run.arguments = policy.arguments; run.status = L("Ожидает"); runs_.push_back(run);
        }
        LanguageChanged(); CentreOnParent();
        if (smoke_) CallAfter([this, smokeURL] {
            bool valid = !full_ && !policiesBox_->IsShown() && summary_->IsShown();
            SetEnglish(true, false); LanguageChanged();
            valid = valid && start_->GetLabel() == "Start test" && mode_->GetLabel() == "Full version";
            full_ = true; Presentation(); valid = valid && policiesBox_->IsShown() && details_->IsShown();
            valid = valid && customSitesToggle_->IsShown() && customPolicyToggle_->IsShown() &&
                !custom_->IsShown() && !customPolicy_->IsShown();
            customSitesExpanded_ = true; customPolicyExpanded_ = true; Presentation();
            valid = valid && custom_->IsShown() && customPolicy_->IsShown();
            customSitesExpanded_ = false; customPolicyExpanded_ = false; Presentation();
            fprintf(stderr, "Tester full content: %d x %d; client: %d x %d\n", root_->GetMinSize().x, root_->GetMinSize().y, GetClientSize().x, GetClientSize().y);
            full_ = false; SetEnglish(false, false); LanguageChanged();
            if (runs_.size() >= 2) {
                phase_ = Probing;
                ProbeResult result; result.url = "http://local.test/"; result.available = true; result.responded = true;
                runs_[1].results.push_back(result); runs_[1].complete = true; Summary();
                valid = valid && summary_->GetItemData(0) == 1;
                sortColumn_ = 0; sortAscending_ = true; Summary();
                valid = valid && summary_->GetItemData(0) == 0;
                sortAscending_ = false; Summary();
                valid = valid && summary_->GetItemData(0) == static_cast<long>(runs_.size() - 1);
                sortColumn_ = 2; sortAscending_ = false; Summary();
                phase_ = Idle;
            } else valid = false;
            if (!valid) { fprintf(stderr, "Tester UI mode/language/sorting check failed\n"); EndModal(wxID_CANCEL); return; }
            for (size_t i = 0; i < groups_.size(); ++i) groupsBox_->Check(i, false);
            for (size_t i = 0; i < policies_.size(); ++i) policiesBox_->Check(i, i == 59);
            custom_->SetValue(smokeURL + "/ok\n" + smokeURL + "/denied");
            timeout_->SetValue(5); attempts_->SetValue(1); parallel_->SetValue(2); sni_->SetValue("ya.ru");
            Begin();
        });
    }
    ~Tester() override {
        timer_.Stop(); batch_.reset();
        if (pid_) { wxProcess::Kill(pid_, wxSIGKILL); process_->Detach(); }
    }
    wxString Chosen() const { return chosen_; }
    int SmokeResult() const { return smokeResult_; }
};
}
PolicyChoice ShowPolicyTests(wxWindow* parent) {
    try {
        Tester dialog(parent);
        if (dialog.ShowModal() == wxID_OK) return {true, dialog.Chosen()};
    } catch (const std::exception& e) { wxMessageBox(W(e.what()), L("Тест политик"), wxOK | wxICON_ERROR, parent); }
    return {false, ""};
}
int RunPolicyUISmoke(wxWindow* parent, const wxString& localBaseURL, bool applyEarly) {
    try {
        Tester dialog(parent, localBaseURL, applyEarly);
        int result = dialog.ShowModal();
        return result == wxID_OK && !dialog.Chosen().empty() ? dialog.SmokeResult() : 1;
    } catch (const std::exception& e) { fprintf(stderr, "%s\n", e.what()); return 1; }
}
