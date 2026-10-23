#include <wx/wx.h>
#include <wx/config.h>
#include <wx/filename.h>
#include <wx/process.h>
#include <wx/socket.h>
#include <wx/spinctrl.h>
#include <wx/stdpaths.h>
#include <wx/clipbrd.h>
#include <wx/wfstream.h>
#include <wx/sstream.h>
#include <wx/snglinst.h>
#include <wx/scrolwin.h>
#include <wx/ffile.h>
#include <future>
#include <chrono>
#include "arguments.h"
#include "system_proxy.h"
#include "policy_test.h"
#include "ui.h"
#include "app_paths.h"
#if defined(__WXMSW__) || defined(__APPLE__)
#include "vpn.h"
#endif
#ifdef __WXMSW__
#include <windows.h>
#endif

#ifndef BYEDPI_APP_VERSION
#define BYEDPI_APP_VERSION "development"
#endif

static bool smokeTest = false;
static bool systemProxySmoke = false;
static bool startVpnElevated = false;
static int smokeResult = 1;

static bool VpnAvailable() {
#if (defined(__WXMSW__) && defined(_WIN64)) || defined(__APPLE__)
    return true;
#else
    return false;
#endif
}

class MainFrame : public wxFrame {
    wxTextCtrl *arguments_ = nullptr, *log_ = nullptr;
    wxSpinCtrl* port_;
    wxChoice* profile_;
    wxChoice *language_, *favorites_, *catalog_, *networkMode_;
    wxButton *mode_, *favoriteButton_, *customButton_;
    wxStaticText *currentPolicy_, *catalogLabel_;
    wxBoxSizer* root_;
    std::vector<wxSizerItem*> advanced_;
    std::vector<wxString> favoriteArgs_;
    std::vector<wxString> catalogArgs_;
    bool full_ = false;
    void RefreshCatalog() {
        catalogArgs_.clear(); catalog_->Clear();
        wxFile file(ApplicationRoot() + "/data/byebyedpi/proxytest_strategies.list");
        wxString text;
        if (file.IsOpened() && file.ReadAll(&text, wxConvUTF8)) {
            auto lines = wxStringTokenize(text, "\n", wxTOKEN_STRTOK);
            for (auto line : lines) {
                line.Trim().Trim(false); if (line.empty()) continue;
                line.Replace("{sni}", "ya.ru"); catalogArgs_.push_back(line);
                int id = static_cast<int>(catalogArgs_.size());
                catalog_->Append(wxString::Format(L("Политика %02d"), id) + wxString::FromUTF8(" · ") + line.Left(80));
            }
        }
        int selected = wxNOT_FOUND;
        for (size_t i = 0; i < catalogArgs_.size(); ++i) if (catalogArgs_[i] == arguments_->GetValue()) selected = static_cast<int>(i);
        catalog_->SetSelection(selected);
        catalogLabel_->SetLabel(L("Все стратегии и параметры"));
    }
    void RefreshFavorites() {
        favoriteArgs_.clear(); favorites_->Clear();
        wxString current = arguments_->GetValue();
        long count = config_.ReadLong("favorites/count", 0);
        for (long i = 0; i < std::min(count, 200L); ++i) {
            wxString arg = config_.Read(wxString::Format("favorites/%ld", i), "");
            if (!arg.empty() && std::find(favoriteArgs_.begin(), favoriteArgs_.end(), arg) == favoriteArgs_.end()) favoriteArgs_.push_back(arg);
        }
        if (favoriteArgs_.empty()) favoriteArgs_.push_back("--split 1+s");
        if (std::find(favoriteArgs_.begin(), favoriteArgs_.end(), current) == favoriteArgs_.end()) favoriteArgs_.insert(favoriteArgs_.begin(), current);
        int selected = 0;
        for (size_t i = 0; i < favoriteArgs_.size(); ++i) {
            favorites_->Append(StrategyName(favoriteArgs_[i]));
            if (favoriteArgs_[i] == current) selected = static_cast<int>(i);
        }
        favorites_->SetSelection(selected);
        favorites_->SetToolTip(L("Избранные стратегии"));
        currentPolicy_->SetLabel(L("Текущая стратегия") + wxString::FromUTF8(" · ") + StrategyName(current));
        Layout();
    }
    void AddFavorite() {
        RefreshFavorites();
        if (!smokeTest) {
            config_.Write("favorites/count", static_cast<long>(favoriteArgs_.size()));
            for (size_t i = 0; i < favoriteArgs_.size(); ++i) config_.Write(wxString::Format("favorites/%zu", i), favoriteArgs_[i]);
            config_.Flush();
        }
    }
    void Presentation() {
        for (auto item : advanced_) item->Show(full_);
        for (auto item : root_->GetChildren()) item->SetBorder(full_ ? 8 : 18);
        toggle_->SetMinSize(wxSize(-1, full_ ? 44 : 76));
        mode_->SetLabel(L(full_ ? "Простая версия" : "Полная версия"));
        restore_->Show(full_ || (proxy_ && proxy_->Pending()));
        SetMinSize(wxSize(full_ ? 760 : 560, full_ ? 700 : 580));
        SetSize(full_ ? wxSize(800, 760) : wxSize(700, 650));
        Layout();
        static_cast<wxScrolledWindow*>(toggle_->GetParent())->FitInside();
    }
    void LanguageChanged() {
        TranslateWindow(this);
        language_->SetSelection(English() ? 1 : 0);
        const char* names[] = {"Свои параметры", "Разделение TCP", "Разделение TLS", "Без обхода (диагностика)"};
        for (unsigned i = 0; i < 4; ++i) profile_->SetString(i, L(names[i]));
        networkMode_->SetString(0, L("Системный прокси"));
        if (networkMode_->GetCount() > 1) networkMode_->SetString(1, L("VPN — все приложения"));
        RefreshCatalog(); RefreshFavorites(); Presentation();
    }
    wxStaticText *status_, *address_;
    wxButton *toggle_, *import_;
    wxCheckBox* automatic_;
    wxButton* restore_;
    wxButton* test_;
    std::unique_ptr<ProxyBackend> proxyBackend_;
    std::unique_ptr<ProxyJournal> proxyJournal_;
    std::unique_ptr<ProxyTransaction> proxy_;
    wxProcess* process_ = nullptr;
    wxProcess* tunProcess_ = nullptr;
    long pid_ = 0;
    long tunPid_ = 0;
    wxTimer timer_;
    int ticks_ = 0;
    bool stopping_ = false, closing_ = false, ready_ = false;
    bool vpnActive_ = false, vpnStarting_ = false, vpnConfiguring_ = false, vpnConfigured_ = false;
    bool processFailed_ = false;
    int vpnTicks_ = 0;
    std::future<wxString> vpnFuture_;
    wxConfig config_{"ByeDPI Desktop"};
    wxString logPath_;
    wxString vpnDevice_;
    wxString vpnStopFile_, vpnStatusFile_;
    VpnPhysicalNetwork vpnPhysical_{"", 0};

    void Log(const wxString& text) {
        if (log_) {
            if (log_->GetLastPosition() > 180000) log_->Remove(0, 60000);
            log_->AppendText(text);
        }
        if (logPath_.empty() || smokeTest) return;
        auto bytes = text.utf8_str();
        wxFFile file(logPath_, "ab");
        if (file.IsOpened()) file.Write(bytes.data(), bytes.length());
    }
    void Event(const wxString& text) {
        Log("[" + wxDateTime::Now().FormatISOCombined(' ') + "] " + text + "\n");
    }
    void InitializeLog() {
#ifdef __APPLE__
        wxString directory = wxStandardPaths::Get().GetUserDataDir();
        wxFileName::Mkdir(directory, 0700, wxPATH_MKDIR_FULL);
        logPath_ = directory + "/HelloAndByeDPI.log";
#else
        logPath_ = ApplicationRoot() + "/HelloAndByeDPI.log";
        wxFFile test(logPath_, "ab");
        if (!test.IsOpened()) {
            wxString directory = wxStandardPaths::Get().GetUserDataDir();
            wxFileName::Mkdir(directory, 0700, wxPATH_MKDIR_FULL);
            logPath_ = directory + "/HelloAndByeDPI.log";
        } else test.Close();
#endif
        if (wxFileExists(logPath_) && wxFileName(logPath_).GetSize() > 2 * 1024 * 1024)
            wxRenameFile(logPath_, logPath_ + ".old", true);
        Event("=== HelloAndByeDPI " BYEDPI_APP_VERSION " session ===");
        Event("OS: " + wxGetOsDescription() + wxString::Format("; process architecture: %zu-bit; PID: %lu", sizeof(void*) * 8, static_cast<unsigned long>(wxGetProcessId())));
        Event("Executable: " + wxStandardPaths::Get().GetExecutablePath());
        Event("Log file: " + logPath_);
    }
    void Save() {
        if (smokeTest) return;
        config_.Write("english", English());
        config_.Write("arguments", arguments_->GetValue());
        config_.Write("port", port_->GetValue());
        config_.Write("automatic_proxy", automatic_->GetValue());
        config_.Write("vpn_mode", VpnAvailable() && networkMode_->GetSelection() == 1);
        config_.Flush();
    }
    void Editable(bool enable) {
        arguments_->Enable(enable); port_->Enable(enable);
        profile_->Enable(enable); import_->Enable(enable);
        automatic_->Enable(enable);
        test_->Enable(enable); favorites_->Enable(enable); catalog_->Enable(enable);
        networkMode_->Enable(enable);
        favoriteButton_->Enable(enable); customButton_->Enable(enable);
    }
    bool RestoreProxy() {
        if (!proxy_ || !proxy_->Pending()) return true;
        Event("Restoring saved system proxy settings");
        try {
            proxy_->Recover();
            restore_->Disable();
            Log(L("Прежние настройки системного прокси восстановлены.\n"));
            return true;
        } catch (const std::exception& error) {
            closing_ = false;
            restore_->Show(); Layout(); restore_->Enable();
            status_->SetLabel(L("Не удалось восстановить сеть — нажмите «Восстановить сеть»"));
            Log(wxString::FromUTF8(error.what()) + "\n");
            Event("Proxy restore failed: " + wxString::FromUTF8(error.what()));
            return false;
        }
    }
    void DrainAvailable(wxProcess* child, bool errors) {
        if (!child) return;
        wxInputStream* stream = errors ? child->GetErrorStream() : child->GetInputStream();
        if (!stream) return;
        std::string bytes;
        bytes.reserve(4096);
        for (size_t count = 0; count < 65536 &&
            (errors ? child->IsErrorAvailable() : child->IsInputAvailable()); ++count) {
            char byte = static_cast<char>(stream->GetC());
            if (stream->LastRead() != 1) break;
            bytes.push_back(byte);
        }
        if (bytes.empty()) return;
        wxString text = wxString::FromUTF8(bytes.data(), bytes.size());
        if (text.empty()) text = wxString::From8BitData(bytes.data(), bytes.size());
        Log(text);
    }
    void Drain(wxProcess* child) {
        DrainAvailable(child, false);
        DrainAvailable(child, true);
    }
    bool Listening() {
        wxIPV4address endpoint;
        endpoint.Hostname("127.0.0.1"); endpoint.Service(port_->GetValue());
        wxSocketClient client;
        client.SetTimeout(1);
        return client.Connect(endpoint, true);
    }
    void StartVpnTunnel() {
#ifdef __WXMSW__
        wxFileName executable(ApplicationRoot() + "/lib/tun2socks.exe");
        wxFileName driver(ApplicationRoot() + "/lib/wintun.dll");
        if (!executable.FileExists() || !driver.FileExists())
            throw std::runtime_error("Не найдены lib/tun2socks.exe или lib/wintun.dll.");
        std::vector<wxString> args{executable.GetFullPath(), "--device",
            "tun://HelloAndByeDPI?guid={A18F60A0-0D7B-4A41-925E-BA2DAB87C847}",
            "--proxy", wxString::Format("socks5://127.0.0.1:%d", port_->GetValue()),
            "--mtu", "1500", "--loglevel", "warning"};
        std::vector<const wchar_t*> argv; for (const auto& arg : args) argv.push_back(arg.wc_str()); argv.push_back(nullptr);
        wxString command; for (const auto& arg : args) command += wxString(command.empty() ? "" : " ") + "\"" + arg + "\"";
        Event("tun2socks command: " + command);
        tunProcess_ = new wxProcess(this); tunProcess_->Redirect();
        tunPid_ = wxExecute(argv.data(), wxEXEC_ASYNC | wxEXEC_HIDE_CONSOLE, tunProcess_);
        if (!tunPid_) { delete tunProcess_; tunProcess_ = nullptr; throw std::runtime_error("Не удалось запустить tun2socks.exe."); }
        tunProcess_->CloseOutput(); vpnStarting_ = true; vpnConfiguring_ = false; vpnTicks_ = 0;
        toggle_->Disable();
        status_->SetLabel(L("Создание VPN-адаптера…"));
        Event(wxString::Format("tun2socks started; PID: %ld", tunPid_));
#elif defined(__APPLE__)
        wxFileName executable(ApplicationRoot() + "/lib/tun2socks");
        if (!executable.IsFileExecutable())
            throw std::runtime_error("Не найден исполняемый lib/tun2socks.");
        vpnDevice_ = "utun233";
        for (int unit = 233; unit < 250 && VpnAdapterReady(vpnDevice_); ++unit)
            vpnDevice_ = wxString::Format("utun%d", unit + 1);
        if (VpnAdapterReady(vpnDevice_)) throw std::runtime_error("Не найден свободный интерфейс utun.");
        vpnStopFile_ = wxString::Format("/tmp/org.helloandbyedpi.%lu.stop", static_cast<unsigned long>(wxGetProcessId()));
        vpnStatusFile_ = wxString::Format("/tmp/org.helloandbyedpi.%lu.status", static_cast<unsigned long>(wxGetProcessId()));
        const wxString proxy = wxString::Format("socks5://127.0.0.1:%d", port_->GetValue());
        const wxString device = vpnDevice_, tunnel = executable.GetFullPath(), physical = vpnPhysical_.interfaceName;
        const wxString stop = vpnStopFile_, status = vpnStatusFile_, log = logPath_;
        Event("Requesting macOS VPN authorization for " + device + " through " + physical);
        vpnFuture_ = std::async(std::launch::async, [tunnel, device, proxy, physical, stop, status, log] {
            return VpnStartMacTunnel(tunnel, device, proxy, physical,
                static_cast<unsigned long>(wxGetProcessId()), stop, status, log);
        });
        vpnConfiguring_ = true; vpnStarting_ = false; vpnTicks_ = 0;
        toggle_->Disable();
        status_->SetLabel(L("Разрешите создание VPN в системном окне…"));
#endif
    }
    void Start() {
        Event("Turn on requested");
        vpnActive_ = VpnAvailable() && networkMode_->GetSelection() == 1;
#ifdef __WXMSW__
        if (vpnActive_ && !VpnIsAdministrator()) {
            Save(); Event("VPN requires administrator rights; requesting elevation");
            if (!VpnRelaunchElevated(wxStandardPaths::Get().GetExecutablePath())) {
                Event("UAC elevation was cancelled or failed");
                wxMessageBox(L("Для VPN-режима нужны права администратора."), L("Не удалось запустить"), wxOK | wxICON_WARNING, this);
            } else Destroy();
            return;
        }
#endif
        if (!full_ && !smokeTest && !vpnActive_) automatic_->SetValue(true);
        if (!RestoreProxy()) return;
        std::vector<std::string> parsed;
        try {
            parsed = parseArguments(arguments_->GetValue().ToStdString(wxConvUTF8),
#ifdef __APPLE__
                true
#else
                false
#endif
            );
        } catch (const std::exception& error) {
            wxMessageBox(wxString::FromUTF8(error.what()), L("Проверьте параметры"), wxOK | wxICON_WARNING, this); return;
        }
        wxFileName engine(ApplicationRoot() + "/ciadpi");
#ifdef __WXMSW__
        engine.SetFullName("ciadpi.exe");
#else
        engine.SetFullName("ciadpi");
#endif
        if (!engine.IsFileExecutable()) {
            Event("Engine is missing or not executable: " + engine.GetFullPath());
            wxMessageBox(L("Не найден движок ByeDPI:\n") + engine.GetFullPath(), L("Ошибка"), wxOK | wxICON_ERROR, this); return;
        }
        if (Listening()) {
            Event(wxString::Format("Port %d is already occupied", port_->GetValue()));
            wxMessageBox(L("Порт уже занят. Выберите другой порт."), L("Не удалось запустить"), wxOK | wxICON_WARNING, this); return;
        }
        // Listen for both protocols on one socket: tun2socks and manually
        // configured clients use SOCKS5, while Windows' system proxy uses
        // its reliably persisted HTTP/HTTPS proxy representation.
        std::vector<wxString> args = {engine.GetFullPath(),
            "--ip", "socks5://127.0.0.1", "--ip", "http://127.0.0.1",
            "--port", wxString::Format("%d", port_->GetValue()), "--debug", "0"};
#ifdef __WXMSW__
        // Windows has no TCP_INFO check for pending split segments here.
        // Waiting makes disorder independent of debug-output timing and the
        // TCP stack differences between Windows 8.1 and newer versions.
        args.push_back("--wait-send");
#endif
#if defined(__WXMSW__) || defined(__APPLE__)
        if (vpnActive_) {
            try {
                vpnPhysical_ = VpnFindPhysicalNetwork();
                args.push_back("--conn-ip"); args.push_back(vpnPhysical_.address);
                Event("Physical IPv4 selected for ByeDPI outbound connections: " + vpnPhysical_.address +
                    " (" + vpnPhysical_.interfaceName + wxString::Format(", interface index %lu)", vpnPhysical_.interfaceIndex));
            } catch (const std::exception& error) {
                Event("Physical network detection failed: " + wxString::FromUTF8(error.what()));
                wxMessageBox(wxString::FromUTF8(error.what()), L("Не удалось запустить"), wxOK | wxICON_ERROR, this); return;
            }
        }
#endif
        for (const auto& arg : parsed) args.push_back(wxString::FromUTF8(arg.c_str()));
        std::vector<const wchar_t*> argv;
        for (const auto& arg : args) argv.push_back(arg.wc_str());
        argv.push_back(nullptr);
        wxString command;
        for (const auto& arg : args) command += wxString(command.empty() ? "" : " ") + "\"" + arg + "\"";
        Event("Engine command: " + command);
        Save();
        process_ = new wxProcess(this);
        process_->Redirect();
        pid_ = wxExecute(argv.data(), wxEXEC_ASYNC | wxEXEC_HIDE_CONSOLE, process_);
        if (!pid_) {
#ifdef __WXMSW__
            Event(wxString::Format("wxExecute failed; Windows error: %lu", static_cast<unsigned long>(GetLastError())));
#else
            Event("wxExecute failed");
#endif
            delete process_; process_ = nullptr;
            wxMessageBox(L("Не удалось запустить движок. Проверьте права и архитектуру сборки."), L("Ошибка"), wxOK | wxICON_ERROR, this); return;
        }
        process_->CloseOutput();
        Event(wxString::Format("Engine started; PID: %ld", pid_));
        ticks_ = 0; stopping_ = false; ready_ = false; processFailed_ = false;
        Editable(false); toggle_->SetLabel(L("Отключить"));
        status_->SetLabel(L("Запуск прокси…"));
        Log(L("\nЗапуск ByeDPI на ") + address_->GetLabel() + "\n");
        timer_.Start(100);
    }
    void Stop() {
        if ((!pid_ && !tunPid_) || stopping_) return;
        // Keep the local proxy alive if the OS refuses to restore settings.
        if (!RestoreProxy()) return;
        stopping_ = true; ticks_ = 0;
        Event(wxString::Format("Stopping engine PID %ld", pid_));
        status_->SetLabel(L("Остановка…")); toggle_->Disable();
        if (vpnActive_) {
#ifdef __APPLE__
            VpnStopMacTunnel(vpnStopFile_);
#endif
            Event("Removing VPN routes: " + VpnCleanup(vpnDevice_));
            vpnConfigured_ = false; vpnStarting_ = false; vpnConfiguring_ = false;
        }
        if (tunPid_) Event(wxString::Format("tun2socks SIGTERM result: %d", static_cast<int>(wxProcess::Kill(tunPid_, wxSIGTERM))));
        if (pid_) Event(wxString::Format("ByeDPI SIGTERM result: %d", static_cast<int>(wxProcess::Kill(pid_, wxSIGTERM))));
    }
    void Tick(wxTimerEvent&) {
        if (!process_ && !tunProcess_) return;
        if (process_) Drain(process_);
        if (tunProcess_) Drain(tunProcess_);
        ++ticks_;
        if (stopping_) {
            if (ticks_ == 20) { if (tunPid_) wxProcess::Kill(tunPid_, wxSIGKILL); if (pid_) wxProcess::Kill(pid_, wxSIGKILL); }
            if (ticks_ == 50) {
                Log(L("Процесс ещё работает. Повторная попытка остановки.\n"));
                if (tunPid_) wxProcess::Kill(tunPid_, wxSIGKILL); if (pid_) wxProcess::Kill(pid_, wxSIGKILL); ticks_ = 20;
            }
        } else if (vpnConfiguring_) {
#if defined(__WXMSW__) || defined(__APPLE__)
            if (vpnFuture_.valid() && vpnFuture_.wait_for(std::chrono::milliseconds(0)) == std::future_status::ready) {
                vpnConfiguring_ = false;
                try {
                    Event("VPN configuration completed: " + vpnFuture_.get());
#ifdef __APPLE__
                    vpnStarting_ = true; vpnTicks_ = 0;
                    status_->SetLabel(L("Создание VPN-адаптера…"));
#else
                    vpnConfigured_ = true;
                    status_->SetLabel(L("VPN подключён — весь IPv4-трафик направлен через ByeDPI"));
                    Event("VPN routes are active");
                    if (closing_) Stop(); else toggle_->Enable();
#endif
                } catch (const std::exception& error) {
                    Event("VPN configuration failed: " + wxString::FromUTF8(error.what()));
                    wxMessageBox(wxString::FromUTF8(error.what()), L("Не удалось запустить"), wxOK | wxICON_ERROR, this);
                    Stop();
                }
            }
#endif
        } else if (vpnStarting_) {
#if defined(__WXMSW__) || defined(__APPLE__)
            ++vpnTicks_;
#ifdef __APPLE__
            if (VpnAdapterReady(vpnDevice_) && VpnMacTunnelReady(vpnStatusFile_)) {
                vpnStarting_ = false; vpnConfigured_ = true;
                status_->SetLabel(L("VPN подключён — весь IPv4-трафик направлен через ByeDPI"));
                Event("macOS utun adapter and VPN routes are active");
                if (closing_) Stop(); else toggle_->Enable();
            } else if (vpnTicks_ >= 150) {
                Event("macOS VPN adapter and routes did not become ready within 15 seconds"); Stop();
            }
#else
            if (VpnAdapterReady(vpnDevice_)) {
                vpnStarting_ = false; vpnConfiguring_ = true;
                status_->SetLabel(L("Настройка VPN-адреса и маршрутов…"));
                Event("VPN adapter appeared; configuring address, DNS and routes in background");
                wxString device = vpnDevice_;
                vpnFuture_ = std::async(std::launch::async, [device] {
                    wxString log = "Cleanup before configuration: " + VpnCleanup(device) + "\n";
                    try { return log + VpnConfigure(device, "1.1.1.1"); }
                    catch (...) { VpnCleanup(device); throw; }
                });
            } else if (vpnTicks_ >= 100) { Event("VPN adapter did not appear within 10 seconds"); Stop(); }
#endif
#endif
        } else if (!ready_ && ticks_ % 3 == 0) {
            if (Listening()) {
                ready_ = true;
                Event(wxString::Format("Engine is listening on 127.0.0.1:%d after %.1f seconds", port_->GetValue(), ticks_ / 10.0));
                if (vpnActive_) {
                    try { StartVpnTunnel(); }
                    catch (const std::exception& error) { Event("VPN start failed: " + wxString::FromUTF8(error.what())); Stop(); }
                } else if (automatic_->GetValue() && (!smokeTest || systemProxySmoke)) {
                    timer_.Stop();
                    toggle_->Disable();
                    status_->SetLabel(L("Включение системного прокси…"));
                    try {
                        Event(wxString::Format("Applying system HTTP/HTTPS proxy on port %d", port_->GetValue()));
                        proxy_->Enable(port_->GetValue());
                        restore_->Enable();
                        status_->SetLabel(L("Подключено — системный прокси включён"));
                        Log(L("Системный прокси включён автоматически.\n"));
                        Event("System HTTP/HTTPS proxy verified after write");
                    } catch (const std::exception& error) {
                        Log(wxString::FromUTF8(error.what()) + "\n");
                        Event("System HTTP/HTTPS proxy apply failed: " + wxString::FromUTF8(error.what()));
                        timer_.Start(100); toggle_->Enable();
                        Stop(); return;
                    }
                    timer_.Start(100); toggle_->Enable();
                } else {
                    status_->SetLabel(L("Прокси запущен — ручной режим"));
                    Log(L("Ручной режим: SOCKS5 — ") + address_->GetLabel() + "\n");
                }
                if (smokeTest) { smokeResult = 0; closing_ = true; Stop(); }
            } else if (ticks_ >= 100) {
                Event("Engine did not open its port within 10 seconds");
                Log(L("Движок не открыл порт за 10 секунд. Остановка.\n")); Stop();
            }
        }
    }
    void FinishProcesses() {
        if (pid_ || tunPid_) return;
        timer_.Stop();
        status_->SetLabel(processFailed_ ? L("Движок завершил работу — проверьте журнал") : L("Прокси остановлен"));
        toggle_->SetLabel(L("Включить")); toggle_->Enable(); Editable(true);
        bool restored = RestoreProxy();
        if (closing_ && restored) Destroy();
    }
    void End(wxProcessEvent& event) {
        if (event.GetPid() == tunPid_) {
            Drain(tunProcess_);
            Event(wxString::Format("tun2socks exit: PID=%ld, code=%d, stopping=%d", tunPid_, event.GetExitCode(), stopping_ ? 1 : 0));
            delete tunProcess_; tunProcess_ = nullptr; tunPid_ = 0; vpnStarting_ = false; vpnConfigured_ = false;
            if (!stopping_) {
                processFailed_ = true; stopping_ = true;
                Event("Removing VPN routes after unexpected tun2socks exit: " + VpnCleanup(vpnDevice_));
                if (pid_) wxProcess::Kill(pid_, wxSIGTERM);
            }
            FinishProcesses(); return;
        }
        if (event.GetPid() != pid_) return;
        Drain(process_);
        if (stopping_) Log(wxString::Format(L("Движок остановлен приложением, код: %d\n"), event.GetExitCode()));
        else { Log(wxString::Format(L("Движок неожиданно завершён, код: %d\n"), event.GetExitCode())); processFailed_ = true; }
        Event(wxString::Format("Engine exit: PID=%ld, code=%d, stopping=%d, ready=%d, ticks=%d",
            pid_, event.GetExitCode(), stopping_ ? 1 : 0, ready_ ? 1 : 0, ticks_));
        delete process_; process_ = nullptr; pid_ = 0;
        if (tunPid_ && !stopping_) {
            stopping_ = true;
            Event("Removing VPN routes after unexpected ByeDPI exit: " + VpnCleanup(vpnDevice_));
            wxProcess::Kill(tunPid_, wxSIGTERM);
        }
#ifdef __APPLE__
        if (vpnActive_ && !stopping_) VpnStopMacTunnel(vpnStopFile_);
#endif
        FinishProcesses();
    }
public:
    void RunElevatedVpn() {
        if (networkMode_->GetCount() > 1) networkMode_->SetSelection(1); Save();
        CallAfter([this] { Start(); });
    }
    void RunUISmoke() {
        CallAfter([this] {
            bool valid = !full_ && toggle_->IsShown() && favorites_->IsShown() && !arguments_->IsShown() && !log_->IsShown();
            SetEnglish(true, false); LanguageChanged();
            valid = valid && toggle_->GetLabel() == "Turn on" && mode_->GetLabel() == "Full version" &&
                networkMode_->GetString(0) == "System proxy" &&
                ((!VpnAvailable() && networkMode_->GetCount() == 1) ||
                 (VpnAvailable() && networkMode_->GetCount() == 2 &&
                  networkMode_->GetString(1) == wxString::FromUTF8("VPN — all applications")));
            full_ = true; Presentation();
            valid = valid && arguments_->IsShown() && log_->IsShown();
            fprintf(stderr, "Main full content: %d x %d; client: %d x %d\n", root_->GetMinSize().x, root_->GetMinSize().y, GetClientSize().x, GetClientSize().y);
            SetEnglish(false, false); LanguageChanged(); full_ = false; Presentation();
            valid = valid && toggle_->GetLabel() == wxString::FromUTF8("Включить") && !arguments_->IsShown();
            auto area = GetClientRect();
            valid = valid && area.Contains(test_->GetRect());
            smokeResult = valid ? 0 : 1;
            fprintf(stderr, "Main UI smoke: %s\n", valid ? "PASS" : "FAIL");
            Destroy();
        });
    }
    void RunTesterSmoke(const wxString& localBaseURL, bool applyEarly = false) {
        CallAfter([this, localBaseURL, applyEarly] { smokeResult = RunPolicyUISmoke(this, localBaseURL, applyEarly); Destroy(); });
    }
    void RunSmoke() {
        closing_ = true;
        automatic_->SetValue(systemProxySmoke); // Regular smoke tests never change the network.
        port_->SetValue(19581);
        arguments_->SetValue("--split 1");
        CallAfter([this] {
            Start();
            if (!pid_) Destroy();
        });
    }
    MainFrame() : wxFrame(nullptr, wxID_ANY, "HelloAndByeDPI " BYEDPI_APP_VERSION, wxDefaultPosition, wxSize(700, 650)), timer_(this) {
        SetMinSize(wxSize(560, 580));
#ifdef __WXMSW__
        SetIcon(wxIcon("IDI_APP_ICON", wxBITMAP_TYPE_ICO_RESOURCE));
#endif
        if (!smokeTest || systemProxySmoke) {
            proxyBackend_ = MakeSystemProxy();
            proxyJournal_ = MakeProxyJournal(wxStandardPaths::Get().GetUserDataDir() + "/proxy-recovery.ini");
            proxy_.reset(new ProxyTransaction(*proxyBackend_, *proxyJournal_));
        }
        auto panel = new wxScrolledWindow(this); panel->SetScrollRate(0, 10);
        auto root = new wxBoxSizer(wxVERTICAL); root_ = root;
        auto header = new wxBoxSizer(wxHORIZONTAL);
        header->AddStretchSpacer();
        language_ = new wxChoice(panel, wxID_ANY); language_->Append(L("Русский")); language_->Append("English");
        language_->SetSelection(English() ? 1 : 0); header->Add(language_, 0, wxRIGHT, 8);
        mode_ = new wxButton(panel, wxID_ANY, L("Полная версия")); header->Add(mode_);
        root->Add(header, 0, wxEXPAND | wxALL, 18);
        auto title = new wxStaticText(panel, wxID_ANY, "HelloAndByeDPI " BYEDPI_APP_VERSION);
        title->SetFont(title->GetFont().Larger().Larger().Bold());
        root->Add(title, 0, wxLEFT | wxRIGHT | wxBOTTOM, 18);
        toggle_ = new wxButton(panel, wxID_ANY, L("Включить"), wxDefaultPosition, wxSize(-1, 76));
        toggle_->SetFont(toggle_->GetFont().Larger().Larger().Bold());
        root->Add(toggle_, 0, wxEXPAND | wxLEFT | wxRIGHT | wxBOTTOM, 18);
        currentPolicy_ = new wxStaticText(panel, wxID_ANY, L("Текущая стратегия"));
        root->Add(currentPolicy_, 0, wxLEFT | wxRIGHT | wxBOTTOM, 18);
        favorites_ = new wxChoice(panel, wxID_ANY);
        root->Add(favorites_, 0, wxEXPAND | wxLEFT | wxRIGHT | wxBOTTOM, 18);
        auto networkRow = new wxBoxSizer(wxHORIZONTAL);
        networkRow->Add(new wxStaticText(panel, wxID_ANY, L("Режим подключения")), 0, wxALIGN_CENTER_VERTICAL | wxRIGHT, 8);
        networkMode_ = new wxChoice(panel, wxID_ANY);
        networkMode_->Append(L("Системный прокси"));
        if (VpnAvailable()) networkMode_->Append(L("VPN — все приложения"));
        networkMode_->SetSelection(VpnAvailable() && config_.ReadBool("vpn_mode", false) ? 1 : 0);
        networkRow->Add(networkMode_, 1);
        root->Add(networkRow, 0, wxEXPAND | wxLEFT | wxRIGHT | wxBOTTOM, 18);
        catalogLabel_ = new wxStaticText(panel, wxID_ANY, L("Все стратегии и параметры"));
        root->Add(catalogLabel_, 0, wxLEFT | wxRIGHT | wxBOTTOM, 8);
        catalog_ = new wxChoice(panel, wxID_ANY, wxDefaultPosition, wxSize(200, -1));
        catalog_->SetMaxSize(wxSize(680, -1));
        root->Add(catalog_, 0, wxEXPAND | wxLEFT | wxRIGHT | wxBOTTOM, 10);
        customButton_ = new wxButton(panel, wxID_ANY, L("Ввести свою стратегию…"));
        root->Add(customButton_, 0, wxEXPAND | wxLEFT | wxRIGHT | wxBOTTOM, 18);
        status_ = new wxStaticText(panel, wxID_ANY, L("Прокси остановлен"));
        root->Add(status_, 0, wxLEFT | wxRIGHT | wxBOTTOM, 18);
        auto row = new wxBoxSizer(wxHORIZONTAL);
        address_ = new wxStaticText(panel, wxID_ANY, "");
        row->Add(address_, 1, wxALIGN_CENTER_VERTICAL);
        auto copy = new wxButton(panel, wxID_ANY, L("Копировать адрес"));
        row->Add(copy);
        root->Add(row, 0, wxEXPAND | wxLEFT | wxRIGHT | wxBOTTOM, 18); advanced_.push_back(root->GetItem(root->GetItemCount() - 1));
        auto settings = new wxBoxSizer(wxHORIZONTAL);
        settings->Add(new wxStaticText(panel, wxID_ANY, L("Порт:")), 0, wxALIGN_CENTER_VERTICAL | wxRIGHT, 8);
        port_ = new wxSpinCtrl(panel, wxID_ANY, "", wxDefaultPosition, wxSize(100, -1), wxSP_ARROW_KEYS, 1024, 65535, 1080);
        long savedPort = 1080; config_.Read("port", &savedPort, 1080);
        port_->SetValue(savedPort >= 1024 && savedPort <= 65535 ? static_cast<int>(savedPort) : 1080);
        settings->Add(port_, 0, wxRIGHT, 16);
        profile_ = new wxChoice(panel, wxID_ANY);
        profile_->Append(L("Свои параметры")); profile_->Append(L("Разделение TCP"));
        profile_->Append(L("Разделение TLS")); profile_->Append(L("Без обхода (диагностика)"));
        profile_->SetSelection(0); settings->Add(profile_, 1);
        root->Add(settings, 0, wxEXPAND | wxLEFT | wxRIGHT | wxBOTTOM, 18); advanced_.push_back(root->GetItem(root->GetItemCount() - 1));
        automatic_ = new wxCheckBox(panel, wxID_ANY, L("Автоматически настраивать системный прокси"));
        bool automatic = true;
        config_.Read("automatic_proxy", &automatic, true);
        automatic_->SetValue(automatic);
        root->Add(automatic_, 0, wxLEFT | wxRIGHT | wxBOTTOM, 18); advanced_.push_back(root->GetItem(root->GetItemCount() - 1));
        root->Add(new wxStaticText(panel, wxID_ANY, L("Параметры ByeDPI (можно вставить с Android):")), 0, wxLEFT | wxRIGHT | wxBOTTOM, 18); advanced_.push_back(root->GetItem(root->GetItemCount() - 1));
        wxString savedArgs; config_.Read("arguments", &savedArgs, "--split 1+s");
        arguments_ = new wxTextCtrl(panel, wxID_ANY, savedArgs, wxDefaultPosition, wxSize(-1, 80), wxTE_MULTILINE);
        root->Add(arguments_, 0, wxEXPAND | wxLEFT | wxRIGHT | wxBOTTOM, 18); advanced_.push_back(root->GetItem(root->GetItemCount() - 1));
        auto buttons = new wxBoxSizer(wxHORIZONTAL);
        favoriteButton_ = new wxButton(panel, wxID_ANY, L("В избранное"));
        import_ = new wxButton(panel, wxID_ANY, L("Импорт параметров…"));
        buttons->Add(favoriteButton_, 1, wxRIGHT, 8); buttons->Add(import_);
        restore_ = new wxButton(panel, wxID_ANY, L("Восстановить сеть"));
        restore_->Enable(proxy_ && proxy_->Pending());

        root->Add(buttons, 0, wxEXPAND | wxLEFT | wxRIGHT | wxBOTTOM, 18); advanced_.push_back(root->GetItem(root->GetItemCount() - 1));
        test_ = new wxButton(panel, wxID_ANY, L("Тест стратегий"));
        root->Add(test_, 0, wxEXPAND | wxLEFT | wxRIGHT | wxBOTTOM, 18);
        root->Add(restore_, 0, wxEXPAND | wxLEFT | wxRIGHT | wxBOTTOM, 18);
        auto hint = new wxStaticText(panel, wxID_ANY,
            L("Нажмите «Включить» — браузеры с системными настройками используют прокси.\nПри отключении прежние настройки сети восстанавливаются.\nПриложения со своими настройками прокси могут игнорировать системные."));
        root->Add(hint, 0, wxLEFT | wxRIGHT | wxBOTTOM, 18); advanced_.push_back(root->GetItem(root->GetItemCount() - 1));
        log_ = new wxTextCtrl(panel, wxID_ANY, "", wxDefaultPosition, wxDefaultSize, wxTE_MULTILINE | wxTE_READONLY);
        root->Add(log_, 1, wxEXPAND | wxLEFT | wxRIGHT | wxBOTTOM, 18); advanced_.push_back(root->GetItem(root->GetItemCount() - 1));
        InitializeLog();
        panel->SetSizer(root);
        auto frameSizer = new wxBoxSizer(wxVERTICAL); frameSizer->Add(panel, 1, wxEXPAND); SetSizer(frameSizer);
        RefreshCatalog(); RefreshFavorites(); Presentation();
        mode_->Bind(wxEVT_BUTTON, [this](wxCommandEvent&) { full_ = !full_; RefreshFavorites(); Presentation(); });
        language_->Bind(wxEVT_CHOICE, [this](wxCommandEvent&) { SetEnglish(language_->GetSelection() == 1, !smokeTest); LanguageChanged(); });
        favorites_->Bind(wxEVT_CHOICE, [this](wxCommandEvent&) {
            arguments_->SetValue(favoriteArgs_[favorites_->GetSelection()]); profile_->SetSelection(0); Save(); RefreshFavorites();
        });
        catalog_->Bind(wxEVT_CHOICE, [this](wxCommandEvent&) {
            int selected = catalog_->GetSelection();
            if (selected >= 0 && static_cast<size_t>(selected) < catalogArgs_.size()) {
                arguments_->SetValue(catalogArgs_[selected]); profile_->SetSelection(0); Save(); RefreshFavorites();
            }
        });
        customButton_->Bind(wxEVT_BUTTON, [this](wxCommandEvent&) {
            wxTextEntryDialog dialog(this, L("Введите параметры стратегии"), L("Своя стратегия"), arguments_->GetValue(), wxOK | wxCANCEL | wxTE_MULTILINE);
            if (dialog.ShowModal() == wxID_OK) {
                wxString value = dialog.GetValue(); value.Trim().Trim(false);
                if (!value.empty()) { arguments_->SetValue(value); profile_->SetSelection(0); AddFavorite(); Save(); RefreshCatalog(); }
            }
        });
        favoriteButton_->Bind(wxEVT_BUTTON, [this](wxCommandEvent&) { AddFavorite(); });
        auto updateAddress = [this] { address_->SetLabel(wxString::Format("socks5://127.0.0.1:%d", port_->GetValue())); };
        updateAddress();
        port_->Bind(wxEVT_SPINCTRL, [updateAddress](wxSpinEvent&) { updateAddress(); });
        port_->Bind(wxEVT_TEXT, [updateAddress](wxCommandEvent&) { updateAddress(); });
        copy->Bind(wxEVT_BUTTON, [this](wxCommandEvent&) {
            if (wxTheClipboard->Open()) { wxTheClipboard->SetData(new wxTextDataObject(address_->GetLabel())); wxTheClipboard->Close(); }
        });
        profile_->Bind(wxEVT_CHOICE, [this](wxCommandEvent&) {
            switch (profile_->GetSelection()) {
                case 1: arguments_->SetValue("--split 1+s"); break;
                case 2: arguments_->SetValue("--tlsrec 1+s"); break;
                case 3: arguments_->Clear(); break;
            }
        });
        import_->Bind(wxEVT_BUTTON, [this](wxCommandEvent&) {
            wxFileDialog dialog(this, L("Текстовый файл с параметрами"), "", "", "Text files (*.txt)|*.txt|All files|*", wxFD_OPEN | wxFD_FILE_MUST_EXIST);
            if (dialog.ShowModal() != wxID_OK) return;
            wxFileName file(dialog.GetPath());
            if (file.GetSize() > 65536) { wxMessageBox(L("Файл должен быть меньше 64 КБ.")); return; }
            wxString text;
            wxFileInputStream input(dialog.GetPath());
            wxStringOutputStream output(&text, wxConvUTF8); input.Read(output);
            arguments_->SetValue(text); profile_->SetSelection(0);
        });
        toggle_->Bind(wxEVT_BUTTON, [this](wxCommandEvent&) { if (pid_) Stop(); else Start(); });
        test_->Bind(wxEVT_BUTTON, [this](wxCommandEvent&) {
            if (!RestoreProxy()) return;
            auto choice = ShowPolicyTests(this); LanguageChanged();
            if (choice.selected) {
                arguments_->SetValue(choice.arguments); profile_->SetSelection(0); AddFavorite(); Save();
                Log(L("Выбранная политика сохранена. Нажмите «Включить».\n"));
            }
        });
        restore_->Bind(wxEVT_BUTTON, [this](wxCommandEvent&) {
            if (RestoreProxy()) {
                if (pid_) Stop();
                else status_->SetLabel(L("Настройки сети восстановлены"));
            }
        });
        Bind(wxEVT_TIMER, &MainFrame::Tick, this);
        Bind(wxEVT_END_PROCESS, &MainFrame::End, this);
        Bind(wxEVT_CLOSE_WINDOW, [this](wxCloseEvent& event) {
            Save();
            if (vpnConfiguring_ && event.CanVeto()) {
                event.Veto(); closing_ = true;
                status_->SetLabel(L("Завершение настройки VPN перед закрытием…"));
                return;
            }
            if ((pid_ || tunPid_) && event.CanVeto()) { event.Veto(); closing_ = true; Stop(); }
            else {
                if (!RestoreProxy() && event.CanVeto()) { event.Veto(); return; }
                if (vpnActive_) Event("Removing VPN routes during close: " + VpnCleanup(vpnDevice_));
                if (tunPid_) { wxProcess::Kill(tunPid_, wxSIGKILL); tunProcess_->Detach(); tunProcess_ = nullptr; }
                if (pid_) { wxProcess::Kill(pid_, wxSIGKILL); process_->Detach(); process_ = nullptr; }
                Destroy();
            }
        });
        LanguageChanged();
        Centre();
        if (proxy_ && proxy_->Pending()) CallAfter([this] { RestoreProxy(); });
    }
};
class App : public wxApp {
    std::unique_ptr<wxSingleInstanceChecker> instance_;
public:
    bool OnInit() override {
        systemProxySmoke = argc > 1 && wxString(argv[1]) == "--system-proxy-smoke-test";
        startVpnElevated = argc > 1 && wxString(argv[1]) == "--start-vpn";
        bool uiSmoke = argc > 1 && wxString(argv[1]) == "--ui-smoke-test";
        bool earlySmoke = argc == 3 && wxString(argv[1]) == "--policy-ui-apply-smoke-test";
        bool testerSmoke = earlySmoke || (argc == 3 && wxString(argv[1]) == "--policy-ui-smoke-test");
        smokeTest = uiSmoke || systemProxySmoke || testerSmoke || (argc > 1 && wxString(argv[1]) == "--smoke-test");
        LoadLanguage();
        SetAppDisplayName("HelloAndByeDPI");
        // Retain the storage identity so an earlier recovery journal remains discoverable.
        SetAppName(smokeTest && !systemProxySmoke ? "ByeDPI Desktop Test" : "ByeDPI Desktop");
        if (!startVpnElevated) {
            instance_.reset(new wxSingleInstanceChecker(GetAppName() + "-" + wxGetUserId()));
            if (instance_->IsAnotherRunning()) {
                wxMessageBox(L("ByeDPI уже запущен. Используйте открытое окно приложения."));
                return false;
            }
        }
        auto frame = new MainFrame(); frame->Show();
        if (startVpnElevated) frame->RunElevatedVpn();
        else if (uiSmoke) frame->RunUISmoke();
        else if (testerSmoke) frame->RunTesterSmoke(wxString(argv[2]), earlySmoke);
        else if (smokeTest) frame->RunSmoke();
        return true;
    }
    int OnRun() override {
        int result = wxApp::OnRun();
        return smokeTest ? smokeResult : result;
    }
};
wxIMPLEMENT_APP(App);
