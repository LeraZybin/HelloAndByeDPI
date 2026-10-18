#include "system_proxy.h"
#include <wx/file.h>
#include <wx/fileconf.h>
#include <wx/filename.h>
#include <wx/sstream.h>

class FileProxyJournal : public ProxyJournal {
    wxString filename_;
public:
    explicit FileProxyJournal(const wxString& filename) : filename_(filename) {}
    bool Exists() override { return wxFileExists(filename_); }
    ProxySnapshot Load() override {
        wxFileConfig file("", "", filename_, "", wxCONFIG_USE_LOCAL_FILE);
        wxString before, after;
        if (!file.Read("before", &before) || !file.Read("after", &after) || before.empty() || after.empty())
            throw std::runtime_error("Повреждена резервная копия сетевых настроек. Файл сохранён для восстановления.");
        return {before.ToStdString(wxConvUTF8), after.ToStdString(wxConvUTF8)};
    }
    void Save(const ProxySnapshot& state) override {
        wxFileName path(filename_);
        if (!path.DirExists() && !path.Mkdir(0700, wxPATH_MKDIR_FULL))
            throw std::runtime_error("Не удалось создать папку резервной копии настроек.");
        // Serialize into memory, then atomically replace the recovery file.
        wxStringInputStream empty("");
        wxFileConfig data(empty);
        data.Write("before", wxString::FromUTF8(state.before.c_str()));
        data.Write("after", wxString::FromUTF8(state.after.c_str()));
        wxString text;
        wxStringOutputStream output(&text, wxConvUTF8);
        if (!data.Save(output)) throw std::runtime_error("Не удалось сохранить резервную копию настроек.");
        wxTempFile file(filename_);
        if (!file.IsOpened() || !file.Write(text, wxConvUTF8) || !file.Flush() || !file.Commit())
            throw std::runtime_error("Не удалось записать резервную копию. Сеть не изменена.");
        wxChmod(filename_, 0600);
    }
    void Clear() override {
        if (Exists() && !wxRemoveFile(filename_))
            throw std::runtime_error("Сеть восстановлена, но не удалось удалить резервную копию.");
    }
};
std::unique_ptr<ProxyJournal> MakeProxyJournal(const wxString& filename) {
    return std::unique_ptr<ProxyJournal>(new FileProxyJournal(filename));
}
