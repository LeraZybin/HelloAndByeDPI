#include "system_proxy.h"
#include <wx/init.h>
#include <wx/filename.h>
#include <iostream>
int main() {
    wxInitializer init;
    if (!init) return 1;
    wxString path = wxFileName::CreateTempFileName("byedpi-journal-test-");
    wxRemoveFile(path);
    auto journal = MakeProxyJournal(path);
    journal->Save({"before=with\\slashes\nand newlines", "after"});
    auto state = journal->Load();
    if (state.before != "before=with\\slashes\nand newlines" || state.after != "after") return 2;
    // A new instance simulates loading the journal after restarting the app.
    auto restarted = MakeProxyJournal(path);
    if (!restarted->Exists() || restarted->Load().before != state.before) return 3;
    restarted->Clear();
    if (restarted->Exists()) return 4;
    std::cout << "Atomic recovery journal roundtrip passed\n";
}
