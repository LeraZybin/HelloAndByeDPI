#include "system_proxy.h"
#include <wx/init.h>
#include <iostream>

int main() {
    wxInitializer init;
    if (!init) return 1;
    try {
        auto backend = MakeSystemProxy();
        ProxySnapshot snapshot = backend->Prepare(19581);
        backend->Apply(snapshot);   // Apply() rereads and verifies Windows settings.
        backend->Restore(snapshot); // Restore() rereads and verifies the rollback.
        std::cout << "Windows HTTP/HTTPS proxy apply and restore passed\n";
        return 0;
    } catch (const std::exception& error) {
        std::cerr << error.what() << '\n';
        return 2;
    }
}
