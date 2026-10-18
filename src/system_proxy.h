#pragma once
#include "proxy_transaction.h"
#include <memory>
#include <wx/string.h>

std::unique_ptr<ProxyBackend> MakeSystemProxy();
std::unique_ptr<ProxyJournal> MakeProxyJournal(const wxString& filename);
