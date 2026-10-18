#define UNICODE
#define _UNICODE
#include <windows.h>
#include <shellapi.h>

static wchar_t executable[32768];
static wchar_t directory[32768];

static const wchar_t* SkipProgramName(const wchar_t* command) {
    int quoted = 0;
    if (*command == L'"') { quoted = 1; ++command; }
    while (*command && ((quoted && *command != L'"') || (!quoted && *command != L' ' && *command != L'\t'))) ++command;
    if (quoted && *command == L'"') ++command;
    while (*command == L' ' || *command == L'\t') ++command;
    return command;
}

void WINAPI wWinMainCRTStartup(void) {
    DWORD length = GetModuleFileNameW(0, directory, 32768);
    if (!length || length >= 32767) ExitProcess(2);
    while (length && directory[length - 1] != L'\\' && directory[length - 1] != L'/') --length;
    directory[length] = 0;
    lstrcpyW(executable, directory);
    lstrcatW(executable, L"lib\\HelloAndByeDPI-core.exe");

    SHELLEXECUTEINFOW launch;
    ZeroMemory(&launch, sizeof(launch));
    launch.cbSize = sizeof(launch);
    launch.fMask = SEE_MASK_NOCLOSEPROCESS | SEE_MASK_FLAG_NO_UI;
    launch.lpFile = executable;
    launch.lpParameters = SkipProgramName(GetCommandLineW());
    launch.lpDirectory = directory;
    launch.nShow = SW_SHOWNORMAL;
    if (!ShellExecuteExW(&launch)) {
        MessageBoxW(0, L"Не найден lib\\HelloAndByeDPI-core.exe. Распакуйте архив полностью.",
            L"HelloAndByeDPI", MB_OK | MB_ICONERROR);
        ExitProcess(3);
    }
    WaitForSingleObject(launch.hProcess, INFINITE);
    DWORD code = 0;
    GetExitCodeProcess(launch.hProcess, &code);
    CloseHandle(launch.hProcess);
    ExitProcess(code);
}
