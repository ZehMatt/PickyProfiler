#include "Logging.h"
#include "Profiler.h"

#include <windows.h>

using namespace Picky;

static void Startup(HMODULE hMod)
{
    Logging::Initialize("Picky.log");

    Logging::Msg("Process Id: %u", GetCurrentProcessId());
    Logging::Msg("Image Base: %p", (void*)GetModuleHandleA(nullptr));

    char currentPath[1024]{};
    GetModuleFileNameA(hMod, currentPath, sizeof(currentPath));

    char* p = strrchr(currentPath, '\\');
    if (p != '\0')
        *p = '\0';

    if (!Profiler::Startup(currentPath))
    {
        ExitProcess(EXIT_FAILURE);
    }

    if constexpr (false)
    {
        while (!IsDebuggerPresent())
        {
            Sleep(1000);
        }
    }

    Logging::Msg("Environment setup");
}

static void Shutdown()
{
    Logging::Msg("Shutdown");
    Logging::Flush();
}

BOOL APIENTRY
    DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved)
{
    using namespace Picky;

    switch (ul_reason_for_call)
    {
        case DLL_PROCESS_ATTACH:
            Startup(hModule);
            break;
        case DLL_THREAD_ATTACH:
            break;
        case DLL_THREAD_DETACH:
            break;
        case DLL_PROCESS_DETACH:
            Shutdown();
            break;
    }
    return TRUE;
}
