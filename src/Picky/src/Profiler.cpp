#include "Profiler.h"
#include "Runtime.h"
#include "Decoder.h"
#include "Logging.h"
#include "Translation.h"

#include <windows.h>
#include <string>
#include <iostream>
#include <fstream>
#include <vector>
#include <stack>
#include <thread>
#include <intrin.h>

namespace Picky {

class FPUSaveRestore
{
    alignas(512) uint8_t _buf[512];

public:
    FPUSaveRestore()
    {
        _fxsave(_buf);
    }
    ~FPUSaveRestore()
    {
        _fxrstor(_buf);
    }
};

struct Function_t
{
    uint32_t rva;
    uint32_t id;
    uint32_t calls;
    uint32_t exits;
    uint64_t totalTime;
};

struct FunctionEntry_t
{
    uint64_t entryTime;
    uintptr_t retAddress;
    explicit FunctionEntry_t(uint64_t t, uintptr_t ret)
        : entryTime(t)
        , retAddress(ret)
    {
    }
};

static Runtime _jitRT;
static std::vector<Function_t> _functions;
static std::vector<std::string> _functionNames;
static std::string _reportFilePath;
static uint64_t _nextReport = 0;
static HANDLE _hThread = nullptr;

static thread_local std::stack<FunctionEntry_t> _returnAddress;

static auto _startTime = std::chrono::high_resolution_clock::now();

static uint64_t GetMicroTime()
{
    auto elapsed = std::chrono::high_resolution_clock::now() - _startTime;
    return std::chrono::duration_cast<std::chrono::microseconds>(elapsed)
        .count();
}

static constexpr uint64_t SecsToMicro(uint64_t secs)
{
    return secs * 1000000;
}

static void WriteReport()
{
    auto now = GetMicroTime();
    if (_nextReport > now)
        return;

    _nextReport = now + SecsToMicro(10);

    FILE* fp = nullptr;
    fopen_s(&fp, _reportFilePath.c_str(), "wt");

    if (fp == nullptr)
        return;

    for (auto& func : _functions)
    {
        double averageTime = 0.0;
        if (func.calls > 0)
            averageTime = ((double)func.totalTime / func.calls) / 1000000.0;

        double upTime = (double)GetMicroTime() / 1000000.0;
        double totalTime = (double)func.totalTime / 1000000.0;
        double percentage = (totalTime / upTime) * 100.0;

        fprintf(
            fp, "Function: %08X (%s)\n", func.rva,
            _functionNames[func.id].c_str());
        fprintf(fp, "  Calls: %u\n", func.calls);
        fprintf(fp, "  Exits: %u\n", func.exits);
        fprintf(fp, "  Average Time: %.08f secs\n", averageTime);
        fprintf(
            fp, "  Total Time: %.08f secs / %0.08f secs (%.08f%%)\n", totalTime,
            upTime, percentage);
    }

    fclose(fp);
}

static DWORD __stdcall UpdateTimeThread(LPVOID)
{
    for (;;)
    {
        WriteReport();
        std::this_thread::sleep_for(std::chrono::seconds(1));
    }
    return 0;
}

extern "C" static void __stdcall FunctionEnter(uint32_t id, uintptr_t retAddr)
{
    FPUSaveRestore fpuSaveRestore;

    auto& func = _functions[id];
    func.calls++;

    if constexpr (false)
    {
        Logging::Msg(
            "Function Enter: %08X (%s)", func.rva, _functionNames[id].c_str());
    }

    _returnAddress.emplace(GetMicroTime(), retAddr);
}

extern "C" static uintptr_t __stdcall FunctionExit(uint32_t id)
{
    FPUSaveRestore fpuSaveRestore;

    auto& func = _functions[id];
    func.exits++;

    if constexpr (false)
    {
        Logging::Msg(
            "Function Exit: %08X (%s)", func.rva, _functionNames[id].c_str());
    }

    auto& retInfo = _returnAddress.top();
    uintptr_t retAddr = retInfo.retAddress;

    uint64_t totalElapsed = GetMicroTime() - retInfo.entryTime;
    func.totalTime += totalElapsed;

    _returnAddress.pop();
    return retAddr;
}

class AsmJitErrorHandler : public asmjit::ErrorHandler
{
public:
    AsmJitErrorHandler()
        : err(asmjit::kErrorOk)
    {
    }

    void handleError(
        asmjit::Error err,
        const char* message,
        asmjit::BaseEmitter* origin) override
    {
        this->err = err;
        Logging::Msg("asmjit error: %s", message);
    }

    asmjit::Error err;
};

static AsmJitErrorHandler _asmjitErrorHandler;

static bool SetupFunction(const uintptr_t imageBase, const Function_t& func)
{
    // 1. Decode required length.
#ifdef _M_I386
    uintptr_t minRequiredSize = 5;
#else
    uintptr_t minRequiredSize = 10;
#endif

    uintptr_t funcVA = imageBase + func.rva;

    auto fullfillsMinimumSize =
        [funcVA, minRequiredSize](const ZydisDecodedInstruction& ins) -> bool {

#ifdef _M_IX86
        // 0xE9 ?? ?? ?? ?? | jmp rel32
        return (ins.instrAddress + ins.length) - funcVA >= 5;
#else
        return ins.instrAddress + ins.length >= 10;
#endif
    };

    auto decoded = DecodeUntil(funcVA, fullfillsMinimumSize);
    if (decoded.empty() || !fullfillsMinimumSize(decoded.back()))
    {
        Logging::Msg(
            "Function %08X has not enough space to be profiled.", func.rva);
        return false;
    }

    uint64_t requiredSize = (decoded.back().instrAddress
                             + decoded.back().length)
                            - funcVA;
    Logging::Msg("Required size: %u", requiredSize);

    // 2. Generate function enter/exit.
    asmjit::CodeHolder code;

    code.init(_jitRT.codeInfo());
    code.setErrorHandler(&_asmjitErrorHandler);

    {
        using namespace asmjit;
        using namespace asmjit::x86;

        Assembler assembler(&code);

        Label labelExit = assembler.newLabel();

        // Enter
        {
            uint64_t functionEnterVA = reinterpret_cast<uint64_t>(
                FunctionEnter);

            // Save registers.
            assembler.pushad(); // 8 * 4.

            // Parameters.
            assembler.push(dword_ptr(esp, (8 * 4)));
            assembler.push(func.id);

            // Call function enter.
            assembler.call(functionEnterVA);

            // Swap return location.
            assembler.lea(eax, dword_ptr(labelExit));
            assembler.mov(dword_ptr(esp, (8 * 4)), eax);

            // Restore registers.
            assembler.popad();
        }

        // Instruction replacement block
        {
            for (auto& ins : decoded)
            {
                if (!Translation::convertInstruction(ins, assembler))
                {
                    Logging::Msg(
                        "Failed to translate instruction: %p.",
                        imageBase + func.rva);
                    return false;
                }
            }

            // Jump back.
            uint64_t returnVA = decoded.back().instrAddress
                                + decoded.back().length;
            assembler.jmp(returnVA);
        }

        // Exit
        {
            uintptr_t functionExitVA = reinterpret_cast<uintptr_t>(
                FunctionExit);

            assembler.bind(labelExit);
            assembler.push(eax);
            assembler.pushad();
            assembler.push(func.id);
            assembler.call(functionExitVA);
            assembler.mov(dword_ptr(esp, (8 * 4)), eax);
            assembler.popad();
            assembler.ret();
        }

        // Patch function.
        {
            void* targetCode = nullptr;
            auto status = _jitRT.add(&targetCode, &code, funcVA);
            if (status != asmjit::kErrorOk)
            {
                Logging::Msg("Failed to generate code.");
                return false;
            }

            intptr_t sourceVA = funcVA + 5;
            intptr_t targetVA = reinterpret_cast<intptr_t>(targetCode);
            int64_t rel64 = targetVA - sourceVA;
            if (rel64 >= std::numeric_limits<int32_t>::max()
                || rel64 < std::numeric_limits<int32_t>::min())
            {
                Logging::Msg("Error, jump distance is greater than 31 bit.");
                return false;
            }
            int32_t disp32 = static_cast<int32_t>(rel64);

            uint8_t buf[5];
            buf[0] = '\xE9';
            std::memcpy(buf + 1, &disp32, sizeof(disp32));

            void* targetBuffer = reinterpret_cast<void*>(funcVA);
            DWORD oldProt, oldProt2;
            VirtualProtect(targetBuffer, 32, PAGE_EXECUTE_READWRITE, &oldProt);
            std::memcpy(targetBuffer, buf, sizeof(buf));
            VirtualProtect(targetBuffer, 32, oldProt, &oldProt2);
        }
    }

    return true;
}

static bool SetupFunctions(const uintptr_t imageBase)
{
    for (auto& func : _functions)
    {
        if (!SetupFunction(imageBase, func))
        {
            Logging::Msg(
                "Failed to setup function %08X (%s)", func.rva,
                _functionNames[func.id].c_str());

            return false;
        }
        else
        {
            Logging::Msg(
                "Initialized profiler for function %08X (%s)", func.rva,
                _functionNames[func.id].c_str());
        }
    }
    return true;
}

bool Profiler::Startup(const char* currentPath)
{
    uintptr_t imageBase = reinterpret_cast<uintptr_t>(
        GetModuleHandleA(nullptr));

    CreateThread(nullptr, 0, UpdateTimeThread, nullptr, 0, nullptr);

    std::string functionsFile = currentPath;
    functionsFile += "\\Functions.txt";

    _reportFilePath = currentPath;
    _reportFilePath += "\\ProfilerReport.txt";

    Logging::Msg("Report File: %s", _reportFilePath.c_str());

    std::ifstream inFile(functionsFile);
    if (!inFile.is_open())
    {
        Logging::Msg("Unable to read Functions.txt.");
        return false;
    }

    auto parseRVA = [](const std::string& str) -> uint32_t {
        if (str.size() >= 2 && str[0] == '0'
            && (str[1] == 'x' || str[1] == 'X'))
        {
            // Hex
            return strtoul(str.c_str(), nullptr, 16);
        }
        return atol(str.c_str());
    };

    std::string line;
    while (std::getline(inFile, line))
    {
        std::string name;

        Function_t func{};
        func.id = static_cast<uint32_t>(_functions.size());

        size_t n = line.find(' ');
        if (n != line.npos)
        {
            func.rva = parseRVA(line.substr(0, n));
            name = line.substr(n + 1);
        }
        else if (!line.empty())
        {
            func.rva = parseRVA(line);

            char temp[64]{};
            sprintf_s(
                temp, "sub_%p", reinterpret_cast<void*>(func.rva + imageBase));
        }
        if (func.rva != 0)
        {
            _functions.push_back(func);
            _functionNames.push_back(std::move(name));
        }
    }

    if (!SetupFunctions(imageBase))
    {
        Logging::Msg("Failed to setup functions for profiling, terminating...");
        return false;
    }

    return true;
}

} // namespace Picky
