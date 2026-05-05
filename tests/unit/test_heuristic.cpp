/*
 * NullBot — Open Source Anti-Botnet | GPL-3.0
 * File: tests/unit/test_heuristic.cpp
 */

#include "tests/test_runner.h"
#include "core/heuristic/pe_analyzer.h"

#include <windows.h>
#include <cstring>

namespace {

std::wstring MakeTempFile() {
    wchar_t dir[MAX_PATH], path[MAX_PATH];
    GetTempPathW(MAX_PATH, dir);
    GetTempFileNameW(dir, L"nbt", 0, path);
    return path;
}

} // namespace

// ─── Tests ────────────────────────────────────────────────────────────────────

TEST_CASE(IsExecutable_ReturnsFalse_ForTextFile) {
    std::wstring path = MakeTempFile();

    HANDLE hFile = CreateFileW(path.c_str(), GENERIC_WRITE, 0, nullptr,
                               CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    const char text[] = "This is not an executable file.";
    DWORD written;
    WriteFile(hFile, text, static_cast<DWORD>(strlen(text)), &written, nullptr);
    CloseHandle(hFile);

    nullbot::heuristic::PEAnalyzer analyzer(path);
    auto info = analyzer.Analyze();

    REQUIRE(!info.is_pe);
    DeleteFileW(path.c_str());
}

TEST_CASE(IsExecutable_ReturnsTrue_ForNotepad) {
    nullbot::heuristic::PEAnalyzer analyzer(L"C:\\Windows\\System32\\notepad.exe");
    auto info = analyzer.Analyze();

    REQUIRE(info.is_pe);
    REQUIRE(analyzer.IsExecutable());
}

TEST_CASE(GetSuspiciousImports_ReturnsNoInjectionAPIs_ForNotepad) {
    nullbot::heuristic::PEAnalyzer analyzer(L"C:\\Windows\\System32\\notepad.exe");
    auto imports = analyzer.GetSuspiciousImports();

    bool has_injection = false;
    for (const auto& imp : imports) {
        if (imp.function_name == "VirtualAllocEx"      ||
            imp.function_name == "WriteProcessMemory"  ||
            imp.function_name == "NtUnmapViewOfSection"||
            imp.function_name == "ZwUnmapViewOfSection") {
            has_injection = true;
            break;
        }
    }
    REQUIRE(!has_injection);
}

TEST_CASE(HasProcessHollowingPattern_ReturnsFalse_ForNotepad) {
    // Notepad does not import the VirtualAllocEx+WriteProcessMemory+NtUnmapViewOfSection triad
    nullbot::heuristic::PEAnalyzer analyzer(L"C:\\Windows\\System32\\notepad.exe");
    REQUIRE(!analyzer.HasProcessHollowingPattern());
}
