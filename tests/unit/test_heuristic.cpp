/*
 * NullBot — Open Source Anti-Botnet | GPL-3.0
 * File: tests/unit/test_heuristic.cpp
 */

#include "tests/test_runner.h"
#include "core/heuristic/pe_analyzer.h"
#include "core/scanner/scanner.h"

#include <windows.h>
#include <cstring>
#include <string>
#include <vector>

namespace {

std::wstring MakeTempFile() {
    wchar_t dir[MAX_PATH], path[MAX_PATH];
    GetTempPathW(MAX_PATH, dir);
    GetTempFileNameW(dir, L"nbt", 0, path);
    return path;
}

// Writes a minimal valid 64-bit PE to a temp file with the given section names.
// Sections have no raw data — usable for name-based tests (IsPackerSignature, GetSuspiciousSections).
std::wstring CreateMinimalPEWithSections(const std::vector<std::string>& section_names) {
    const DWORD   nt_off     = 64;
    const WORD    opt_size   = sizeof(IMAGE_OPTIONAL_HEADER64);
    const WORD    num_secs   = static_cast<WORD>(section_names.size());
    const DWORD   file_size  = 0x1000; // 4 KB is more than enough for headers

    std::vector<BYTE> file(file_size, 0);

    auto* dos         = reinterpret_cast<IMAGE_DOS_HEADER*>(file.data());
    dos->e_magic      = IMAGE_DOS_SIGNATURE;
    dos->e_lfanew     = static_cast<LONG>(nt_off);

    auto* nt          = reinterpret_cast<IMAGE_NT_HEADERS64*>(file.data() + nt_off);
    nt->Signature     = IMAGE_NT_SIGNATURE;
    nt->FileHeader.Machine              = IMAGE_FILE_MACHINE_AMD64;
    nt->FileHeader.NumberOfSections     = num_secs;
    nt->FileHeader.SizeOfOptionalHeader = opt_size;
    nt->OptionalHeader.Magic            = IMAGE_NT_OPTIONAL_HDR64_MAGIC;
    nt->OptionalHeader.SizeOfHeaders    = 0x400;
    nt->OptionalHeader.SizeOfImage      = static_cast<DWORD>(num_secs + 1) * 0x1000;

    auto* secs = reinterpret_cast<IMAGE_SECTION_HEADER*>(
        file.data() + nt_off + sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER) + opt_size);
    for (WORD i = 0; i < num_secs; ++i) {
        memset(secs[i].Name, 0, 8);
        const auto& n = section_names[i];
        memcpy(secs[i].Name, n.c_str(), (n.size() < 8) ? n.size() : 8);
        secs[i].VirtualAddress      = (i + 1) * 0x1000;
        secs[i].Misc.VirtualSize    = 0x1000;
        secs[i].SizeOfRawData       = 0;
        secs[i].PointerToRawData    = 0;
    }

    std::wstring path = MakeTempFile();
    HANDLE hFile = CreateFileW(path.c_str(), GENERIC_WRITE, 0, nullptr,
                               CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    DWORD written;
    WriteFile(hFile, file.data(), static_cast<DWORD>(file.size()), &written, nullptr);
    CloseHandle(hFile);
    return path;
}

// Writes a minimal valid 64-bit PE with a .idata section containing exactly the
// given function names imported from KERNEL32.DLL.
// Used to test threshold-based heuristics without requiring real malware.
std::wstring CreateMinimalPEWithImports(const std::vector<std::string>& fn_names) {
    const DWORD nt_off          = 64;
    const WORD  opt_size        = sizeof(IMAGE_OPTIONAL_HEADER64);
    const DWORD headers_size    = 0x200;   // 512 B — fits all PE metadata
    const DWORD sec_file_offset = 0x200;   // .idata raw data starts here
    const DWORD sec_rva         = 0x1000;
    const DWORD sec_raw_size    = 0x200;

    std::vector<BYTE> file(headers_size + sec_raw_size, 0);

    // DOS header
    auto* dos     = reinterpret_cast<IMAGE_DOS_HEADER*>(file.data());
    dos->e_magic  = IMAGE_DOS_SIGNATURE;
    dos->e_lfanew = static_cast<LONG>(nt_off);

    // NT headers
    auto* nt = reinterpret_cast<IMAGE_NT_HEADERS64*>(file.data() + nt_off);
    nt->Signature     = IMAGE_NT_SIGNATURE;
    nt->FileHeader.Machine              = IMAGE_FILE_MACHINE_AMD64;
    nt->FileHeader.NumberOfSections     = 1;
    nt->FileHeader.SizeOfOptionalHeader = opt_size;
    nt->OptionalHeader.Magic            = IMAGE_NT_OPTIONAL_HDR64_MAGIC;
    nt->OptionalHeader.SizeOfHeaders    = headers_size;
    nt->OptionalHeader.SizeOfImage      = sec_rva + sec_raw_size;
    nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress = sec_rva;
    nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size           = 0x90;

    // .idata section header
    auto* sec = reinterpret_cast<IMAGE_SECTION_HEADER*>(
        file.data() + nt_off + sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER) + opt_size);
    memcpy(sec->Name, ".idata\0\0", 8);
    sec->Misc.VirtualSize = sec_raw_size;
    sec->VirtualAddress   = sec_rva;
    sec->SizeOfRawData    = sec_raw_size;
    sec->PointerToRawData = sec_file_offset;
    sec->Characteristics  = IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_MEM_READ;

    // Build .idata layout
    BYTE* idata = file.data() + sec_file_offset;

    const DWORD num     = static_cast<DWORD>(fn_names.size());
    const DWORD int_off = 0x028;
    const DWORD iat_off = int_off + (num + 1) * 8;
    DWORD       cur     = iat_off + (num + 1) * 8;

    // DLL name
    const char dll[] = "KERNEL32.DLL";
    const DWORD dll_off = cur;
    memcpy(idata + dll_off, dll, sizeof(dll)); // includes null terminator
    cur += static_cast<DWORD>(sizeof(dll));
    if (cur & 1) cur++; // 2-byte alignment

    // Import descriptor
    auto* desc            = reinterpret_cast<IMAGE_IMPORT_DESCRIPTOR*>(idata);
    desc[0].OriginalFirstThunk = sec_rva + int_off;
    desc[0].Name          = sec_rva + dll_off;
    desc[0].FirstThunk     = sec_rva + iat_off;
    // desc[1] stays zeroed (null terminator)

    // Import-by-name entries + INT/IAT
    for (DWORD i = 0; i < num; ++i) {
        const DWORD ibn_off = cur;
        *reinterpret_cast<WORD*>(idata + ibn_off) = 0; // hint
        const auto& fn = fn_names[i];
        memcpy(idata + ibn_off + 2, fn.c_str(), fn.size() + 1);
        const DWORD ibn_rva = sec_rva + ibn_off;

        *reinterpret_cast<ULONGLONG*>(idata + int_off + i * 8) = ibn_rva;
        *reinterpret_cast<ULONGLONG*>(idata + iat_off + i * 8) = ibn_rva;

        cur += static_cast<DWORD>(2 + fn.size() + 1);
        if (cur & 1) cur++;
    }

    std::wstring path = MakeTempFile();
    HANDLE hFile = CreateFileW(path.c_str(), GENERIC_WRITE, 0, nullptr,
                               CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    DWORD written;
    WriteFile(hFile, file.data(), static_cast<DWORD>(file.size()), &written, nullptr);
    CloseHandle(hFile);
    return path;
}

} // namespace

// ─── Regression tests (weeks 1–4) ─────────────────────────────────────────────

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
        if (imp.function_name == "VirtualAllocEx"       ||
            imp.function_name == "WriteProcessMemory"   ||
            imp.function_name == "NtUnmapViewOfSection" ||
            imp.function_name == "ZwUnmapViewOfSection") {
            has_injection = true;
            break;
        }
    }
    REQUIRE(!has_injection);
}

TEST_CASE(HasProcessHollowingPattern_ReturnsFalse_ForNotepad) {
    nullbot::heuristic::PEAnalyzer analyzer(L"C:\\Windows\\System32\\notepad.exe");
    REQUIRE(!analyzer.HasProcessHollowingPattern());
}

// ─── Anti-regression tests (week 5–6) ─────────────────────────────────────────

TEST_CASE(IsPackerSignature_DetectsUPX_ForPEWithUPXSections) {
    std::wstring path = CreateMinimalPEWithSections({"UPX0", "UPX1"});
    nullbot::heuristic::PEAnalyzer analyzer(path);
    REQUIRE(analyzer.IsPackerSignature() == "UPX");
    DeleteFileW(path.c_str());
}

TEST_CASE(GetSuspiciousSections_ReturnsEmpty_ForNotepad) {
    nullbot::heuristic::PEAnalyzer analyzer(L"C:\\Windows\\System32\\notepad.exe");
    auto sections = analyzer.GetSuspiciousSections();
    REQUIRE(sections.empty());
}

TEST_CASE(HasKeyloggerPattern_ReturnsFalse_ForCalc) {
    nullbot::heuristic::PEAnalyzer analyzer(L"C:\\Windows\\System32\\calc.exe");
    REQUIRE(!analyzer.HasKeyloggerPattern());
}

TEST_CASE(ScanFile_ReturnsClean_WithFewerThanMinSuspiciousImports) {
    // PE with VirtualAllocEx + WriteProcessMemory = 2 suspicious imports.
    // MIN_SUSPICIOUS_IMPORTS = 3, so the scanner must return CLEAN.
    std::wstring path = CreateMinimalPEWithImports({"VirtualAllocEx", "WriteProcessMemory"});
    nullbot::scanner::FileScanner scanner{"Z:\\nonexistent"};
    auto result = scanner.ScanFile(path);
    REQUIRE(result.level == nullbot::scanner::ThreatLevel::CLEAN);
    DeleteFileW(path.c_str());
}
