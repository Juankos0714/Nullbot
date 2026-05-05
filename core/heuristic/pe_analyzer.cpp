/*
 * NullBot — Open Source Anti-Botnet | GPL-3.0
 * File: core/heuristic/pe_analyzer.cpp
 */

#include "core/heuristic/pe_analyzer.h"

namespace nullbot {
namespace heuristic {

PEAnalyzer::PEAnalyzer(const std::wstring& file_path)
    : file_path_(file_path)
{}

PEAnalyzer::~PEAnalyzer() {
    Unload();
}

bool PEAnalyzer::IsExecutable() const { return loaded_; }
bool PEAnalyzer::IsValid()      const { return loaded_; }

std::vector<SuspiciousImport> PEAnalyzer::GetSuspiciousImports() {
    std::vector<SuspiciousImport> result;
    if (!loaded_ && !Load()) return result;
    ParseImports(result);
    return result;
}

bool PEAnalyzer::HasAntiDebugTechniques() {
    for (const auto& imp : GetSuspiciousImports()) {
        if (imp.reason.find("Anti-debug") != std::string::npos) return true;
    }
    return false;
}

bool PEAnalyzer::HasProcessHollowingPattern() {
    bool has_alloc = false, has_write = false, has_thread = false;
    for (const auto& imp : GetSuspiciousImports()) {
        if (imp.function_name == "VirtualAllocEx")     has_alloc  = true;
        if (imp.function_name == "WriteProcessMemory") has_write  = true;
        if (imp.function_name == "CreateRemoteThread") has_thread = true;
    }
    return has_alloc && has_write && has_thread;
}

bool PEAnalyzer::HasKeyloggerPattern() {
    for (const auto& imp : GetSuspiciousImports()) {
        if (imp.function_name == "SetWindowsHookEx") return true;
    }
    return false;
}

PEInfo PEAnalyzer::Analyze() {
    PEInfo info;
    if (!loaded_ && !Load()) return info;
    info.is_pe    = true;
    info.is_64bit = (nt_headers_->FileHeader.Machine == IMAGE_FILE_MACHINE_AMD64);
    info.is_dll   = (nt_headers_->FileHeader.Characteristics & IMAGE_FILE_DLL) != 0;
    info.section_count = section_count_;
    ParseImports(info.suspicious_imports);
    info.import_count = static_cast<DWORD>(info.suspicious_imports.size());
    return info;
}

bool PEAnalyzer::Load() {
    hFile_ = CreateFileW(file_path_.c_str(), GENERIC_READ, FILE_SHARE_READ,
                         nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (hFile_ == INVALID_HANDLE_VALUE) return false;

    hMap_ = CreateFileMappingW(hFile_, nullptr, PAGE_READONLY, 0, 0, nullptr);
    if (!hMap_) { Unload(); return false; }

    base_ = MapViewOfFile(hMap_, FILE_MAP_READ, 0, 0, 0);
    if (!base_) { Unload(); return false; }

    dos_header_ = static_cast<IMAGE_DOS_HEADER*>(base_);
    if (dos_header_->e_magic != IMAGE_DOS_SIGNATURE) { Unload(); return false; }

    nt_headers_ = reinterpret_cast<IMAGE_NT_HEADERS*>(
        static_cast<BYTE*>(base_) + dos_header_->e_lfanew);
    if (nt_headers_->Signature != IMAGE_NT_SIGNATURE) { Unload(); return false; }

    sections_      = IMAGE_FIRST_SECTION(nt_headers_);
    section_count_ = nt_headers_->FileHeader.NumberOfSections;
    loaded_        = true;
    return true;
}

void PEAnalyzer::Unload() {
    if (base_)                          { UnmapViewOfFile(base_);  base_  = nullptr; }
    if (hMap_)                          { CloseHandle(hMap_);      hMap_  = nullptr; }
    if (hFile_ != INVALID_HANDLE_VALUE) { CloseHandle(hFile_);     hFile_ = INVALID_HANDLE_VALUE; }
    loaded_ = false;
}

void PEAnalyzer::ParseImports(std::vector<SuspiciousImport>& out) {
    if (!nt_headers_) return;

    DWORD import_rva = nt_headers_->OptionalHeader
                           .DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT]
                           .VirtualAddress;
    if (import_rva == 0) return;

    auto* desc = static_cast<IMAGE_IMPORT_DESCRIPTOR*>(RvaToVa(import_rva));
    if (!desc) return;

    for (; desc->Name != 0; ++desc) {
        auto* dll_name = static_cast<const char*>(RvaToVa(desc->Name));
        if (!dll_name) continue;

        DWORD first_thunk = desc->OriginalFirstThunk
                                ? desc->OriginalFirstThunk
                                : desc->FirstThunk;
        auto* thunk = static_cast<IMAGE_THUNK_DATA*>(RvaToVa(first_thunk));
        for (; thunk && thunk->u1.AddressOfData != 0; ++thunk) {
            if (IMAGE_SNAP_BY_ORDINAL(thunk->u1.Ordinal)) continue;
            auto* ibn = static_cast<IMAGE_IMPORT_BY_NAME*>(
                RvaToVa(static_cast<DWORD>(thunk->u1.AddressOfData)));
            if (!ibn) continue;

            const std::string fn_name = reinterpret_cast<const char*>(ibn->Name);
            for (const auto& [api, reason] : SUSPICIOUS_APIS) {
                if (fn_name == api) {
                    out.push_back({dll_name, fn_name, reason});
                    break;
                }
            }
        }
    }
}

LPVOID PEAnalyzer::RvaToVa(DWORD rva) {
    if (!base_ || rva == 0) return nullptr;
    for (WORD i = 0; i < section_count_; ++i) {
        const auto& s = sections_[i];
        if (rva >= s.VirtualAddress &&
            rva <  s.VirtualAddress + s.SizeOfRawData) {
            return static_cast<BYTE*>(base_)
                   + (rva - s.VirtualAddress + s.PointerToRawData);
        }
    }
    return nullptr;
}

} // namespace heuristic
} // namespace nullbot
