/*
 * NullBot — Open Source Anti-Botnet | GPL-3.0
 * File: core/heuristic/pe_analyzer.cpp
 */

#include "core/heuristic/pe_analyzer.h"
#include "core/heuristic/thresholds.h"

#include <cmath>
#include <cstring>

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

// ─── Import helpers ───────────────────────────────────────────────────────────

static bool HasImport(const std::vector<SuspiciousImport>& imports,
                      const std::string& fn_name) {
    for (const auto& imp : imports)
        if (imp.function_name == fn_name) return true;
    return false;
}

// ─── Section name helper ──────────────────────────────────────────────────────

static std::string SectionName(const IMAGE_SECTION_HEADER& sec) {
    char buf[9] = {};
    memcpy(buf, sec.Name, 8);
    return buf;
}

// ─── Public API ───────────────────────────────────────────────────────────────

std::vector<SuspiciousImport> PEAnalyzer::GetSuspiciousImports() {
    std::vector<SuspiciousImport> result;
    if (!loaded_ && !Load()) return result;
    ParseImports(result);
    return result;
}

std::vector<SectionEntropyResult> PEAnalyzer::GetSectionEntropies() {
    std::vector<SectionEntropyResult> result;
    if (!loaded_ && !Load()) return result;

    for (WORD i = 0; i < section_count_; ++i) {
        const auto& sec = sections_[i];
        if (sec.SizeOfRawData == 0 || sec.PointerToRawData == 0) continue;

        const BYTE* raw = static_cast<const BYTE*>(base_) + sec.PointerToRawData;

        DWORD freq[256] = {};
        for (DWORD j = 0; j < sec.SizeOfRawData; ++j) freq[raw[j]]++;

        double entropy = 0.0;
        for (int k = 0; k < 256; ++k) {
            if (freq[k] == 0) continue;
            double p = static_cast<double>(freq[k]) / sec.SizeOfRawData;
            entropy -= p * log2(p);
        }

        result.push_back({SectionName(sec), entropy,
                          entropy >= thresholds::SECTION_ENTROPY_HIGH});
    }
    return result;
}

std::vector<std::string> PEAnalyzer::GetSuspiciousSections() {
    std::vector<std::string> result;
    if (!loaded_ && !Load()) return result;

    for (WORD i = 0; i < section_count_; ++i) {
        const std::string name = SectionName(sections_[i]);
        bool standard = false;
        for (const auto& s : STANDARD_SECTION_NAMES) {
            if (name == s) { standard = true; break; }
        }
        if (!standard) result.push_back(name);
    }
    return result;
}

bool PEAnalyzer::HasAntiDebugTechniques() {
    int count = 0;
    for (const auto& imp : GetSuspiciousImports()) {
        if (imp.reason.find("Anti-debug") != std::string::npos) {
            if (++count >= thresholds::ANTI_DEBUG_MIN_CLUSTER) return true;
        }
    }
    return false;
}

bool PEAnalyzer::HasProcessHollowingPattern() {
    const auto imports = GetSuspiciousImports();
    return HasImport(imports, "VirtualAllocEx")
        && HasImport(imports, "WriteProcessMemory")
        && (HasImport(imports, "NtUnmapViewOfSection")
            || HasImport(imports, "ZwUnmapViewOfSection"));
}

bool PEAnalyzer::HasKeyloggerPattern() {
    const auto imports = GetSuspiciousImports();
    if (!HasImport(imports, "SetWindowsHookEx")) return false;
    return HasImport(imports, "GetAsyncKeyState") || HasImport(imports, "GetKeyState");
}

std::string PEAnalyzer::IsPackerSignature() {
    if (!loaded_ && !Load()) return "";

    for (WORD i = 0; i < section_count_; ++i) {
        const std::string name = SectionName(sections_[i]);
        if (name == "UPX0" || name == "UPX1")         return "UPX";
        if (name == ".MPRESS1" || name == ".MPRESS2") return "MPRESS";
    }
    return "";
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

// ─── PE loading / unloading ───────────────────────────────────────────────────

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

// ─── Import table parsing ─────────────────────────────────────────────────────

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

// ─── RVA to file-offset conversion ────────────────────────────────────────────

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
