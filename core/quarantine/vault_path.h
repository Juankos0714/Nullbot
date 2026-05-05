#pragma once

/*
 * NullBot — Open Source Anti-Botnet | GPL-3.0
 * File: core/quarantine/vault_path.h
 */

#include <windows.h>
#include <objbase.h>
#include <string>

#pragma comment(lib, "ole32.lib")

namespace nullbot::quarantine {

// Returns L"{xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx}.qvault"
inline std::wstring GenerateVaultFilename() {
    GUID guid{};
    if (FAILED(CoCreateGuid(&guid)))
        return L"fallback.qvault";

    wchar_t buf[64];
    swprintf_s(buf, L"{%08lX-%04X-%04X-%02X%02X-%02X%02X%02X%02X%02X%02X}.qvault",
        guid.Data1, guid.Data2, guid.Data3,
        guid.Data4[0], guid.Data4[1],
        guid.Data4[2], guid.Data4[3], guid.Data4[4],
        guid.Data4[5], guid.Data4[6], guid.Data4[7]);
    return buf;
}

} // namespace nullbot::quarantine
