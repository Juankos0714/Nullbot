/*
 * NullBot — Open Source Anti-Botnet | GPL-3.0
 * File: core/realtime/amsi_provider.cpp
 *
 * Compiled as a standalone DLL: nullbot_amsi_provider.dll
 * The AMSI subsystem loads this DLL via COM when a script is submitted for scan.
 */

#include "core/realtime/amsi_provider.h"

#include <algorithm>
#include <cctype>
#include <new>
#include <string>

#pragma comment(lib, "ole32.lib")
#pragma comment(lib, "advapi32.lib")

// Module-level reference count used by DllCanUnloadNow.
static std::atomic<LONG> g_dll_ref_count{ 0 };

// Handle filled in by DllMain — needed for GetModuleFileNameW in RegisterProvider.
static HMODULE g_hmodule = nullptr;

BOOL APIENTRY DllMain(HMODULE hmod, DWORD reason, LPVOID) {
    if (reason == DLL_PROCESS_ATTACH) {
        g_hmodule = hmod;
        DisableThreadLibraryCalls(hmod);
    }
    return TRUE;
}

namespace nullbot {
namespace realtime {

// ─── Malicious pattern list ───────────────────────────────────────────────────
//
// Patterns are checked case-insensitively against the submitted script text.
// Each entry is a known indicator of malicious PowerShell / script activity.

static const char* kMaliciousPatterns[] = {
    "invoke-mimikatz",
    "amsiinitialized",       // AMSI bypass reflection
    "amsiutils",             // AMSI bypass via reflection patching
    "amsiinitialized",
    "add-mppreference -exclusionpath",   // disabling Windows Defender
    "set-mppreference -disablerealtimemonitoring",
    "iex (new-object net.webclient).downloadstring",
    "iex(new-object net.webclient).downloadstring",
    "[system.runtime.interopservices.marshal]::writebyte",  // AMSI patch
    "powershell -w hidden -enc",
    "powershell -windowstyle hidden -encodedcommand",
    "net.webclient).downloadfile",
    "invoke-expression (new-object",
    "start-process -windowstyle hidden",
};

// ─── AmsiProvider ─────────────────────────────────────────────────────────────

AmsiProvider::AmsiProvider() { ++g_dll_ref_count; }
AmsiProvider::~AmsiProvider() { --g_dll_ref_count; }

STDMETHODIMP_(ULONG) AmsiProvider::AddRef() {
    return ref_count_.fetch_add(1, std::memory_order_relaxed) + 1;
}

STDMETHODIMP_(ULONG) AmsiProvider::Release() {
    ULONG prev = ref_count_.fetch_sub(1, std::memory_order_acq_rel);
    if (prev == 1) delete this;
    return prev - 1;
}

STDMETHODIMP AmsiProvider::QueryInterface(REFIID riid, void** ppv) {
    if (!ppv) return E_POINTER;
    if (IsEqualIID(riid, IID_IUnknown) ||
        IsEqualIID(riid, __uuidof(IAntimalwareProvider))) {
        *ppv = static_cast<IAntimalwareProvider*>(this);
        AddRef();
        return S_OK;
    }
    *ppv = nullptr;
    return E_NOINTERFACE;
}

// ─── IAntimalwareProvider ────────────────────────────────────────────────────

STDMETHODIMP AmsiProvider::Scan(IAmsiStream* amsi_stream, AMSI_RESULT* result) {
    if (!result) return E_POINTER;
    *result = AMSI_RESULT_CLEAN;
    if (!amsi_stream) return E_INVALIDARG;

    // Retrieve a pointer to the script content in the calling process memory.
    PVOID content_addr = nullptr;
    ULONG ret_size     = 0;
    HRESULT hr = amsi_stream->GetAttribute(
        AMSI_ATTRIBUTE_CONTENT_ADDRESS,
        sizeof(PVOID),
        reinterpret_cast<PBYTE>(&content_addr),
        &ret_size);
    if (FAILED(hr) || !content_addr) return S_OK;

    // Content size in bytes.
    ULONGLONG content_size = 0;
    hr = amsi_stream->GetAttribute(
        AMSI_ATTRIBUTE_CONTENT_SIZE,
        sizeof(ULONGLONG),
        reinterpret_cast<PBYTE>(&content_size),
        &ret_size);
    if (FAILED(hr) || content_size == 0) return S_OK;

    // Content name (script filename or buffer label) — optional, best-effort.
    LPWSTR content_name_ptr = nullptr;
    amsi_stream->GetAttribute(
        AMSI_ATTRIBUTE_CONTENT_NAME,
        sizeof(LPWSTR),
        reinterpret_cast<PBYTE>(&content_name_ptr),
        &ret_size);
    std::wstring content_name = content_name_ptr ? content_name_ptr : L"<unknown>";

    *result = ScanContent(
        static_cast<const BYTE*>(content_addr),
        content_size,
        content_name);

    return S_OK;
}

void STDMETHODCALLTYPE AmsiProvider::CloseSession(ULONGLONG /*session*/) {
    // No per-session state to release.
}

STDMETHODIMP AmsiProvider::DisplayName(LPWSTR* display_name) {
    if (!display_name) return E_POINTER;
    static const wchar_t kName[] = L"NullBot Antimalware Provider";
    *display_name = static_cast<LPWSTR>(
        CoTaskMemAlloc(sizeof(kName)));
    if (!*display_name) return E_OUTOFMEMORY;
    wcscpy_s(*display_name, _countof(kName), kName);
    return S_OK;
}

// ─── Content scanner ─────────────────────────────────────────────────────────

AMSI_RESULT AmsiProvider::ScanContent(const BYTE* data, ULONGLONG size,
                                       const std::wstring& /*content_name*/) {
    // Cap the buffer we inspect to 4 MB to avoid large allocations.
    const size_t inspect_len = static_cast<size_t>(
        std::min(size, static_cast<ULONGLONG>(4 * 1024 * 1024)));

    std::string text(reinterpret_cast<const char*>(data), inspect_len);
    std::string lower_text = text;
    std::transform(lower_text.begin(), lower_text.end(),
                   lower_text.begin(),
                   [](unsigned char c) { return static_cast<char>(std::tolower(c)); });

    for (const char* pattern : kMaliciousPatterns) {
        if (lower_text.find(pattern) != std::string::npos) {
            return AMSI_RESULT_DETECTED;
        }
    }
    return AMSI_RESULT_CLEAN;
}

// ─── Registration helpers ────────────────────────────────────────────────────

static HRESULT WriteRegistryString(HKEY root,
                                   const wchar_t* subkey,
                                   const wchar_t* value_name,
                                   const wchar_t* value) {
    HKEY hkey = nullptr;
    LONG rc = RegCreateKeyExW(root, subkey, 0, nullptr,
                              REG_OPTION_NON_VOLATILE,
                              KEY_WRITE, nullptr, &hkey, nullptr);
    if (rc != ERROR_SUCCESS) return HRESULT_FROM_WIN32(rc);

    if (value) {
        rc = RegSetValueExW(hkey, value_name, 0, REG_SZ,
                            reinterpret_cast<const BYTE*>(value),
                            static_cast<DWORD>((wcslen(value) + 1) * sizeof(wchar_t)));
    }
    RegCloseKey(hkey);
    return HRESULT_FROM_WIN32(rc);
}

HRESULT AmsiProvider::RegisterProvider() {
    // 1. Retrieve the path of this DLL.
    wchar_t dll_path[MAX_PATH] = {};
    if (!GetModuleFileNameW(g_hmodule, dll_path, MAX_PATH))
        return HRESULT_FROM_WIN32(GetLastError());

    // 2. COM InprocServer32 — so CoCreateInstance can load the DLL.
    {
        std::wstring key = std::wstring(L"CLSID\\") + kNullBotAmsiProviderClsidStr
                           + L"\\InprocServer32";
        HRESULT hr = WriteRegistryString(HKEY_CLASSES_ROOT, key.c_str(), nullptr, dll_path);
        if (FAILED(hr)) return hr;
        hr = WriteRegistryString(HKEY_CLASSES_ROOT, key.c_str(), L"ThreadingModel", L"Both");
        if (FAILED(hr)) return hr;
    }

    // 3. AMSI provider list — presence of this key is what enables the provider.
    {
        std::wstring key = std::wstring(L"SOFTWARE\\Microsoft\\AMSI\\Providers\\")
                           + kNullBotAmsiProviderClsidStr;
        HRESULT hr = WriteRegistryString(HKEY_LOCAL_MACHINE, key.c_str(), nullptr, nullptr);
        if (FAILED(hr)) return hr;
    }

    return S_OK;
}

HRESULT AmsiProvider::UnregisterProvider() {
    // Remove AMSI provider entry.
    std::wstring amsi_key = std::wstring(L"SOFTWARE\\Microsoft\\AMSI\\Providers\\")
                            + kNullBotAmsiProviderClsidStr;
    RegDeleteKeyW(HKEY_LOCAL_MACHINE, amsi_key.c_str());

    // Remove COM registration.
    std::wstring inproc_key = std::wstring(L"CLSID\\") + kNullBotAmsiProviderClsidStr
                              + L"\\InprocServer32";
    RegDeleteKeyW(HKEY_CLASSES_ROOT, inproc_key.c_str());

    std::wstring clsid_key = std::wstring(L"CLSID\\") + kNullBotAmsiProviderClsidStr;
    RegDeleteKeyW(HKEY_CLASSES_ROOT, clsid_key.c_str());

    return S_OK;
}

// ─── AmsiProviderFactory ─────────────────────────────────────────────────────

STDMETHODIMP_(ULONG) AmsiProviderFactory::AddRef() {
    return ref_count_.fetch_add(1, std::memory_order_relaxed) + 1;
}

STDMETHODIMP_(ULONG) AmsiProviderFactory::Release() {
    ULONG prev = ref_count_.fetch_sub(1, std::memory_order_acq_rel);
    if (prev == 1) delete this;
    return prev - 1;
}

STDMETHODIMP AmsiProviderFactory::QueryInterface(REFIID riid, void** ppv) {
    if (!ppv) return E_POINTER;
    if (IsEqualIID(riid, IID_IUnknown) ||
        IsEqualIID(riid, IID_IClassFactory)) {
        *ppv = static_cast<IClassFactory*>(this);
        AddRef();
        return S_OK;
    }
    *ppv = nullptr;
    return E_NOINTERFACE;
}

STDMETHODIMP AmsiProviderFactory::CreateInstance(IUnknown* outer, REFIID riid, void** ppv) {
    if (outer) return CLASS_E_NOAGGREGATION;
    auto* provider = new(std::nothrow) AmsiProvider();
    if (!provider) return E_OUTOFMEMORY;
    HRESULT hr = provider->QueryInterface(riid, ppv);
    provider->Release();
    return hr;
}

STDMETHODIMP AmsiProviderFactory::LockServer(BOOL lock) {
    if (lock) ++g_dll_ref_count;
    else      --g_dll_ref_count;
    return S_OK;
}

} // namespace realtime
} // namespace nullbot

// ─── DLL entry points ────────────────────────────────────────────────────────
//
// Wrapped in extern "C" to match combaseapi.h / olectl.h forward declarations.
// __declspec(dllexport) marks each symbol for the DLL export table.

extern "C" {

HRESULT STDAPICALLTYPE DllGetClassObject(REFCLSID rclsid, REFIID riid, LPVOID* ppv) {
    using namespace nullbot::realtime;
    if (!IsEqualCLSID(rclsid, CLSID_NullBotAmsiProvider)) return CLASS_E_CLASSNOTAVAILABLE;

    auto* factory = new(std::nothrow) AmsiProviderFactory();
    if (!factory) return E_OUTOFMEMORY;
    HRESULT hr = factory->QueryInterface(riid, ppv);
    factory->Release();
    return hr;
}

HRESULT STDAPICALLTYPE DllCanUnloadNow() {
    return (g_dll_ref_count.load() == 0) ? S_OK : S_FALSE;
}

HRESULT STDAPICALLTYPE DllRegisterServer() {
    return nullbot::realtime::AmsiProvider::RegisterProvider();
}

HRESULT STDAPICALLTYPE DllUnregisterServer() {
    return nullbot::realtime::AmsiProvider::UnregisterProvider();
}

} // extern "C"
