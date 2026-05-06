#pragma once

/*
 * NullBot — Open Source Anti-Botnet | GPL-3.0
 * File: core/realtime/amsi_provider.h
 *
 * COM in-process server that registers with the Windows AMSI subsystem.
 * Intercepts scripts (PowerShell, VBScript, JScript, etc.) before execution
 * and returns AMSI_RESULT_DETECTED for known malicious patterns.
 *
 * Build target: nullbot_amsi_provider.dll  (SHARED library)
 * Registration: run DllRegisterServer as Administrator, or call
 *               AmsiProvider::RegisterProvider() directly.
 *
 * AMSI provider CLSID: {B7D3E491-4F83-4E92-A8C5-72AA9B3C5F01}
 */

#include <windows.h>
#include <amsi.h>
#include <objbase.h>

#include <atomic>
#include <string>

namespace nullbot {
namespace realtime {

// {B7D3E491-4F83-4E92-A8C5-72AA9B3C5F01}
// GUID is fixed — changing it invalidates existing registry registrations.
inline constexpr CLSID CLSID_NullBotAmsiProvider = {
    0xB7D3E491, 0x4F83, 0x4E92,
    { 0xA8, 0xC5, 0x72, 0xAA, 0x9B, 0x3C, 0x5F, 0x01 }
};

inline constexpr wchar_t kNullBotAmsiProviderClsidStr[] =
    L"{B7D3E491-4F83-4E92-A8C5-72AA9B3C5F01}";

// ─── Provider ─────────────────────────────────────────────────────────────────

class AmsiProvider final : public IAntimalwareProvider {
public:
    AmsiProvider();
    ~AmsiProvider();

    // IUnknown
    STDMETHODIMP QueryInterface(REFIID riid, void** ppv) override;
    STDMETHODIMP_(ULONG) AddRef() override;
    STDMETHODIMP_(ULONG) Release() override;

    // IAntimalwareProvider
    STDMETHODIMP Scan(IAmsiStream* amsi_stream, AMSI_RESULT* result) override;
    void STDMETHODCALLTYPE CloseSession(ULONGLONG session) override;
    STDMETHODIMP DisplayName(LPWSTR* display_name) override;

    // Write / remove HKLM AMSI provider key and HKCR COM InprocServer32 entries.
    static HRESULT RegisterProvider();
    static HRESULT UnregisterProvider();

private:
    // Scan an in-memory script buffer for known malicious patterns.
    // Returns AMSI_RESULT_DETECTED or AMSI_RESULT_CLEAN.
    static AMSI_RESULT ScanContent(const BYTE* data, ULONGLONG size,
                                   const std::wstring& content_name);

    std::atomic<ULONG> ref_count_{ 1 };
};

// ─── Class factory ────────────────────────────────────────────────────────────

class AmsiProviderFactory final : public IClassFactory {
public:
    // IUnknown
    STDMETHODIMP QueryInterface(REFIID riid, void** ppv) override;
    STDMETHODIMP_(ULONG) AddRef() override;
    STDMETHODIMP_(ULONG) Release() override;

    // IClassFactory
    STDMETHODIMP CreateInstance(IUnknown* outer, REFIID riid, void** ppv) override;
    STDMETHODIMP LockServer(BOOL lock) override;

private:
    std::atomic<ULONG> ref_count_{ 1 };
};

} // namespace realtime
} // namespace nullbot
