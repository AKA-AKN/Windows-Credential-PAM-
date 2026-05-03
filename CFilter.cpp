#include "CFilter.h"
#include <new>
#include <shlwapi.h>

extern void DllAddRef();
extern void DllRelease();

// The hardcoded GUID for the native Microsoft Password Credential Provider
static const GUID GUID_NativePasswordProvider =
    {0x60b78e88, 0xead8, 0x445c, {0x9c, 0xfd, 0x0b, 0x87, 0xf7, 0x4e, 0xa6, 0xcd}};

CFilter::CFilter() : _cRef(1)
{
    DllAddRef();
}

CFilter::~CFilter()
{
    DllRelease();
}

IFACEMETHODIMP_(ULONG)
CFilter::AddRef()
{
    return ++_cRef;
}

IFACEMETHODIMP_(ULONG)
CFilter::Release()
{
    long cRef = --_cRef;
    if (!cRef)
    {
        delete this;
    }
    return cRef;
}

IFACEMETHODIMP CFilter::QueryInterface(_In_ REFIID riid, _COM_Outptr_ void **ppv)
{
    static const QITAB qit[] =
        {
            QITABENT(CFilter, ICredentialProviderFilter),
            {0},
        };
    return QISearch(this, qit, riid, ppv);
}

IFACEMETHODIMP CFilter::Filter(CREDENTIAL_PROVIDER_USAGE_SCENARIO cpus, DWORD dwFlags, _In_reads_(cProviders) GUID *rgclsidProviders, _Inout_updates_(cProviders) BOOL *rgbAllow, DWORD cProviders)
{
    UNREFERENCED_PARAMETER(dwFlags); // Tell C++ we are intentionally ignoring this!

    if (cpus == CPUS_LOGON || cpus == CPUS_UNLOCK_WORKSTATION)
    {
        for (DWORD i = 0; i < cProviders; i++)
        {
            // Use our newly renamed variable here!
            if (rgclsidProviders[i] == GUID_NativePasswordProvider)
            {
                rgbAllow[i] = FALSE;
            }
        }
    }
    return S_OK;
}

IFACEMETHODIMP CFilter::UpdateRemoteCredential(
    _In_ const CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION *pcpcsIn,
    _Out_ CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION *pcpcsOut)
{
    if (pcpcsIn == nullptr || pcpcsOut == nullptr)
    {
        return E_INVALIDARG;
    }

    if (pcpcsIn->cbSerialization > 0 && pcpcsIn->rgbSerialization != nullptr)
    {
        // THIS IS THE EXACT GUID FOR YOUR UI PROVIDER (From your .reg file)
        static const GUID CLSID_CSampleProvider =
            {0x5fd3d285, 0x0dd9, 0x4362, {0x88, 0x55, 0xe0, 0xab, 0xaa, 0xcd, 0x4a, 0xf6}};

        // 1. Allocate memory for the outgoing payload
        pcpcsOut->rgbSerialization = static_cast<byte *>(CoTaskMemAlloc(pcpcsIn->cbSerialization));
        if (pcpcsOut->rgbSerialization)
        {
            // 2. Copy the encrypted password payload exactly as RDP sent it
            CopyMemory(pcpcsOut->rgbSerialization, pcpcsIn->rgbSerialization, pcpcsIn->cbSerialization);
            pcpcsOut->cbSerialization = pcpcsIn->cbSerialization;
            pcpcsOut->ulAuthenticationPackage = pcpcsIn->ulAuthenticationPackage;

            // 3. THE HIJACK: Change the destination GUID to our Custom DLL!
            pcpcsOut->clsidCredentialProvider = CLSID_CSampleProvider;

            return S_OK; // Tell Winlogon: "I successfully rerouted this payload!"
        }
        return E_OUTOFMEMORY;
    }

    return E_NOTIMPL;
}

// Boilerplate initialization
HRESULT CFilter_CreateInstance(_In_ REFIID riid, _Outptr_ void **ppv)
{
    HRESULT hr;
    CFilter *pFilter = new (std::nothrow) CFilter();
    if (pFilter)
    {
        hr = pFilter->QueryInterface(riid, ppv);
        pFilter->Release();
    }
    else
    {
        hr = E_OUTOFMEMORY;
    }
    return hr;
}