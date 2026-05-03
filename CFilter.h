#pragma once
#include <credentialprovider.h>
#include <windows.h>

class CFilter : public ICredentialProviderFilter
{
public:
    // IUnknown
    IFACEMETHODIMP_(ULONG)
    AddRef();
    IFACEMETHODIMP_(ULONG)
    Release();
    IFACEMETHODIMP QueryInterface(_In_ REFIID riid, _COM_Outptr_ void **ppv);

    // ICredentialProviderFilter
    IFACEMETHODIMP Filter(CREDENTIAL_PROVIDER_USAGE_SCENARIO cpus, DWORD dwFlags, _In_reads_(cProviders) GUID *rgclsidProviders, _Inout_updates_(cProviders) BOOL *rgbAllow, DWORD cProviders);
    IFACEMETHODIMP UpdateRemoteCredential(_In_ const CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION *pcpcsIn, _Out_ CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION *pcpcsOut);

    friend HRESULT CFilter_CreateInstance(_In_ REFIID riid, _Outptr_ void **ppv);

protected:
    CFilter();
    ~CFilter();

private:
    long _cRef;
};