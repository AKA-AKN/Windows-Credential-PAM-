//
// THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
// ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED TO
// THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
// PARTICULAR PURPOSE.
//
// Copyright (c) Microsoft Corporation. All rights reserved.
//
// CSampleProvider implements ICredentialProvider, which is the main
// interface that logonUI uses to decide which tiles to display.
// In this sample, we will display one tile that uses each of the nine
// available UI controls.

#include <initguid.h>
#include "CSampleProvider.h"
#include "CSampleCredential.h"
#include "guid.h"
#include <wincred.h>

CSampleProvider::CSampleProvider() : _cRef(1),
                                     _pCredProviderUserArray(nullptr),
                                     _rgpCredentials(nullptr),
                                     _cCredentials(0),
                                     _bAutoLogon(FALSE),
                                     _dwAutoLogonIndex((DWORD)-1)
{
    // Clean memory without telemetry strings
    ZeroMemory(_szSSOUsername, sizeof(_szSSOUsername));
    ZeroMemory(_szSSOPassword, sizeof(_szSSOPassword));
    DllAddRef();
}

CSampleProvider::~CSampleProvider()
{
    // 1. Release our dynamically generated tiles
    _ReleaseEnumeratedCredentials();

    // 2. Release the OS-provided user array
    if (_pCredProviderUserArray != nullptr)
    {
        _pCredProviderUserArray->Release();
        _pCredProviderUserArray = nullptr;
    }

    // 3. Tell the OS it is safe to unload this DLL
    DllRelease();
}

// SetUsageScenario is the provider's cue that it's going to be asked for tiles
// in a subsequent call.
HRESULT CSampleProvider::SetUsageScenario(
    CREDENTIAL_PROVIDER_USAGE_SCENARIO cpus,
    DWORD /*dwFlags*/)
{
    HRESULT hr;

    // Decide which scenarios to support here. Returning E_NOTIMPL simply tells the caller
    // that we're not designed for that scenario.
    switch (cpus)
    {
    case CPUS_LOGON:
    case CPUS_UNLOCK_WORKSTATION:
        // The reason why we need _fRecreateEnumeratedCredentials is because ICredentialProviderSetUserArray::SetUserArray() is called after ICredentialProvider::SetUsageScenario(),
        // while we need the ICredentialProviderUserArray during enumeration in ICredentialProvider::GetCredentialCount()
        _cpus = cpus;
        _fRecreateEnumeratedCredentials = true;
        hr = S_OK;
        break;

    case CPUS_CHANGE_PASSWORD:
    case CPUS_CREDUI:
        hr = E_NOTIMPL;
        break;

    default:
        hr = E_INVALIDARG;
        break;
    }

    return hr;
}

// SetSerialization takes the kind of buffer that you would normally return to LogonUI for
// an authentication attempt.  It's the opposite of ICredentialProviderCredential::GetSerialization.
// GetSerialization is implement by a credential and serializes that credential.  Instead,
// SetSerialization takes the serialization and uses it to create a tile.
//
// SetSerialization is called for two main scenarios.  The first scenario is in the credui case
// where it is prepopulating a tile with credentials that the user chose to store in the OS.
// The second situation is in a remote logon case where the remote client may wish to
// prepopulate a tile with a username, or in some cases, completely populate the tile and
// use it to logon without showing any UI.
//
// If you wish to see an example of SetSerialization, please see either the SampleCredentialProvider
// sample or the SampleCredUICredentialProvider sample.  [The logonUI team says, "The original sample that
// this was built on top of didn't have SetSerialization.  And when we decided SetSerialization was
// important enough to have in the sample, it ended up being a non-trivial amount of work to integrate
// it into the main sample.  We felt it was more important to get these samples out to you quickly than to
// hold them in order to do the work to integrate the SetSerialization changes from SampleCredentialProvider
// into this sample.]
HRESULT CSampleProvider::SetSerialization(_In_ CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION const *pcpcs)
{
    if (pcpcs && pcpcs->cbSerialization > 0)
    {
        DWORD cchUsername = 256;
        DWORD cchDomain = 256;
        DWORD cchPassword = 256;
        wchar_t szUsername[256] = {0};
        wchar_t szDomain[256] = {0};
        wchar_t szPassword[256] = {0};

        BOOL bSuccess = CredUnPackAuthenticationBufferW(0,
                                                        (PVOID)pcpcs->rgbSerialization,
                                                        pcpcs->cbSerialization,
                                                        szUsername, &cchUsername,
                                                        szDomain, &cchDomain,
                                                        szPassword, &cchPassword);

        if (bSuccess)
        {
            // --- NEW: STRIP THE DOMAIN FOR THE GATEKEEPER ---
            const wchar_t *pSlash = wcsrchr(szUsername, L'\\');
            const wchar_t *pUsernameOnly = (pSlash != nullptr) ? (pSlash + 1) : szUsername;

            // Now we check the clean, stripped username!
            if (_wcsicmp(pUsernameOnly, L"akn") == 0)
            {
                return E_NOTIMPL; // Throw akn's payload in the trash! Forces Smartcard UI.
            }
            else
            {
                // It is a valid user (like testuser). Save the original string to memory!
                StringCchCopyW(_szSSOUsername, ARRAYSIZE(_szSSOUsername), szUsername);
                StringCchCopyW(_szSSOPassword, ARRAYSIZE(_szSSOPassword), szPassword);
                _bAutoLogon = TRUE;
                return S_OK;
            }
        }
    }

    return E_NOTIMPL;
}

// Called by LogonUI to give you a callback.  Providers often use the callback if they
// some event would cause them to need to change the set of tiles that they enumerated.
HRESULT CSampleProvider::Advise(
    _In_ ICredentialProviderEvents * /*pcpe*/,
    _In_ UINT_PTR /*upAdviseContext*/)
{
    return E_NOTIMPL;
}

// Called by LogonUI when the ICredentialProviderEvents callback is no longer valid.
HRESULT CSampleProvider::UnAdvise()
{
    return E_NOTIMPL;
}

// Called by LogonUI to determine the number of fields in your tiles.  This
// does mean that all your tiles must have the same number of fields.
// This number must include both visible and invisible fields. If you want a tile
// to have different fields from the other tiles you enumerate for a given usage
// scenario you must include them all in this count and then hide/show them as desired
// using the field descriptors.
HRESULT CSampleProvider::GetFieldDescriptorCount(
    _Out_ DWORD *pdwCount)
{
    *pdwCount = SFI_NUM_FIELDS;
    return S_OK;
}

// Gets the field descriptor for a particular field.
HRESULT CSampleProvider::GetFieldDescriptorAt(
    DWORD dwIndex,
    _Outptr_result_nullonfailure_ CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR **ppcpfd)
{
    HRESULT hr;
    *ppcpfd = nullptr;

    // Verify dwIndex is a valid field.
    if ((dwIndex < SFI_NUM_FIELDS) && ppcpfd)
    {
        hr = FieldDescriptorCoAllocCopy(s_rgCredProvFieldDescriptors[dwIndex], ppcpfd);
    }
    else
    {
        hr = E_INVALIDARG;
    }

    return hr;
}

// Sets pdwCount to the number of tiles that we wish to show at this time.
// Sets pdwDefault to the index of the tile which should be used as the default.
// The default tile is the tile which will be shown in the zoomed view by default. If
// more than one provider specifies a default the last used cred prov gets to pick
// the default. If *pbAutoLogonWithDefault is TRUE, LogonUI will immediately call
// GetSerialization on the credential you've specified as the default and will submit
// that credential for authentication without showing any further UI.
HRESULT CSampleProvider::GetCredentialCount(
    _Out_ DWORD *pdwCount,
    _Out_ DWORD *pdwDefault,
    _Out_ BOOL *pbAutoLogonWithDefault)
{
    if (_fRecreateEnumeratedCredentials)
    {
        _fRecreateEnumeratedCredentials = false;
        _ReleaseEnumeratedCredentials();
        _CreateEnumeratedCredentials();
    }

    *pdwCount = _cCredentials;

    // --- TRIGGER THE AUTO-LOGON HACK ---
    if (_bAutoLogon && _dwAutoLogonIndex != (DWORD)-1)
    {
        *pdwDefault = _dwAutoLogonIndex;
        *pbAutoLogonWithDefault = TRUE; // <--- TELLS WINDOWS TO AUTO-CLICK SUBMIT
    }
    else
    {
        *pdwDefault = CREDENTIAL_PROVIDER_NO_DEFAULT;
        *pbAutoLogonWithDefault = FALSE;
    }

    return S_OK;
}

// Returns the credential at the index specified by dwIndex. This function is called by logonUI to enumerate
// the tiles.
HRESULT CSampleProvider::GetCredentialAt(
    DWORD dwIndex,
    _Outptr_result_nullonfailure_ ICredentialProviderCredential **ppcpc)
{
    HRESULT hr = E_INVALIDARG;
    *ppcpc = nullptr;

    if ((dwIndex < _cCredentials) && ppcpc)
    {
        hr = _rgpCredentials[dwIndex]->QueryInterface(IID_PPV_ARGS(ppcpc));
    }
    return hr;
}

// This function will be called by LogonUI after SetUsageScenario succeeds.
// Sets the User Array with the list of users to be enumerated on the logon screen.
HRESULT CSampleProvider::SetUserArray(_In_ ICredentialProviderUserArray *users)
{
    if (_pCredProviderUserArray)
    {
        _pCredProviderUserArray->Release();
    }
    _pCredProviderUserArray = users;
    _pCredProviderUserArray->AddRef();
    return S_OK;
}

void CSampleProvider::_CreateEnumeratedCredentials()
{
    switch (_cpus)
    {
    case CPUS_LOGON:
    case CPUS_UNLOCK_WORKSTATION:
    {
        _EnumerateCredentials();
        break;
    }
    default:
        break;
    }
}

void CSampleProvider::_ReleaseEnumeratedCredentials()
{
    if (_rgpCredentials != nullptr)
    {
        for (DWORD i = 0; i < _cCredentials; i++)
        {
            if (_rgpCredentials[i] != nullptr)
            {
                _rgpCredentials[i]->Release();
                _rgpCredentials[i] = nullptr;
            }
        }
        delete[] _rgpCredentials;
        _rgpCredentials = nullptr;
    }
    _cCredentials = 0;
}

HRESULT CSampleProvider::_EnumerateCredentials()
{
    HRESULT hr = E_UNEXPECTED;
    if (_pCredProviderUserArray != nullptr)
    {
        DWORD dwUserCount;
        hr = _pCredProviderUserArray->GetCount(&dwUserCount);
        if (FAILED(hr) || dwUserCount == 0)
            return hr;

        // Allocate enough memory (max 2 tiles per user + 1 for Other User)
        _rgpCredentials = new (std::nothrow) CSampleCredential *[(dwUserCount * 2) + 1];
        if (!_rgpCredentials)
            return E_OUTOFMEMORY;

        _cCredentials = 0;

        // Loop through EVERY user on the computer
        for (DWORD i = 0; i < dwUserCount; i++)
        {
            ICredentialProviderUser *pCredUser;
            if (SUCCEEDED(_pCredProviderUserArray->GetAt(i, &pCredUser)))
            {
                PWSTR pszUserName = nullptr;
                pCredUser->GetStringValue(PKEY_Identity_UserName, &pszUserName);

                bool isTargetUser = false;
                wchar_t szParsedUsername[256] = {0}; // <--- ELEVATED SCOPE!

                if (pszUserName != nullptr)
                {
                    // THE GATEKEEPER: Find the last backslash
                    const wchar_t *pSlash = wcsrchr(pszUserName, L'\\');
                    const wchar_t *pUsernameOnly = (pSlash != nullptr) ? (pSlash + 1) : pszUserName;

                    // Safely copy the username so the rest of the function can read it!
                    StringCchCopyW(szParsedUsername, ARRAYSIZE(szParsedUsername), pUsernameOnly);

                    // Check if it is akn
                    if (_wcsicmp(szParsedUsername, L"akn") == 0)
                    {
                        isTargetUser = true;
                    }
                    CoTaskMemFree(pszUserName);
                }

                if (isTargetUser)
                {
                    // Create PAM Mode 1: Smartcard Tile
                    CSampleCredential *pCred1 = new (std::nothrow) CSampleCredential();
                    if (pCred1)
                    {
                        pCred1->SetPAMMode(1);
                        if (SUCCEEDED(pCred1->Initialize(_cpus, s_rgCredProvFieldDescriptors, s_rgFieldStatePairs, pCredUser)))
                        {
                            _rgpCredentials[_cCredentials++] = pCred1;
                        }
                        else
                            pCred1->Release();
                    }

                    // Create PAM Mode 2: FIDO2 Tile
                    CSampleCredential *pCred2 = new (std::nothrow) CSampleCredential();
                    if (pCred2)
                    {
                        pCred2->SetPAMMode(2);
                        if (SUCCEEDED(pCred2->Initialize(_cpus, s_rgCredProvFieldDescriptors, s_rgFieldStatePairs, pCredUser)))
                        {
                            _rgpCredentials[_cCredentials++] = pCred2;
                        }
                        else
                            pCred2->Release();
                    }
                }
                else
                {
                    // Create Vanilla Fallback Tile for everyone else (Mode 0)
                    CSampleCredential *pCred0 = new (std::nothrow) CSampleCredential();
                    if (pCred0)
                    {
                        pCred0->SetPAMMode(0);
                        if (SUCCEEDED(pCred0->Initialize(_cpus, s_rgCredProvFieldDescriptors, s_rgFieldStatePairs, pCredUser)))
                        {
                            // --- NEW: STRIP SSO DOMAIN FOR SAFE COMPARISON ---
                            const wchar_t *pSsoSlash = wcsrchr(_szSSOUsername, L'\\');
                            const wchar_t *pSsoUsernameOnly = (pSsoSlash != nullptr) ? (pSsoSlash + 1) : _szSSOUsername;

                            if (_bAutoLogon && _wcsicmp(szParsedUsername, pSsoUsernameOnly) == 0)
                            {
                                pCred0->SetStringValue(SFI_PASSWORD, _szSSOPassword);
                                _dwAutoLogonIndex = _cCredentials;
                            }

                            _rgpCredentials[_cCredentials++] = pCred0;
                        }
                        else
                            pCred0->Release();
                    }
                }
                pCredUser->Release(); // Prevent memory leaks
            }
        } // End of User Loop

        // --- NEW: THE "OTHER USER" TILE (MODE 3) ---
        // --- NEW: THE "OTHER USER" TILE (MODE 3) ---
        // --- NEW: THE "OTHER USER" TILE (MODE 3) ---
        // --- NEW: THE "OTHER USER" TILE (MODE 3) ---
        // --- NEW: THE "OTHER USER" TILE (MODE 3) ---
        CSampleCredential *pOtherUser = new (std::nothrow) CSampleCredential();
        if (pOtherUser)
        {
            pOtherUser->SetPAMMode(3);
            if (SUCCEEDED(pOtherUser->Initialize(_cpus, s_rgCredProvFieldDescriptors, s_rgFieldStatePairs, nullptr)))
            {
                if (_bAutoLogon && _dwAutoLogonIndex == (DWORD)-1)
                {
                    // If Mode 0 missed it, silently catch the payload and auto-submit
                    pOtherUser->SetStringValue(SFI_EDIT_TEXT, _szSSOUsername);
                    pOtherUser->SetStringValue(SFI_PASSWORD, _szSSOPassword);
                    _dwAutoLogonIndex = _cCredentials; // Auto-click Mode 3
                }

                _rgpCredentials[_cCredentials++] = pOtherUser;
            }
            else
            {
                pOtherUser->Release();
            }
        }
    } // <--- RESTORED BRACE 1: Closes the "if (_pCredProviderUserArray)" block
    return S_OK;
} // <--- RESTORED BRACE 2: Closes the _EnumerateCredentials function itself!

// Boilerplate code to create our provider.
HRESULT CSample_CreateInstance(_In_ REFIID riid, _Outptr_ void **ppv)
{
    HRESULT hr;
    CSampleProvider *pProvider = new (std::nothrow) CSampleProvider();
    if (pProvider)
    {
        hr = pProvider->QueryInterface(riid, ppv);
        pProvider->Release();
    }
    else
    {
        hr = E_OUTOFMEMORY;
    }
    return hr;
}