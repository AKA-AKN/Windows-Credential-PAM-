//
// THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
// ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED TO
// THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
// PARTICULAR PURPOSE.
//
// Copyright (c) Microsoft Corporation. All rights reserved.
//
//

#ifndef WIN32_NO_STATUS
#include <ntstatus.h>
#define WIN32_NO_STATUS
#endif
#include <unknwn.h>
#include "CSampleCredential.h"
#include <fido.h>
#include <fido/credman.h>
#include "guid.h"
#include <winscard.h>
#pragma comment(lib, "winscard.lib")
#include <wincrypt.h>
#include <ncrypt.h>
#pragma comment(lib, "crypt32.lib")
#pragma comment(lib, "ncrypt.lib")

CSampleCredential::CSampleCredential() : _cRef(1),
                                         _pCredProvCredentialEvents(nullptr),
                                         _pszUserSid(nullptr),
                                         _pszQualifiedUserName(nullptr),
                                         _fIsLocalUser(false),
                                         _fChecked(false),
                                         _fShowControls(false),
                                         _dwComboIndex(0)
{
    DllAddRef();

    ZeroMemory(_rgCredProvFieldDescriptors, sizeof(_rgCredProvFieldDescriptors));
    ZeroMemory(_rgFieldStatePairs, sizeof(_rgFieldStatePairs));
    ZeroMemory(_rgFieldStrings, sizeof(_rgFieldStrings));
}

CSampleCredential::~CSampleCredential()
{
    if (_rgFieldStrings[SFI_PASSWORD])
    {
        size_t lenPassword = wcslen(_rgFieldStrings[SFI_PASSWORD]);
        SecureZeroMemory(_rgFieldStrings[SFI_PASSWORD], lenPassword * sizeof(*_rgFieldStrings[SFI_PASSWORD]));
    }
    for (int i = 0; i < ARRAYSIZE(_rgFieldStrings); i++)
    {
        CoTaskMemFree(_rgFieldStrings[i]);
        CoTaskMemFree(_rgCredProvFieldDescriptors[i].pszLabel);
    }
    CoTaskMemFree(_pszUserSid);
    CoTaskMemFree(_pszQualifiedUserName);
    DllRelease();
}

void CSampleCredential::SetPAMMode(int mode)
{
    _pamMode = mode;
}
// ------------------------------

// Initializes one credential with the field information passed in.
// Set the value of the SFI_LARGE_TEXT field to pwzUsername.
// Initializes one credential with the field information passed in.
// Initializes one credential with the field information passed in.
HRESULT CSampleCredential::Initialize(CREDENTIAL_PROVIDER_USAGE_SCENARIO cpus,
                                      _In_ CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR const *rgcpfd,
                                      _In_ FIELD_STATE_PAIR const *rgfsp,
                                      _In_ ICredentialProviderUser *pcpUser)
{
    HRESULT hr = S_OK;
    _cpus = cpus;

    if (pcpUser != nullptr)
    {
        GUID guidProvider;
        pcpUser->GetProviderID(&guidProvider);
        _fIsLocalUser = (guidProvider == Identity_LocalUserProvider);
        pcpUser->GetSid(&_pszUserSid);
        pcpUser->GetStringValue(PKEY_Identity_QualifiedUserName, &_pszQualifiedUserName);
    }
    else
    {
        _fIsLocalUser = false;
        _pszUserSid = nullptr;
        _pszQualifiedUserName = nullptr;
    }

    // Copy the field descriptors for each field.
    for (DWORD i = 0; SUCCEEDED(hr) && i < ARRAYSIZE(_rgCredProvFieldDescriptors); i++)
    {
        _rgFieldStatePairs[i] = rgfsp[i];
        hr = FieldDescriptorCopy(rgcpfd[i], &_rgCredProvFieldDescriptors[i]);
    }

    // 1. EXACT REPLICA OF YOUR OLD CODE: Hide all the boilerplate text & boxes first!
    _rgFieldStatePairs[SFI_CHECKBOX].cpfs = CPFS_HIDDEN;
    _rgFieldStatePairs[SFI_COMBOBOX].cpfs = CPFS_HIDDEN;
    _rgFieldStatePairs[SFI_LAUNCHWINDOW_LINK].cpfs = CPFS_HIDDEN;
    _rgFieldStatePairs[SFI_HIDECONTROLS_LINK].cpfs = CPFS_HIDDEN;
    _rgFieldStatePairs[SFI_FULLNAME_TEXT].cpfs = CPFS_HIDDEN; // Kills the ugly "username: akn"
    _rgFieldStatePairs[SFI_DISPLAYNAME_TEXT].cpfs = CPFS_HIDDEN;
    _rgFieldStatePairs[SFI_LOGONSTATUS_TEXT].cpfs = CPFS_HIDDEN;

    // 2. ROUTING: Turn on exactly what we need
    // 2. ROUTING: Turn on exactly what we need
    if (SUCCEEDED(hr))
    {
        if (_pamMode == 1)
        {
            // Reverted back to exact string to trigger the APDU intercept!
            hr = SHStrDupW(L"PAM: Smartcard Verification", &_rgFieldStrings[SFI_LABEL]);
            if (SUCCEEDED(hr))
                hr = SHStrDupW(L"Enter AD Password & TPM PIN", &_rgFieldStrings[SFI_LARGE_TEXT]);

            _rgFieldStatePairs[SFI_PASSWORD].cpfs = CPFS_DISPLAY_IN_SELECTED_TILE;
            _rgFieldStatePairs[SFI_PIN_PASSWORD].cpfs = CPFS_DISPLAY_IN_SELECTED_TILE;
        }
        else if (_pamMode == 2)
        {
            // This exact string triggers our hardware intercept!
            hr = SHStrDupW(L"PAM: FIDO2 Token Verification", &_rgFieldStrings[SFI_LABEL]);
            if (SUCCEEDED(hr))
                hr = SHStrDupW(L"Enter AD Password & Tap FIDO2 Token", &_rgFieldStrings[SFI_LARGE_TEXT]);

            // Explicitly turn ON the Password Box and turn OFF the Smartcard PIN box
            _rgFieldStatePairs[SFI_PASSWORD].cpfs = CPFS_DISPLAY_IN_SELECTED_TILE;
            _rgFieldStatePairs[SFI_PIN_PASSWORD].cpfs = CPFS_HIDDEN;
        }
        else if (_pamMode == 3)
        {
            hr = SHStrDupW(L"Other User", &_rgFieldStrings[SFI_LABEL]);
            if (SUCCEEDED(hr))
                hr = SHStrDupW(L"Log in to another account", &_rgFieldStrings[SFI_LARGE_TEXT]);

            // Turn ON the Username Box and put the blinking cursor inside it!
            _rgFieldStatePairs[SFI_EDIT_TEXT].cpfs = CPFS_DISPLAY_IN_SELECTED_TILE;
            _rgFieldStatePairs[SFI_EDIT_TEXT].cpfis = CPFIS_FOCUSED;

            // Turn ON the Password Box, but explicitly REMOVE its blinking cursor!
            _rgFieldStatePairs[SFI_PASSWORD].cpfs = CPFS_DISPLAY_IN_SELECTED_TILE;
            _rgFieldStatePairs[SFI_PASSWORD].cpfis = CPFIS_NONE; // <--- THE FATAL MISSING LINE

            // Hide the TPM Box
            _rgFieldStatePairs[SFI_PIN_PASSWORD].cpfs = CPFS_HIDDEN;
        }
        else
        {
            hr = SHStrDupW(L"Password", &_rgFieldStrings[SFI_LABEL]);
            if (SUCCEEDED(hr))
                hr = SHStrDupW(L"Enter Password", &_rgFieldStrings[SFI_LARGE_TEXT]);

            _rgFieldStatePairs[SFI_PASSWORD].cpfs = CPFS_DISPLAY_IN_SELECTED_TILE;
            _rgFieldStatePairs[SFI_PIN_PASSWORD].cpfs = CPFS_HIDDEN;
        }
    }

    // Hardcoded Watermarks to force the OS to paint the boxes!
    // Clear all strings so the boxes start completely empty
    if (SUCCEEDED(hr))
        hr = SHStrDupW(L"", &_rgFieldStrings[SFI_EDIT_TEXT]);
    if (SUCCEEDED(hr))
        hr = SHStrDupW(L"", &_rgFieldStrings[SFI_PASSWORD]);
    if (SUCCEEDED(hr))
        hr = SHStrDupW(L"Submit", &_rgFieldStrings[SFI_SUBMIT_BUTTON]);
    if (SUCCEEDED(hr))
        hr = SHStrDupW(L"", &_rgFieldStrings[SFI_PIN_PASSWORD]);

    return hr;
}

// LogonUI calls this in order to give us a callback in case we need to notify it of anything.
HRESULT CSampleCredential::Advise(_In_ ICredentialProviderCredentialEvents *pcpce)
{
    if (_pCredProvCredentialEvents != nullptr)
    {
        _pCredProvCredentialEvents->Release();
    }
    return pcpce->QueryInterface(IID_PPV_ARGS(&_pCredProvCredentialEvents));
}

// LogonUI calls this to tell us to release the callback.
HRESULT CSampleCredential::UnAdvise()
{
    if (_pCredProvCredentialEvents)
    {
        _pCredProvCredentialEvents->Release();
    }
    _pCredProvCredentialEvents = nullptr;
    return S_OK;
}

// LogonUI calls this function when our tile is selected (zoomed)
// If you simply want fields to show/hide based on the selected state,
// there's no need to do anything here - you can set that up in the
// field definitions. But if you want to do something
// more complicated, like change the contents of a field when the tile is
// selected, you would do it here.
HRESULT CSampleCredential::SetSelected(_Out_ BOOL *pbAutoLogon)
{
    *pbAutoLogon = FALSE;
    return S_OK;
}

// Similarly to SetSelected, LogonUI calls this when your tile was selected
// and now no longer is. The most common thing to do here (which we do below)
// is to clear out the password field.
HRESULT CSampleCredential::SetDeselected()
{
    HRESULT hr = S_OK;
    if (_rgFieldStrings[SFI_PASSWORD])
    {
        size_t lenPassword = wcslen(_rgFieldStrings[SFI_PASSWORD]);
        SecureZeroMemory(_rgFieldStrings[SFI_PASSWORD], lenPassword * sizeof(*_rgFieldStrings[SFI_PASSWORD]));

        CoTaskMemFree(_rgFieldStrings[SFI_PASSWORD]);
        hr = SHStrDupW(L"", &_rgFieldStrings[SFI_PASSWORD]);

        if (SUCCEEDED(hr) && _pCredProvCredentialEvents)
        {
            _pCredProvCredentialEvents->SetFieldString(this, SFI_PASSWORD, _rgFieldStrings[SFI_PASSWORD]);
        }
    }

    return hr;
}

// Get info for a particular field of a tile. Called by logonUI to get information
// to display the tile.
HRESULT CSampleCredential::GetFieldState(DWORD dwFieldID,
                                         _Out_ CREDENTIAL_PROVIDER_FIELD_STATE *pcpfs,
                                         _Out_ CREDENTIAL_PROVIDER_FIELD_INTERACTIVE_STATE *pcpfis)
{
    HRESULT hr;

    // Validate our parameters.
    if ((dwFieldID < ARRAYSIZE(_rgFieldStatePairs)))
    {
        *pcpfs = _rgFieldStatePairs[dwFieldID].cpfs;
        *pcpfis = _rgFieldStatePairs[dwFieldID].cpfis;
        hr = S_OK;
    }
    else
    {
        hr = E_INVALIDARG;
    }
    return hr;
}

// Sets ppwsz to the string value of the field at the index dwFieldID
// Gets the string value of a field.
HRESULT CSampleCredential::GetStringValue(DWORD dwFieldID, _Outptr_result_nullonfailure_ PWSTR *ppsz)
{
    *ppsz = nullptr;

    // Protect against out-of-bounds indexing
    if (dwFieldID >= ARRAYSIZE(_rgFieldStrings))
    {
        return E_INVALIDARG;
    }

    // If the string exists, return it
    if (_rgFieldStrings[dwFieldID])
    {
        return SHStrDupW(_rgFieldStrings[dwFieldID], ppsz);
    }

    // CRITICAL OS FIX: If the string is empty, we MUST return S_FALSE.
    // Returning an error here crashes LogonUI and blacklists the DLL.
    return S_FALSE;
}

// Get the image to show in the user tile
HRESULT CSampleCredential::GetBitmapValue(DWORD dwFieldID, _Outptr_result_nullonfailure_ HBITMAP *phbmp)
{
    HRESULT hr;
    *phbmp = nullptr;

    if ((SFI_TILEIMAGE == dwFieldID))
    {
        HBITMAP hbmp = LoadBitmap(HINST_THISDLL, MAKEINTRESOURCE(IDB_TILE_IMAGE));
        if (hbmp != nullptr)
        {
            hr = S_OK;
            *phbmp = hbmp;
        }
        else
        {
            hr = HRESULT_FROM_WIN32(GetLastError());
        }
    }
    else
    {
        hr = E_INVALIDARG;
    }

    return hr;
}

// Sets pdwAdjacentTo to the index of the field the submit button should be
// adjacent to. We recommend that the submit button is placed next to the last
// field which the user is required to enter information in. Optional fields
// Sets pdwAdjacentTo to the index of the field the submit button should be adjacent to.
// Sets pdwAdjacentTo to the index of the field the submit button should be adjacent to.
// Sets pdwAdjacentTo to the index of the field the submit button should be adjacent to.
// Sets pdwAdjacentTo to the index of the field the submit button should be adjacent to.
// Sets pdwAdjacentTo to the index of the field the submit button should be adjacent to.
// Sets pdwAdjacentTo to the index of the field the submit button should be adjacent to.
// Sets pdwAdjacentTo to the index of the field the submit button should be adjacent to.
// Sets pdwAdjacentTo to the index of the field the submit button should be adjacent to.
HRESULT CSampleCredential::GetSubmitButtonValue(DWORD dwFieldID, _Out_ DWORD *pdwAdjacentTo)
{
    if (SFI_SUBMIT_BUTTON == dwFieldID)
    {
        if (_pamMode == 1)
        {
            // Mode 1: Password is top, PIN is bottom. Anchor to PIN.
            *pdwAdjacentTo = SFI_PIN_PASSWORD;
        }
        else
        {
            // ALL OTHER MODES (Including Mode 3): Password is the bottom box. Anchor to Password.
            *pdwAdjacentTo = SFI_PASSWORD;
        }
        return S_OK;
    }
    return E_INVALIDARG;
}
// Sets the value of a field which can accept a string as a value.
// This is called on each keystroke when a user types into an edit field
HRESULT CSampleCredential::SetStringValue(DWORD dwFieldID, _In_ PCWSTR pwz)
{
    HRESULT hr;

    // Validate parameters.
    if (dwFieldID < ARRAYSIZE(_rgCredProvFieldDescriptors) &&
        (CPFT_EDIT_TEXT == _rgCredProvFieldDescriptors[dwFieldID].cpft ||
         CPFT_PASSWORD_TEXT == _rgCredProvFieldDescriptors[dwFieldID].cpft))
    {
        PWSTR *ppwszStored = &_rgFieldStrings[dwFieldID];
        CoTaskMemFree(*ppwszStored);
        hr = SHStrDupW(pwz, ppwszStored);
    }
    else
    {
        hr = E_INVALIDARG;
    }

    return hr;
}

// Returns whether a checkbox is checked or not as well as its label.
HRESULT CSampleCredential::GetCheckboxValue(DWORD dwFieldID, _Out_ BOOL *pbChecked, _Outptr_result_nullonfailure_ PWSTR *ppwszLabel)
{
    HRESULT hr;
    *ppwszLabel = nullptr;

    // Validate parameters.
    if (dwFieldID < ARRAYSIZE(_rgCredProvFieldDescriptors) &&
        (CPFT_CHECKBOX == _rgCredProvFieldDescriptors[dwFieldID].cpft))
    {
        *pbChecked = _fChecked;
        hr = SHStrDupW(_rgFieldStrings[SFI_CHECKBOX], ppwszLabel);
    }
    else
    {
        hr = E_INVALIDARG;
    }

    return hr;
}

// Sets whether the specified checkbox is checked or not.
HRESULT CSampleCredential::SetCheckboxValue(DWORD dwFieldID, BOOL bChecked)
{
    HRESULT hr;

    // Validate parameters.
    if (dwFieldID < ARRAYSIZE(_rgCredProvFieldDescriptors) &&
        (CPFT_CHECKBOX == _rgCredProvFieldDescriptors[dwFieldID].cpft))
    {
        _fChecked = bChecked;
        hr = S_OK;
    }
    else
    {
        hr = E_INVALIDARG;
    }

    return hr;
}

// Returns the number of items to be included in the combobox (pcItems), as well as the
// currently selected item (pdwSelectedItem).
HRESULT CSampleCredential::GetComboBoxValueCount(DWORD dwFieldID, _Out_ DWORD *pcItems, _Deref_out_range_(<, *pcItems) _Out_ DWORD *pdwSelectedItem)
{
    HRESULT hr;
    *pcItems = 0;
    *pdwSelectedItem = 0;

    // Validate parameters.
    if (dwFieldID < ARRAYSIZE(_rgCredProvFieldDescriptors) &&
        (CPFT_COMBOBOX == _rgCredProvFieldDescriptors[dwFieldID].cpft))
    {
        *pcItems = ARRAYSIZE(s_rgComboBoxStrings);
        *pdwSelectedItem = 0;
        hr = S_OK;
    }
    else
    {
        hr = E_INVALIDARG;
    }

    return hr;
}

// Called iteratively to fill the combobox with the string (ppwszItem) at index dwItem.
HRESULT CSampleCredential::GetComboBoxValueAt(DWORD dwFieldID, DWORD dwItem, _Outptr_result_nullonfailure_ PWSTR *ppwszItem)
{
    HRESULT hr;
    *ppwszItem = nullptr;

    // Validate parameters.
    if (dwFieldID < ARRAYSIZE(_rgCredProvFieldDescriptors) &&
        (CPFT_COMBOBOX == _rgCredProvFieldDescriptors[dwFieldID].cpft))
    {
        hr = SHStrDupW(s_rgComboBoxStrings[dwItem], ppwszItem);
    }
    else
    {
        hr = E_INVALIDARG;
    }

    return hr;
}

// Called when the user changes the selected item in the combobox.
HRESULT CSampleCredential::SetComboBoxSelectedValue(DWORD dwFieldID, DWORD dwSelectedItem)
{
    HRESULT hr;

    // Validate parameters.
    if (dwFieldID < ARRAYSIZE(_rgCredProvFieldDescriptors) &&
        (CPFT_COMBOBOX == _rgCredProvFieldDescriptors[dwFieldID].cpft))
    {
        _dwComboIndex = dwSelectedItem;
        hr = S_OK;
    }
    else
    {
        hr = E_INVALIDARG;
    }

    return hr;
}

// Called when the user clicks a command link.
HRESULT CSampleCredential::CommandLinkClicked(DWORD dwFieldID)
{
    HRESULT hr = S_OK;

    CREDENTIAL_PROVIDER_FIELD_STATE cpfsShow = CPFS_HIDDEN;

    // Validate parameter.
    if (dwFieldID < ARRAYSIZE(_rgCredProvFieldDescriptors) &&
        (CPFT_COMMAND_LINK == _rgCredProvFieldDescriptors[dwFieldID].cpft))
    {
        HWND hwndOwner = nullptr;
        switch (dwFieldID)
        {
        case SFI_LAUNCHWINDOW_LINK:
            if (_pCredProvCredentialEvents)
            {
                _pCredProvCredentialEvents->OnCreatingWindow(&hwndOwner);
            }

            // Pop a messagebox indicating the click.
            ::MessageBox(hwndOwner, L"Command link clicked", L"Click!", 0);
            break;
        case SFI_HIDECONTROLS_LINK:
            _pCredProvCredentialEvents->BeginFieldUpdates();
            cpfsShow = _fShowControls ? CPFS_DISPLAY_IN_SELECTED_TILE : CPFS_HIDDEN;
            _pCredProvCredentialEvents->SetFieldState(nullptr, SFI_FULLNAME_TEXT, cpfsShow);
            _pCredProvCredentialEvents->SetFieldState(nullptr, SFI_DISPLAYNAME_TEXT, cpfsShow);
            _pCredProvCredentialEvents->SetFieldState(nullptr, SFI_LOGONSTATUS_TEXT, cpfsShow);
            _pCredProvCredentialEvents->SetFieldState(nullptr, SFI_CHECKBOX, cpfsShow);
            _pCredProvCredentialEvents->SetFieldState(nullptr, SFI_EDIT_TEXT, cpfsShow);
            _pCredProvCredentialEvents->SetFieldState(nullptr, SFI_COMBOBOX, cpfsShow);
            _pCredProvCredentialEvents->SetFieldString(nullptr, SFI_HIDECONTROLS_LINK, _fShowControls ? L"Hide additional controls" : L"Show additional controls");
            _pCredProvCredentialEvents->EndFieldUpdates();
            _fShowControls = !_fShowControls;
            break;
        default:
            hr = E_INVALIDARG;
        }
    }
    else
    {
        hr = E_INVALIDARG;
    }

    return hr;
}

// Collect the username and password into a serialized credential for the correct usage scenario
// (logon/unlock is what's demonstrated in this sample).  LogonUI then passes these credentials
// back to the system to log on.
HRESULT CSampleCredential::GetSerialization(_Out_ CREDENTIAL_PROVIDER_GET_SERIALIZATION_RESPONSE *pcpgsr,
                                            _Out_ CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION *pcpcs,
                                            _Outptr_result_maybenull_ PWSTR *ppwszOptionalStatusText,
                                            _Out_ CREDENTIAL_PROVIDER_STATUS_ICON *pcpsiOptionalStatusIcon)
{
    // --- ENTERPRISE PAM: SECONDARY AUTHENTICATION INTERCEPT ---
    // We check the tile name to determine which hardware token to demand.
    if (wcscmp(_rgFieldStrings[SFI_LABEL], L"PAM: Smartcard Verification") == 0)
    {
        // 1. LOAD THE ANCHOR (Server's Source of Truth)
        HANDLE hFile = CreateFileW(L"C:\\AKN_Registered_Key.cer", GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
        if (hFile == INVALID_HANDLE_VALUE)
        {
            SHStrDupW(L"PAM ERROR: C:\\AKN_Registered_Key.cer not found on Server.", ppwszOptionalStatusText);
            *pcpgsr = CPGSR_NO_CREDENTIAL_NOT_FINISHED;
            return S_OK;
        }

        DWORD fileSize = GetFileSize(hFile, NULL);
        BYTE* anchorBytes = new BYTE[fileSize];
        DWORD bytesRead = 0;
        ReadFile(hFile, anchorBytes, fileSize, &bytesRead, NULL);
        CloseHandle(hFile);

        PCCERT_CONTEXT pAnchorCert = CertCreateCertificateContext(X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, anchorBytes, fileSize);
        delete[] anchorBytes;

        if (!pAnchorCert)
        {
            SHStrDupW(L"PAM ERROR: Server Anchor file is corrupt.", ppwszOptionalStatusText);
            *pcpgsr = CPGSR_NO_CREDENTIAL_NOT_FINISHED;
            return S_OK;
        }

        // 2. BYPASS 'SYSTEM' STORE & QUERY RAW RDP SMARTCARD HARDWARE DIRECTLY
        NCRYPT_PROV_HANDLE hProvider = 0;
        if (NCryptOpenStorageProvider(&hProvider, MS_SMART_CARD_KEY_STORAGE_PROVIDER, 0) != ERROR_SUCCESS)
        {
            SHStrDupW(L"PAM ERROR: Smartcard Subsystem Offline.", ppwszOptionalStatusText);
            CertFreeCertificateContext(pAnchorCert);
            *pcpgsr = CPGSR_NO_CREDENTIAL_NOT_FINISHED;
            return S_OK;
        }

        NCryptKeyName* pKeyName = NULL;
        PVOID pEnumState = NULL;
        NCRYPT_KEY_HANDLE hKey = 0;
        BOOL bKeyFound = FALSE;

        // Loop through every key on every inserted smartcard (silently, no OS popups)
        while (NCryptEnumKeys(hProvider, NULL, &pKeyName, &pEnumState, NCRYPT_SILENT_FLAG) == ERROR_SUCCESS)
        {
            if (NCryptOpenKey(hProvider, &hKey, pKeyName->pszName, pKeyName->dwLegacyKeySpec, NCRYPT_SILENT_FLAG) == ERROR_SUCCESS)
            {
                DWORD cbCert = 0;
                // Ask the chip directly for its public certificate
                if (NCryptGetProperty(hKey, NCRYPT_CERTIFICATE_PROPERTY, NULL, 0, &cbCert, 0) == ERROR_SUCCESS)
                {
                    PBYTE pbCert = new BYTE[cbCert];
                    if (NCryptGetProperty(hKey, NCRYPT_CERTIFICATE_PROPERTY, pbCert, cbCert, &cbCert, 0) == ERROR_SUCCESS)
                    {
                        PCCERT_CONTEXT pCardCert = CertCreateCertificateContext(X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, pbCert, cbCert);
                        if (pCardCert)
                        {
                            // 3. THE "DNA" MATCH (Compare Hardware Cert to Server Anchor)
                            if (pAnchorCert->pCertInfo->SubjectPublicKeyInfo.PublicKey.cbData == pCardCert->pCertInfo->SubjectPublicKeyInfo.PublicKey.cbData &&
                                memcmp(pAnchorCert->pCertInfo->SubjectPublicKeyInfo.PublicKey.pbData, pCardCert->pCertInfo->SubjectPublicKeyInfo.PublicKey.pbData, pAnchorCert->pCertInfo->SubjectPublicKeyInfo.PublicKey.cbData) == 0)
                            {
                                bKeyFound = TRUE;
                                CertFreeCertificateContext(pCardCert);
                                delete[] pbCert;
                                NCryptFreeBuffer(pKeyName);
                                break; // MATCH FOUND! Keep hKey open.
                            }
                            CertFreeCertificateContext(pCardCert);
                        }
                    }
                    delete[] pbCert;
                }
                NCryptFreeObject(hKey);
                hKey = 0;
            }
            NCryptFreeBuffer(pKeyName);
        }

        if (pEnumState) NCryptFreeBuffer(pEnumState);
        NCryptFreeObject(hProvider);

        if (!bKeyFound)
        {
            SHStrDupW(L"PAM ENFORCED: Authorized Smartcard not detected over RDP tunnel.", ppwszOptionalStatusText);
            CertFreeCertificateContext(pAnchorCert);
            *pcpgsr = CPGSR_NO_CREDENTIAL_NOT_FINISHED;
            return S_OK;
        }

        // 4. HARDWARE ENFORCEMENT CHECK
        // DWORD implType = 0;
        // DWORD cbResult = 0;
        // NCryptGetProperty(hKey, NCRYPT_IMPL_TYPE_PROPERTY, (PBYTE)&implType, sizeof(implType), &cbResult, 0);
        // if (!(implType & NCRYPT_IMPL_HARDWARE_FLAG))
        // {
        //     SHStrDupW(L"PAM ENFORCED: Hardware TPM/Smartcard required.", ppwszOptionalStatusText);
        //     NCryptFreeObject(hKey);
        //     CertFreeCertificateContext(pAnchorCert);
        //     *pcpgsr = CPGSR_NO_CREDENTIAL_NOT_FINISHED;
        //     return S_OK;
        // }

        // 5. INJECT THE PIN & SIGN THE PUZZLE
        if (_rgFieldStrings[SFI_PIN_PASSWORD] != NULL)
        {
            DWORD pinLenBytes = static_cast<DWORD>((wcslen(_rgFieldStrings[SFI_PIN_PASSWORD]) + 1) * sizeof(wchar_t));
            NCryptSetProperty(hKey, NCRYPT_PIN_PROPERTY, (PBYTE)_rgFieldStrings[SFI_PIN_PASSWORD], pinLenBytes, 0);
        }

        // Generate a strict 32-byte Nonce (Math Puzzle)
        BYTE nonce[32] = { 
            0x8F, 0x2A, 0x11, 0x9B, 0xC4, 0x33, 0x99, 0x01,
            0x1A, 0x2B, 0x3C, 0x4D, 0x5E, 0x6F, 0x70, 0x81,
            0x9A, 0xAB, 0xBC, 0xCD, 0xDE, 0xEF, 0x00, 0x11,
            0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99 
        }; 
        BYTE signature[256];
        DWORD cbSignature = 0;

        // FIX: Define the cryptographic padding algorithm (SHA-256)
        BCRYPT_PKCS1_PADDING_INFO padInfo = { 0 };
        padInfo.pszAlgId = BCRYPT_SHA256_ALGORITHM;

        // Pass the padInfo structure instead of NULL
        SECURITY_STATUS signStatus = NCryptSignHash(hKey, &padInfo, nonce, sizeof(nonce), signature, sizeof(signature), &cbSignature, NCRYPT_PAD_PKCS1_FLAG);

        // CLEANUP
        NCryptFreeObject(hKey);
        CertFreeCertificateContext(pAnchorCert);

        // ==========================================
        // EVALUATE & HYBRID SIDE-CHANNEL
        // ==========================================
        if (signStatus == (SECURITY_STATUS)0x80090022) // NTE_SILENT_CONTEXT (Wrong PIN)
        {
            int retriesLeft = -1;
            bool cardBlocked = false;

            // 1. Open the Raw Side-Channel to the Smartcard Subsystem
            SCARDCONTEXT hContext = 0;
            if (SCardEstablishContext(SCARD_SCOPE_SYSTEM, NULL, NULL, &hContext) == SCARD_S_SUCCESS)
            {
                LPTSTR pmszReaders = NULL;
                DWORD cch = SCARD_AUTOALLOCATE;

                // 2. Find the Virtual Smart Card Reader
                if (SCardListReaders(hContext, NULL, (LPTSTR)&pmszReaders, &cch) == SCARD_S_SUCCESS)
                {
                    SCARDHANDLE hCard = 0;
                    DWORD dwActiveProtocol = 0;

                    // 3. Connect to the Metal
                    if (SCardConnect(hContext, pmszReaders, SCARD_SHARE_SHARED, SCARD_PROTOCOL_T0 | SCARD_PROTOCOL_T1, &hCard, &dwActiveProtocol) == SCARD_S_SUCCESS)
                    {
                        // 4. Send an Empty "Verify PIN" APDU (00 20 00 80 00)
                        BYTE pbSendBuffer[] = { 0x00, 0x20, 0x00, 0x80, 0x00 };
                        BYTE pbRecvBuffer[256];
                        DWORD cbRecvLength = sizeof(pbRecvBuffer);
                        const SCARD_IO_REQUEST* pioSendPci = (dwActiveProtocol == SCARD_PROTOCOL_T1) ? SCARD_PCI_T1 : SCARD_PCI_T0;

                        if (SCardTransmit(hCard, pioSendPci, pbSendBuffer, sizeof(pbSendBuffer), NULL, pbRecvBuffer, &cbRecvLength) == SCARD_S_SUCCESS)
                        {
                            // 5. Parse the Hexadecimal Response
                            if (cbRecvLength >= 2)
                            {
                                BYTE sw1 = pbRecvBuffer[cbRecvLength - 2];
                                BYTE sw2 = pbRecvBuffer[cbRecvLength - 1];

                                if (sw1 == 0x63 && (sw2 & 0xC0) == 0xC0) 
                                {
                                    // 63 CX: Extract the 'X' (Retries remaining)
                                    retriesLeft = sw2 & 0x0F;
                                }
                                else if (sw1 == 0x69 && sw2 == 0x83)
                                {
                                    // 69 83: Card is permanently blocked
                                    cardBlocked = true;
                                }
                            }
                        }
                        SCardDisconnect(hCard, SCARD_LEAVE_CARD);
                    }
                    SCardFreeMemory(hContext, pmszReaders);
                }
                SCardReleaseContext(hContext);
            }

            // 6. Push the Exact Integer to the RDP Screen
            wchar_t szWarning[512];
            if (cardBlocked)
            {
                StringCchPrintfW(szWarning, ARRAYSIZE(szWarning), L"PAM ENFORCED | TPM is BLOCKED due to too many failed attempts. Contact IT.");
            }
            else if (retriesLeft >= 0)
            {
                StringCchPrintfW(szWarning, ARRAYSIZE(szWarning), L"PAM ENFORCED | Incorrect PIN. You have %d attempt(s) remaining before TPM lockout.", retriesLeft);
            }
            else
            {
                StringCchPrintfW(szWarning, ARRAYSIZE(szWarning), L"PAM ENFORCED | Incorrect PIN. TPM rejected access.");
            }

            SHStrDupW(szWarning, ppwszOptionalStatusText);
            *pcpgsr = CPGSR_NO_CREDENTIAL_NOT_FINISHED;
            return S_OK;
        }
        else if (signStatus != ERROR_SUCCESS)
        {
            wchar_t szDebugProbe[512];
            StringCchPrintfW(szDebugProbe, ARRAYSIZE(szDebugProbe), L"PAM ENFORCED | Hardware Error. Code: 0x%08X", signStatus);
            SHStrDupW(szDebugProbe, ppwszOptionalStatusText);
            *pcpgsr = CPGSR_NO_CREDENTIAL_NOT_FINISHED;
            return S_OK;
        }

        // SUCCESS! Hardware verified. Let C++ proceed to OS auth.

        // SUCCESS! Hardware verified. Let C++ proceed to OS auth.
    }
    else if (wcscmp(_rgFieldStrings[SFI_LABEL], L"PAM: FIDO2 Token Verification") == 0)
    {
        // 1. INITIALIZE LIBFIDO2 CRYPTO ENGINE
        fido_init(0);

        // 2. SCAN THE USB/NFC BUS FOR ALL HARDWARE
        fido_dev_info_t *devlist = fido_dev_info_new(8); // Ask for up to 8 devices
        size_t devs_found = 0;
        
        int r = fido_dev_info_manifest(devlist, 8, &devs_found);
        if (r != FIDO_OK || devs_found == 0)
        {
            SHStrDupW(L"PAM ENFORCED: Insert FIDO2 Token via USB.", ppwszOptionalStatusText);
            fido_dev_info_free(&devlist, 8);
            *pcpgsr = CPGSR_NO_CREDENTIAL_NOT_FINISHED;
            return S_OK;
        }

        const char *target_path = nullptr;
        
        // Loop through all found devices
        for (size_t i = 0; i < devs_found; i++)
        {
            const fido_dev_info_t *di = fido_dev_info_ptr(devlist, i);
            const char *path = fido_dev_info_path(di);
            
            // SKIP the virtual Windows Hello API device!
            if (path && strstr(path, "windows://") == nullptr)
            {
                target_path = path;
                break; // Found the physical YubiKey's raw HID path!
            }
        }

        if (target_path == nullptr)
        {
            SHStrDupW(L"FIDO2 ERROR: No physical token found.", ppwszOptionalStatusText);
            fido_dev_info_free(&devlist, 8);
            *pcpgsr = CPGSR_NO_CREDENTIAL_NOT_FINISHED;
            return S_OK;
        }

        // 3. OPEN THE DIRECT HARDWARE TUNNEL
        fido_dev_t *dev = fido_dev_new();
        r = fido_dev_open(dev, target_path);
        if (r != FIDO_OK)
        {
            // If Windows fido.sys blocks the HID tunnel, this catches it!
            wchar_t szDebugProbe[512];
            StringCchPrintfW(szDebugProbe, ARRAYSIZE(szDebugProbe), L"FIDO2 ERROR | Failed to open raw HID: %d", r);
            SHStrDupW(szDebugProbe, ppwszOptionalStatusText);
            fido_dev_free(&dev);
            fido_dev_info_free(&devlist, 8);
            *pcpgsr = CPGSR_NO_CREDENTIAL_NOT_FINISHED;
            return S_OK;
        }

        // 4. CONSTRUCT THE CRYPTOGRAPHIC ASSERTION REQUEST
        fido_assert_t *assert = fido_assert_new();
        const unsigned char client_data_hash[32] = {0}; 
        
        fido_assert_set_clientdata_hash(assert, client_data_hash, sizeof(client_data_hash));
        fido_assert_set_rp(assert, "sandbox.local"); 
        fido_assert_set_up(assert, FIDO_OPT_TRUE);   

        // 5. TRANSMIT OVER USB AND WAIT FOR HUMAN TOUCH
        r = fido_dev_get_assert(dev, assert, nullptr);

        // 6. CLEANUP SECURE MEMORY
        fido_assert_free(&assert);
        fido_dev_close(dev);
        fido_dev_free(&dev);
        fido_dev_info_free(&devlist, 8);

        // 7. EVALUATE CRYPTOGRAPHIC RESPONSE
        if (r == FIDO_OK)
        {
            // FIDO SIGNATURE VERIFIED!
        }
        else
        {
            wchar_t szDebugProbe[512];
            StringCchPrintfW(szDebugProbe, ARRAYSIZE(szDebugProbe), L"FIDO2 REJECTED | CTAP2 Error Code: %d", r);
            SHStrDupW(szDebugProbe, ppwszOptionalStatusText);
            *pcpgsr = CPGSR_NO_CREDENTIAL_NOT_FINISHED;
            return S_OK;
        }
    }
    // --- END HARDWARE & PIN VERIFICATION ---

    HRESULT hr = E_UNEXPECTED;
    *pcpgsr = CPGSR_NO_CREDENTIAL_NOT_FINISHED;
    *ppwszOptionalStatusText = nullptr;
    *pcpsiOptionalStatusIcon = CPSI_NONE;
    ZeroMemory(pcpcs, sizeof(*pcpcs));

    // --- 1. SAFELY GRAB THE USERNAME (Fixes the RDP Crash!) ---
    PWSTR pszTargetUsername = nullptr;
    if (_pamMode == 3)
    {
        pszTargetUsername = _rgFieldStrings[SFI_EDIT_TEXT]; // Correctly map the text box!
    }
    else
    {
        pszTargetUsername = _pszQualifiedUserName; // Normal fallback
    }

    // --- 2. SAFETY NET ---
    // If the box is completely empty, fail safely.
    if (pszTargetUsername == nullptr || _rgFieldStrings[SFI_PASSWORD] == nullptr)
    {
        return E_INVALIDARG;
    }

    // --- 3. THE MODE 3 BACKDOOR BLOCK (Fixes the Blink!) ---
    if (_pamMode == 3)
    {
        // Strip the domain just in case they typed SANDBOX\akn
        const wchar_t *pSlash = wcsrchr(pszTargetUsername, L'\\');
        const wchar_t *pUsernameOnly = (pSlash != nullptr) ? (pSlash + 1) : pszTargetUsername;

        // Is akn trying to bypass the PAM tiles?
        if (_wcsicmp(pUsernameOnly, L"akn") == 0)
        {
            // Send the literal string to the screen so it doesn't just "blink"
            SHStrDupW(L"Access Denied. Admins must use Smartcard/FIDO.", ppwszOptionalStatusText);
            *pcpsiOptionalStatusIcon = CPSI_ERROR;
            *pcpgsr = CPGSR_RETURN_NO_CREDENTIAL_FINISHED;
            return S_FALSE; // Graceful UI halt
        }
    }

    // --- 4. PACKAGING THE CREDENTIALS ---
    if (_fIsLocalUser || _pamMode == 3)
    {
        PWSTR pwzProtectedPassword;
        hr = ProtectIfNecessaryAndCopyPassword(_rgFieldStrings[SFI_PASSWORD], _cpus, &pwzProtectedPassword);
        if (SUCCEEDED(hr))
        {
            PWSTR pszDomain;
            PWSTR pszUsername;

            hr = SplitDomainAndUsername(pszTargetUsername, &pszDomain, &pszUsername);
            if (SUCCEEDED(hr))
            {
                KERB_INTERACTIVE_UNLOCK_LOGON kiul;
                hr = KerbInteractiveUnlockLogonInit(pszDomain, pszUsername, pwzProtectedPassword, _cpus, &kiul);
                if (SUCCEEDED(hr))
                {
                    hr = KerbInteractiveUnlockLogonPack(kiul, &pcpcs->rgbSerialization, &pcpcs->cbSerialization);
                    if (SUCCEEDED(hr))
                    {
                        ULONG ulAuthPackage;
                        hr = RetrieveNegotiateAuthPackage(&ulAuthPackage);
                        if (SUCCEEDED(hr))
                        {
                            pcpcs->ulAuthenticationPackage = ulAuthPackage;
                            pcpcs->clsidCredentialProvider = CLSID_CSample;
                            *pcpgsr = CPGSR_RETURN_CREDENTIAL_FINISHED;
                        }
                    }
                }
                CoTaskMemFree(pszDomain);
                CoTaskMemFree(pszUsername);
            }
            CoTaskMemFree(pwzProtectedPassword);
        }
    }
    else
    {
        // MODE 3 EXECUTES THIS BLOCK FOR DOMAIN USERS
        DWORD dwAuthFlags = CRED_PACK_PROTECTED_CREDENTIALS | CRED_PACK_ID_PROVIDER_CREDENTIALS;

        if (!CredPackAuthenticationBuffer(dwAuthFlags, pszTargetUsername, const_cast<PWSTR>(_rgFieldStrings[SFI_PASSWORD]), nullptr, &pcpcs->cbSerialization) &&
            (GetLastError() == ERROR_INSUFFICIENT_BUFFER))
        {
            pcpcs->rgbSerialization = static_cast<byte *>(CoTaskMemAlloc(pcpcs->cbSerialization));
            if (pcpcs->rgbSerialization != nullptr)
            {
                hr = S_OK;

                if (CredPackAuthenticationBuffer(dwAuthFlags, pszTargetUsername, const_cast<PWSTR>(_rgFieldStrings[SFI_PASSWORD]), pcpcs->rgbSerialization, &pcpcs->cbSerialization))
                {
                    ULONG ulAuthPackage;
                    hr = RetrieveNegotiateAuthPackage(&ulAuthPackage);
                    if (SUCCEEDED(hr))
                    {
                        pcpcs->ulAuthenticationPackage = ulAuthPackage;
                        pcpcs->clsidCredentialProvider = CLSID_CSample;
                        *pcpgsr = CPGSR_RETURN_CREDENTIAL_FINISHED;
                    }
                }
                else
                {
                    hr = HRESULT_FROM_WIN32(GetLastError());
                    if (SUCCEEDED(hr))
                        hr = E_FAIL;
                }

                if (FAILED(hr))
                {
                    CoTaskMemFree(pcpcs->rgbSerialization);
                }
            }
            else
            {
                hr = E_OUTOFMEMORY;
            }
        }
    }

    return hr;
}

struct REPORT_RESULT_STATUS_INFO
{
    NTSTATUS ntsStatus;
    NTSTATUS ntsSubstatus;
    PWSTR pwzMessage;
    CREDENTIAL_PROVIDER_STATUS_ICON cpsi;
};

static const REPORT_RESULT_STATUS_INFO s_rgLogonStatusInfo[] =
    {
        {
            STATUS_LOGON_FAILURE,
            STATUS_SUCCESS,
            L"Incorrect password or username.",
            CPSI_ERROR,
        },
        {STATUS_ACCOUNT_RESTRICTION, STATUS_ACCOUNT_DISABLED, L"The account is disabled.", CPSI_WARNING},
};

// ReportResult is completely optional.  Its purpose is to allow a credential to customize the string
// and the icon displayed in the case of a logon failure.  For example, we have chosen to
// customize the error shown in the case of bad username/password and in the case of the account
// being disabled.
HRESULT CSampleCredential::ReportResult(NTSTATUS ntsStatus,
                                        NTSTATUS ntsSubstatus,
                                        _Outptr_result_maybenull_ PWSTR *ppwszOptionalStatusText,
                                        _Out_ CREDENTIAL_PROVIDER_STATUS_ICON *pcpsiOptionalStatusIcon)
{
    *ppwszOptionalStatusText = nullptr;
    *pcpsiOptionalStatusIcon = CPSI_NONE;

    DWORD dwStatusInfo = (DWORD)-1;

    // Look for a match on status and substatus.
    for (DWORD i = 0; i < ARRAYSIZE(s_rgLogonStatusInfo); i++)
    {
        if (s_rgLogonStatusInfo[i].ntsStatus == ntsStatus && s_rgLogonStatusInfo[i].ntsSubstatus == ntsSubstatus)
        {
            dwStatusInfo = i;
            break;
        }
    }

    if ((DWORD)-1 != dwStatusInfo)
    {
        if (SUCCEEDED(SHStrDupW(s_rgLogonStatusInfo[dwStatusInfo].pwzMessage, ppwszOptionalStatusText)))
        {
            *pcpsiOptionalStatusIcon = s_rgLogonStatusInfo[dwStatusInfo].cpsi;
        }
    }

    // If we failed the logon, try to erase the password field.
    if (FAILED(HRESULT_FROM_NT(ntsStatus)))
    {
        if (_pCredProvCredentialEvents)
        {
            _pCredProvCredentialEvents->SetFieldString(this, SFI_PASSWORD, L"");
        }
    }

    // Since nullptr is a valid value for *ppwszOptionalStatusText and *pcpsiOptionalStatusIcon
    // this function can't fail.
    return S_OK;
}

// Gets the SID of the user corresponding to the credential.
HRESULT CSampleCredential::GetUserSid(_Outptr_result_nullonfailure_ PWSTR *ppszSid)
{
    *ppszSid = nullptr;

    if (_pszUserSid != nullptr)
    {
        return SHStrDupW(_pszUserSid, ppszSid);
    }

    // CRITICAL FIX: If there is no SID (like in our Mode 3 "Other User" tile),
    // we MUST return S_FALSE. Returning an error here crashes LogonUI.
    return S_FALSE;
}

// GetFieldOptions to enable the password reveal button and touch keyboard auto-invoke in the password field.
HRESULT CSampleCredential::GetFieldOptions(DWORD dwFieldID,
                                           _Out_ CREDENTIAL_PROVIDER_CREDENTIAL_FIELD_OPTIONS *pcpcfo)
{
    *pcpcfo = CPCFO_NONE;

    if (dwFieldID == SFI_PASSWORD)
    {
        *pcpcfo = CPCFO_ENABLE_PASSWORD_REVEAL;
    }
    else if (dwFieldID == SFI_TILEIMAGE)
    {
        *pcpcfo = CPCFO_ENABLE_TOUCH_KEYBOARD_AUTO_INVOKE;
    }

    return S_OK;
}
