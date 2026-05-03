# Windows-Credential-PAM: Hardware-Enforced RDP Credential Provider

**Windows-Credential-PAM** is a custom, enterprise-grade C++ Windows Credential Provider designed to enforce strict, hardware-backed identity verification over Remote Desktop Protocol (RDP) tunnels.

By replacing the native Windows Lock Screen authentication flow, this module prevents credential stuffing and password-based attacks by demanding a cryptographic signature from a physical (or TPM-backed) Smartcard before releasing Active Directory credentials to the Domain Controller.

## 🏗️ Architecture Overview

This project bypasses the standard Windows authentication flow and implements a 4-Pillar Zero-Trust Cryptographic Handshake:

1.  **The Bouncer (Tile Assassination):** A custom `ICredentialProviderFilter` intercepts the `LogonUI.exe` boot sequence and programmatically terminates the native Microsoft Password Provider (`60b78e88-ead8-445c-9cfd-0b87f74ea6cd`).
    
2.  **The Anchor (Source of Truth):** The server loads a pre-registered Public Key certificate (`.cer`) from its local secure storage.
    
3.  **The Hardware Handshake (CNG over RDP):** Using the Windows Cryptography API: Next Generation (`NCrypt.dll`), the lock screen generates a 32-byte SHA-256 mathematical puzzle (Nonce) and tunnels it over RDP to the user's local hardware TPM/Smartcard.
    
4.  **Hybrid Side-Channel Diagnostics:** If the hardware rejects the PIN, the code dynamically spins up a raw `winscard.lib` APDU side-channel (`00 20 00 80 00`) to interrogate the silicon, extracting and displaying the exact number of retry attempts remaining before the chip permanently bricks itself.
    

## ⚠️ Configuration: Mandatory Variables

Before compiling this project, you **must** update the source code to match your specific cryptographic identity and server environment.

Open `CSampleCredential.cpp` and modify the following values:

-   **The Subject Name (Your ID Badge):** Search for the `CertFindCertificateInStore` function. Change the `L"YOUR_USERNAME_HERE"` parameter to match the Common Name (CN) of your smartcard certificate (e.g., `L"akn"`).
    
-   **The Server Anchor Path:** Search for the `CreateFileW` function. Change `L"C:\\Server_Anchor_Key.cer"` to the exact path where you plan to store the exported Public Key on your Windows Server.(the .cer file in the project is named "AKN_Registered_Key.cer", so modify that according to your .cer file name) 
    

## 🛠️ Hardware Setup Guide (TPM Virtual Smart Card)

If you do not have a physical YubiKey, you can provision your laptop's TPM to act as a Virtual Smart Card (VSC). Run these commands in an **Administrator PowerShell** window on your _client_ machine (not the server).

**1\. Initialize the Hardware Silicon**

PowerShell

    tpmvscmgr.exe create /name "Enterprise_TPM_VSC" /pin prompt /pinpolicy minlen 4 /adminkey random /generate

**2\. Mint the Cryptographic Identity** _(Change `CN=YOUR_USERNAME_HERE` to match your actual username)_

PowerShell

    New-SelfSignedCertificate -Subject "CN=YOUR_USERNAME_HERE" -Provider "Microsoft Smart Card Key Storage Provider" -KeyAlgorithm RSA -KeyLength 2048 -CertStoreLocation "Cert:\CurrentUser\My"

**3\. Export the Server Anchor (Public Key)** _(This extracts the mathematical ID badge without compromising the Private Key)_

PowerShell

    Get-ChildItem -Path "Cert:\CurrentUser\My" | Where-Object {$_.Subject -match "CN=YOUR_USERNAME_HERE"} | Export-Certificate -FilePath "C:\Server_Anchor_Key.cer"

**Crucial:** Copy the resulting `Server_Anchor_Key.cer` file to your server and place it in the exact path you defined in `CSampleCredential.cpp`.

## ⚙️ Build & Compilation Instructions (SDK Injection Method)

To keep this repository lightweight, this project is designed to be injected directly into the official Microsoft Windows Classic Samples SDK.

**Step 1: Install Prerequisites** Ensure you have **Microsoft Visual Studio Build Tools** installed. You must include the "Desktop development with C++" workload and the Windows 11 (or Windows 10) SDK.

**Step 2: Download the Official Base SDK**

1.  Navigate to the official Microsoft repository: [Windows-classic-samples](https://github.com/microsoft/Windows-classic-samples).
    
2.  Download the repository as a ZIP and extract it to your local machine.
    
3.  Locate the target directory: `Windows-classic-samples-main\Samples\CredentialProvider\cpp`.
    

**Step 3: Inject the Custom Architecture**

1.  Clone this `Windows-Credential-PAM` repository to your machine.
    
2.  Copy all files from this repository (`.cpp`, `.h`, `.vcxproj`, `.reg`, etc.).
    
3.  Paste them into the SDK's `cpp` folder from Step 2, **overwriting** the original Microsoft sample files when prompted.
    

**Step 4: Compile the DLL**

1.  Open your Windows Start Menu and launch the **Developer Command Prompt for VS**.
    
2.  Navigate to the `cpp` folder where you injected the code:
    
    DOS
    
        cd C:\Path\To\Windows-classic-samples-main\Samples\CredentialProvider\cpp
    
3.  Run the MSBuild compiler to generate the 64-bit payload:
    
    DOS
    
        msbuild SampleV2CredentialProvider.sln /p:Configuration=Release /p:Platform=x64
    

Your compiled payload will be located at `x64\Release\SampleV2CredentialProvider.dll`.

## 🚀 Deployment & Installation

_Warning: Test this in a Virtual Machine Sandbox before deploying to a production Domain Controller. Misconfiguring a Credential Provider Filter can lock you out of your server._

1.  Copy your newly compiled `SampleV2CredentialProvider.dll` to your server's `C:\Windows\System32` directory.
    
2.  Ensure your `Server_Anchor_Key.cer` is sitting in the correct path on the server.
    
3.  Double-click `Register.reg` to inject the DLL into the Local Security Authority (LSA) subsystem.
    
4.  Lock the server (`Ctrl+Alt+Delete` -> Lock).
    

**To Update the Code:** Windows places a strict file-lock on Credential Providers while they are active. To replace the `.dll`, you must first run `Unregister.reg`, overwrite the file in `System32`, and then run `Register.reg` again.

## 📡 RDP Prerequisites

For the RDP hardware tunnel to function properly, the client connecting to the server must allow Smartcard redirection.

-   Open `mstsc.exe` -> **Show Options** -> **Local Resources** tab -> **More...**
    
-   Ensure **Smart cards or other Windows Hello for Business devices** is checked before connecting.
