---
title: "AD Recycle Bin"
tags: ["Active Directory", "AD Recycle Bin", "Deleted Objects", "Domain Controller", "Object Recovery", "PowerShell", "Privilege Escalation", "Restore", "Windows"]
---

{{< filter_buttons >}}

### Restore Deleted AD Object

{{< tab set1 tab1 >}}Windows{{< /tab >}}
{{< tabcontent set1 tab1 >}}

#### 1. Import AD Module

```console
Import-Module ActiveDirectory
```

```console {class="sample-code"}
evil-winrm-py PS C:\> Import-Module ActiveDirectory
```

#### 2. Query All Deleted Objects within Domain

```console
Get-ADObject -filter 'isDeleted -eq $true -and name -ne "Deleted Objects"' -includeDeletedObjects
```

```console {class="sample-code"}
evil-winrm-py PS C:\> Get-ADObject -filter 'isDeleted -eq $true -and name -ne "Deleted Objects"' -includeDeletedObjects


Deleted           : True
DistinguishedName : CN=cert_admin\0ADEL:f80369c8-96a2-4a7f-a56c-9c15edd7d1e3,CN=Deleted Objects,DC=tombwatcher,DC=htb
Name              : cert_admin
                    DEL:f80369c8-96a2-4a7f-a56c-9c15edd7d1e3
ObjectClass       : user
ObjectGUID        : f80369c8-96a2-4a7f-a56c-9c15edd7d1e3

Deleted           : True
DistinguishedName : CN=cert_admin\0ADEL:c1f1f0fe-df9c-494c-bf05-0679e181b358,CN=Deleted Objects,DC=tombwatcher,DC=htb
Name              : cert_admin
                    DEL:c1f1f0fe-df9c-494c-bf05-0679e181b358
ObjectClass       : user
ObjectGUID        : c1f1f0fe-df9c-494c-bf05-0679e181b358

Deleted           : True
DistinguishedName : CN=cert_admin\0ADEL:938182c3-bf0b-410a-9aaa-45c8e1a02ebf,CN=Deleted Objects,DC=tombwatcher,DC=htb
Name              : cert_admin
                    DEL:938182c3-bf0b-410a-9aaa-45c8e1a02ebf
ObjectClass       : user
ObjectGUID        : 938182c3-bf0b-410a-9aaa-45c8e1a02ebf
```

#### 3. Get All Details for the Deleted Object

```console
Get-ADObject -filter { SAMAccountName -eq '<DELETED_USER>' } -includeDeletedObjects -property *
```

```console {class="sample-code"}
evil-winrm-py PS C:\> Get-ADObject -filter { SAMAccountName -eq 'cert_admin' } -includeDeletedObjects -property *


accountExpires                  : 9223372036854775807
badPasswordTime                 : 0
badPwdCount                     : 0
CanonicalName                   : tombwatcher.htb/Deleted Objects/cert_admin
                                  DEL:f80369c8-96a2-4a7f-a56c-9c15edd7d1e3
CN                              : cert_admin
                                  DEL:f80369c8-96a2-4a7f-a56c-9c15edd7d1e3
codePage                        : 0
countryCode                     : 0
Created                         : 11/15/2024 7:55:59 PM
createTimeStamp                 : 11/15/2024 7:55:59 PM
Deleted                         : True
Description                     : 
DisplayName                     : 
DistinguishedName               : CN=cert_admin\0ADEL:f80369c8-96a2-4a7f-a56c-9c15edd7d1e3,CN=Deleted 
                                  Objects,DC=tombwatcher,DC=htb
dSCorePropagationData           : {11/15/2024 7:56:05 PM, 11/15/2024 7:56:02 PM, 12/31/1600 7:00:01 PM}
givenName                       : cert_admin
instanceType                    : 4
isDeleted                       : True
LastKnownParent                 : OU=ADCS,DC=tombwatcher,DC=htb
lastLogoff                      : 0
lastLogon                       : 0
logonCount                      : 0
Modified                        : 11/15/2024 7:57:59 PM
modifyTimeStamp                 : 11/15/2024 7:57:59 PM
msDS-LastKnownRDN               : cert_admin
Name                            : cert_admin
                                  DEL:f80369c8-96a2-4a7f-a56c-9c15edd7d1e3
nTSecurityDescriptor            : System.DirectoryServices.ActiveDirectorySecurity
ObjectCategory                  : 
ObjectClass                     : user
ObjectGUID                      : f80369c8-96a2-4a7f-a56c-9c15edd7d1e3
objectSid                       : S-1-5-21-1392491010-1358638721-2126982587-1109
primaryGroupID                  : 513
ProtectedFromAccidentalDeletion : False
pwdLastSet                      : 133761921597856970
sAMAccountName                  : cert_admin
sDRightsEffective               : 7
sn                              : cert_admin
userAccountControl              : 66048
uSNChanged                      : 12975
uSNCreated                      : 12844
whenChanged                     : 11/15/2024 7:57:59 PM
whenCreated                     : 11/15/2024 7:55:59 PM

---[SNIP]---
```

#### 4. Restore the Deleted Object

```console
# Rename the target account to avoid user exists error
Restore-ADObject -Identity <OBJECT_GUID> -NewName '<DELETED_USER>.2' -TargetPath 'CN=Users,DC=<EXAMPLE>,DC=<COM>'
```

```console {class="sample-code"}
*Evil-WinRM* PS C:\Users\test.user\Documents> Restore-ADObject -Identity ebe15df5-e265-45ec-b7fc-359877217138 -NewName 'Another User2' -TargetPath 'CN=Users,DC=EXAMPLE,DC=COM'
```

```console
# Or
Restore-ADObject -Identity "<DISTINGUISHED_NAME>"
```

```console {class="sample-code"}
evil-winrm-py PS C:\> Restore-ADObject -Identity "CN=cert_admin\0ADEL:f80369c8-96a2-4a7f-a56c-9c15edd7d1e3,CN=Deleted Objects,DC=tombwatcher,DC=htb"
```

#### 5. Check

```console
net user <DELETED_USER>
```

```console {class="sample-code"}
evil-winrm-py PS C:\> net user cert_admin
User name                    cert_admin
Full Name                    
Comment                      
User's comment               
Country/region code          000 (System Default)
Account active               Yes
Account expires              Never

Password last set            11/15/2024 8:55:59 PM
Password expires             Never
Password changeable          11/15/2024 8:55:59 PM
Password required            Yes
User may change password     Yes

Workstations allowed         All
Logon script                 
User profile                 
Home directory               
Last logon                   Never

Logon hours allowed          All

Local Group Memberships      
Global Group memberships     *Domain Users         
The command completed successfully.
```

{{< /tabcontent >}}
