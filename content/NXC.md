---
title: "NetExec (nxc)"
tags: ["Active Directory", "NetExec (nxc)", "Brute Force", "Crackmapexec", "Domain Controller", "Enumeration", "Ldap", "Ldap Search", "Nxc", "Rid", "Smb", "Windows", "Winrm"]
---

#### General

{{< tab set1 tab1 >}}Password{{< /tab >}}
{{< tab set1 tab2 >}}NTLM{{< /tab >}}
{{< tab set1 tab3 >}}Kerberos{{< /tab >}}
{{< tabcontent set1 tab1 >}}

```console
# Single user, Single password
nxc <PROTOCOL> <TARGET> -u '<USER>' -p '<PASSWORD>'
```

```console
# Single user, Single password, Local auth
nxc <PROTOCOL> <TARGET> -u '<USER>' -p '<PASSWORD>' --local-auth
```

```console
# Single user, Single password (Active Directory)
nxc <PROTOCOL> <TARGET> -u '<USER>' -p '<PASSWORD>' -d <DOMAIN>
```

```console
# Single user, Multiple passwords
nxc <PROTOCOL> <TARGET> -u '<USER>' -p <PASSWORDS> -d <DOMAIN>
```

```console
# Multiple users, Single password
nxc <PROTOCOL> <TARGET> -u <USERS> -p '<PASSWORD>' -d <DOMAIN> --continue-on-success
```

```console
# Multiple users, Multiple passwords
nxc <PROTOCOL> <TARGET> -u <USERS> -p <PASSWORDS> -d <DOMAIN> --continue-on-success
```

```console
# Match username to corresponding password
nxc <PROTOCOL> <TARGET> -u <USERS> -p <PASSWORDS> --no-bruteforce --continue-on-success
```

{{< /tabcontent >}}
{{< tabcontent set1 tab2 >}}

```console
# NTLM
nxc <PROTOCOL> <TARGET> -u '<USER>' -H <HASH> -d <DOMAIN>
```

{{< /tabcontent >}}
{{< tabcontent set1 tab3 >}}

```console
# Password-based Kerberos
sudo ntpdate -s <DC_IP> && nxc <PROTOCOL> <TARGET> -u '<USER>' -p '<PASSWORD>' -d <DOMAIN> -k --kdcHost <DC>
```

```console
# NTLM-based Kerberos
sudo ntpdate -s <DC_IP> && nxc <PROTOCOL> <TARGET> -u '<USER>' -H <HASH> -d <DOMAIN> -k --kdcHost <DC>
```

```console
# Ticket-based Kerberos
sudo ntpdate -s <DC_IP> && nxc <PROTOCOL> <TARGET> -u '<USER>' -d <DOMAIN> -k --kdcHost <DC> --use-kcache
```

{{< /tabcontent >}}

<small>*Hint: We can also run on multiple targets*</small>

#### Available Protocols

```
+----------------------------------------------------------------+
| ftp | wim | vnc | winrm | mssql | ldap | smb | rdp | nfs | ssh |
+----------------------------------------------------------------+
```

<br>

---

#### Users Enum - Anonymous

{{< tab set2 tab1 >}}NULL{{< /tab >}}
{{< tab set2 tab2 >}}RID Brute{{< /tab >}}
{{< tabcontent set2 tab1 >}}

```console
nxc smb <TARGET> -u '' -p '' -d <DOMAIN> --users
```

{{< /tabcontent >}}
{{< tabcontent set2 tab2 >}}

```console
nxc smb <TARGET> -u guest -p '' --rid-brute 10000
```

{{< /tabcontent >}}

#### Users Enum - Authenticated

{{< tab set3 tab1 >}}Password{{< /tab >}}
{{< tab set3 tab2 >}}NTLM{{< /tab >}}
{{< tab set3 tab3 >}}Kerberos{{< /tab >}}
{{< tabcontent set3 tab1 >}}

```console
# Password
nxc smb <TARGET> -u '<USER>' -p '<PASSWORD>' -d <DOMAIN> --users
```

{{< /tabcontent >}}
{{< tabcontent set3 tab2 >}}

```console
# NTLM
nxc smb <TARGET> -u '<USER>' -H <HASH> -d <DOMAIN> --users
```

{{< /tabcontent >}}
{{< tabcontent set3 tab3 >}}

```console
# Password-based Kerberos
nxc smb <TARGET> -u '<USER>' -p '<PASSWORD>' -d <DOMAIN> -k --kdcHost <DC> --users
```

```console
# NTLM-based Kerberos
nxc smb <TARGET> -u '<USER>' -H <HASH> -d <DOMAIN> -k --kdcHost <DC> --use-kcache --users
```

```console
# Ticket-based Kerberos
nxc smb <TARGET> -u '<USER>' -d <DOMAIN> -k --kdcHost <DC> --use-kcache --users
```

{{< /tabcontent >}}


<small>*Ref: [nxc wiki](https://www.netexec.wiki/)*</small>
