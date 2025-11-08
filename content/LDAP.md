---
title: "LDAP"
tags: ["Active Directory", "LDAP", "Enumeration", "Kerberos", "Ldap", "Ldap Search", "Nmap", "Nxc", "Permissions", "Windows", "ldapmodify", "ldif"]
---

{{< filter_buttons >}}

### Enumeration

{{< tab set1 tab1 >}}ldapsearch{{< /tab >}}
{{< tab set1 tab2 >}}ldapdomaindump{{< /tab >}}
{{< tab set1 tab3 >}}nxc{{< /tab >}}
{{< tab set1 tab4 >}}nmap{{< /tab >}}
{{< tabcontent set1 tab1 >}}

#### General

```console
# Get domain base
ldapsearch -x -H ldap://<TARGET> -s base namingcontexts
```

```console
# Get everything
ldapsearch -x -H ldap://<TARGET> -b 'DC=<EXAMPLE>,DC=<COM>'
```

```console
# Get a class
ldapsearch -x -H ldap://<TARGET> -b 'DC=<EXAMPLE>,DC=<COM>' '(objectClass=<CLASS>)'
```

#### LDAP Bind

{{< tab set1-1 tab1 active>}}Password{{< /tab >}}{{< tab set1-1 tab2 >}}Kerberos{{< /tab >}}
{{< tabcontent set1-1 tab1 >}}

```console
# Password
ldapsearch -x -H ldap://<TARGET> -D "CN=<USER>,CN=Users,DC=<EXAMPLE>,DC=<COM>" -w '<PASSWORD>' -b 'DC=<EXAMPLE>,DC=<COM>'
```

```console
# Fix 'BindSimple: Transport encryption required.'
LDAPTLS_REQCERT=never ldapsearch -x -H ldaps://<TARGET> -D "CN=<USER>,CN=Users,DC=<EXAMPLE>,DC=<COM>" -w '<PASSWORD>' -b 'DC=<EXAMPLE>,DC=<COM>'
```

{{< /tabcontent >}}
{{< tabcontent set1-1 tab2 >}}

#### 1. Installation

```console
sudo apt install libsasl2-modules-gssapi-mit
```

#### 2. Ldapsearch with Kerberos

```console
# Ticket-based Kerberos
ldapsearch -H ldap://<TARGET> -Y GSSAPI -b 'DC=<EXAMPLE>,DC=<COM>'
```

{{< /tabcontent >}}
{{< /tabcontent >}}
{{< tabcontent set1 tab2 >}}

```console {class="password"}
# Password
ldapdomaindump -u '<DOMAIN>\<USER>' -p '<PASSWORD>' <TARGET> -o ./ldap
```

```console {class="ntlm"}
# NTLM
ldapdomaindump -u '<DOMAIN>\<USER>' -p ':<HASH>' <TARGET> -o ./ldap
```

{{< /tabcontent >}}
{{< tabcontent set1 tab3 >}}

```console {class="password"}
# Password
nxc ldap <TARGET> -u '<USER>' -p '<PASSWORD>' -d <DOMAIN> --users
```

```console {class="ntlm"}
# NTLM
nxc ldap <TARGET> -u '<USER>' -H '<HASH>' -d <DOMAIN> --users
```

```console {class="password-based-kerberos"}
# Password-based Kerberos
nxc ldap <TARGET> -u '<USER>' -p '<PASSWORD>' -d <DOMAIN> -k --kdcHost <DC> --users
```

```console {class="ntlm-based-kerberos"}
# NTLM-based Kerberos
nxc ldap <TARGET> -u '<USER>' -H '<HASH>' -d <DOMAIN> -k --kdcHost <DC> --users
```

```console {class="ticket-based-kerberos"}
# Ticket-based Kerberos
nxc ldap <TARGET> -u '<USER>' -d <DOMAIN> -k --use-kcache --kdcHost <DC> --users
```

{{< /tabcontent >}}
{{< tabcontent set1 tab4 >}}

```console
sudo nmap -p 389 --script ldap-search <TARGET>
```

{{< /tabcontent >}}

---

### Enum ACLs

{{< tab set3 tab1 >}}bloodyAD{{< /tab >}}
{{< tabcontent set3 tab1 >}}

```console {class="password"}
# Password
bloodyAD -d '<DOMAIN>' -u '<USER>' -p '<PASSWORD>' --host '<TARGET>' get writable --detail
```

```console {class="ntlm"}
# NTLM
bloodyAD -d '<DOMAIN>' -u '<USER>' -p ':<HASH>' -f rc4 --host '<TARGET>' get writable --detail
```

```console {class="password-based-kerberos"}
# Password-based Kerberos
bloodyAD -d '<DOMAIN>' -u '<USER>' -p '<PASSWORD>' -k --host '<TARGET>' get writable --detail
```

```console {class="ntlm-based-kerberos"}
# NTLM-based Kerberos
bloodyAD -d '<DOMAIN>' -u '<USER>' -p '<HASH>' -f rc4 -k --host '<TARGET>' get writable --detail
```

```console {class="ticket-based-kerberos"}
# Ticket-based Kerberos
bloodyAD -d '<DOMAIN>' -u '<USER>' -k --host '<TARGET>' get writable --detail
```

{{< /tabcontent >}}

---

### Modify Entries

#### 1. Create a LDIF File

```console
dn: <DN>
changetype: modify
replace: <KEY>
<KEY>: <VALUE>
-
add: <KEY_1>
<KEY_1>: <VALUE_1>
```

```console {class="sample-code"}
dn: cn=John Doe,ou=People,dc=example,dc=com
changetype: modify
replace: logonHours
logonHours:: ////////////////////////////
-
```

#### 2. Modify Entries

```console {class="password"}
# Password
ldapmodify -x -D '<USER>@<DOMAIN>' -w '<PASSWORD>' -H ldap://<TARGET> -f <LDIF_FILE>
```

```console {class="sample-code"}
$ ldapmodify -x -D 'john.doe@example.com' -w 'password1' -H ldap://DC01.EXAMPLE.COM -f set_logonhours.ldif
modifying entry "CN=John Doe,OU=People,DC=example,DC=com"
```

```console {class="ticket-based-kerberos"}
# Ticket-based Kerberos
ldapmodify -x -D '<USER>@<DOMAIN>' -Y GSSAPI -H ldap://<TARGET> -f <LDIF_FILE>
```

#### Template: Move an Entry to New OU

```console
dn: <DN>
changetype: modrdn
newrdn: CN=<CN>
deleteoldrdn: 1
newsuperior: <OU>
```

```console {class="sample-code"}
dn: CN=Apple Seed,OU=Department A,OU=DCEXAMPLE,DC=example,DC=com
changetype: modrdn
newrdn: CN=Apple Seed
deleteoldrdn: 1
newsuperior: OU=Department B,OU=DCEXAMPLE,DC=example,DC=htb
```