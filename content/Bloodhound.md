---
title: "Bloodhound"
tags: ["Active Directory", "Bloodhound", "DNS", "Enumeration", "LDAP", "Neo4J", "Sharphound", "Sliver", "Windows", "dnschef", "ldapsearch"]
---

{{< filter_buttons >}}

### Info Collection

{{< tab set1 tab1 >}}Linux{{< /tab >}}
{{< tab set1 tab2 >}}Windows{{< /tab >}}
{{< tab set1 tab3 >}}C2{{< /tab >}}
{{< tabcontent set1 tab1 >}}
{{< tab set1-1 tab1 active>}}bloodhound-ce-python{{< /tab >}}{{< tab set1-1 tab2 >}}nxc{{< /tab >}}{{< tab set1-1 tab3 >}}ldapsearch{{< /tab >}}
{{< tabcontent set1-1 tab1 >}}

```console {class="password"}
# Password
bloodhound-ce-python -d <DOMAIN> -u '<USER>' -p '<PASSWORD>' -dc <DC> -ns <DC_IP> -c all --zip
```

```console {class="sample-code"}
$ bloodhound-ce-python -d FLUFFY.HTB -u 'j.fleischman' -p 'J0elTHEM4n1990!' -dc DC01.FLUFFY.HTB -ns 10.129.232.88 -c all --zip
INFO: BloodHound.py for BloodHound Community Edition
INFO: Found AD domain: fluffy.htb
INFO: Getting TGT for user
INFO: Connecting to LDAP server: DC01.FLUFFY.HTB
INFO: Testing resolved hostname connectivity dead:beef::1189:4e5a:9825:1144
INFO: Trying LDAP connection to dead:beef::1189:4e5a:9825:1144
INFO: Found 1 domains
INFO: Found 1 domains in the forest
INFO: Found 1 computers
INFO: Connecting to LDAP server: DC01.FLUFFY.HTB
INFO: Testing resolved hostname connectivity dead:beef::1189:4e5a:9825:1144
INFO: Trying LDAP connection to dead:beef::1189:4e5a:9825:1144
INFO: Found 10 users
INFO: Found 54 groups
INFO: Found 2 gpos
INFO: Found 1 ous
INFO: Found 19 containers
INFO: Found 0 trusts
INFO: Starting computer enumeration with 10 workers
INFO: Querying computer: DC01.fluffy.htb
INFO: Done in 00M 15S
INFO: Compressing output into 20251101143219_bloodhound.zip
```

```console {class="ntlm"}
# NTLM
bloodhound-ce-python -d <DOMAIN> -u '<USER>' --hashes ':<HASH>' -dc <DC> -ns <DC_IP> -c all --zip
```

```console {class="sample-code"}
$ bloodhound-ce-python -d FLUFFY.HTB -u 'j.fleischman' --hashes ':10842EAD8D1D060A2DE1394E4B2EA460' -dc DC01.FLUFFY.HTB -ns 10.129.232.88 -c all --zip
INFO: BloodHound.py for BloodHound Community Edition
INFO: Found AD domain: fluffy.htb
INFO: Getting TGT for user
INFO: Connecting to LDAP server: DC01.FLUFFY.HTB
INFO: Testing resolved hostname connectivity dead:beef::1189:4e5a:9825:1144
INFO: Trying LDAP connection to dead:beef::1189:4e5a:9825:1144
INFO: Found 1 domains
INFO: Found 1 domains in the forest
INFO: Found 1 computers
INFO: Connecting to LDAP server: DC01.FLUFFY.HTB
INFO: Testing resolved hostname connectivity dead:beef::1189:4e5a:9825:1144
INFO: Trying LDAP connection to dead:beef::1189:4e5a:9825:1144
INFO: Found 10 users
INFO: Found 54 groups
INFO: Found 2 gpos
INFO: Found 1 ous
INFO: Found 19 containers
INFO: Found 0 trusts
INFO: Starting computer enumeration with 10 workers
INFO: Querying computer: DC01.fluffy.htb
INFO: Done in 00M 10S
INFO: Compressing output into 20251101144755_bloodhound.zip
```

```console {class="password-based-kerberos"}
# Password-based Kerberos
sudo ntpdate -s <DC_IP> && bloodhound-ce-python -d <DOMAIN> -u '<USER>' -p '<PASSWORD>' -k -dc <DC> -ns <DC_IP> -c all --zip --use-ldaps
```

```console {class="sample-code"}
$ sudo ntpdate -s 10.129.232.88 && bloodhound-ce-python -d FLUFFY.HTB -u 'j.fleischman' -p 'J0elTHEM4n1990!' -k -dc DC01.FLUFFY.HTB -ns 10.129.232.88 -c all --zip --use-ldaps
INFO: BloodHound.py for BloodHound Community Edition
INFO: Found AD domain: fluffy.htb
INFO: Getting TGT for user
INFO: Connecting to LDAP server: DC01.FLUFFY.HTB
INFO: Testing resolved hostname connectivity dead:beef::1189:4e5a:9825:1144
INFO: Trying LDAP connection to dead:beef::1189:4e5a:9825:1144
INFO: Found 1 domains
INFO: Found 1 domains in the forest
INFO: Found 1 computers
INFO: Connecting to LDAP server: DC01.FLUFFY.HTB
INFO: Testing resolved hostname connectivity dead:beef::1189:4e5a:9825:1144
INFO: Trying LDAP connection to dead:beef::1189:4e5a:9825:1144
INFO: Found 10 users
INFO: Found 54 groups
INFO: Found 2 gpos
INFO: Found 1 ous
INFO: Found 19 containers
INFO: Found 0 trusts
INFO: Starting computer enumeration with 10 workers
INFO: Querying computer: DC01.fluffy.htb
INFO: Done in 00M 12S
INFO: Compressing output into 20251101145319_bloodhound.zip
```

```console {class="ntlm-based-kerberos"}
# NTLM-based Kerberos
sudo ntpdate -s <DC_IP> && bloodhound-ce-python -d <DOMAIN> -u '<USER>' --hashes ':<HASH>' -k -dc <DC> -ns <DC_IP> -c all --zip --use-ldaps
```

```console {class="sample-code"}
$ sudo ntpdate -s 10.129.232.88 && bloodhound-ce-python -d FLUFFY.HTB -u 'j.fleischman' --hashes ':10842EAD8D1D060A2DE1394E4B2EA460' -k -dc DC01.FLUFFY.HTB -ns 10.129.232.88 -c all --zip --use-ldaps
INFO: BloodHound.py for BloodHound Community Edition
INFO: Found AD domain: fluffy.htb
INFO: Getting TGT for user
INFO: Connecting to LDAP server: DC01.FLUFFY.HTB
INFO: Testing resolved hostname connectivity dead:beef::1189:4e5a:9825:1144
INFO: Trying LDAP connection to dead:beef::1189:4e5a:9825:1144
INFO: Found 1 domains
INFO: Found 1 domains in the forest
INFO: Found 1 computers
INFO: Connecting to LDAP server: DC01.FLUFFY.HTB
INFO: Testing resolved hostname connectivity dead:beef::1189:4e5a:9825:1144
INFO: Trying LDAP connection to dead:beef::1189:4e5a:9825:1144
INFO: Found 10 users
INFO: Found 54 groups
INFO: Found 2 gpos
INFO: Found 1 ous
INFO: Found 19 containers
INFO: Found 0 trusts
INFO: Starting computer enumeration with 10 workers
INFO: Querying computer: DC01.fluffy.htb
INFO: Done in 00M 12S
INFO: Compressing output into 20251101145349_bloodhound.zip
```

```console {class="ticket-based-kerberos"}
# Ticket-based Kerberos
sudo ntpdate -s <DC_IP> && bloodhound-ce-python -d <DOMAIN> -u '<USER>' -k -no-pass -dc <DC> -ns <DC_IP> -c all --zip --use-ldaps
```

```console {class="sample-code"}
$ sudo ntpdate -s 10.129.232.88 && bloodhound-ce-python -d FLUFFY.HTB -u 'j.fleischman' -k -no-pass -dc DC01.FLUFFY.HTB -ns 10.129.232.88 -c all --zip --use-ldaps
INFO: BloodHound.py for BloodHound Community Edition
INFO: Found AD domain: fluffy.htb
INFO: Using TGT from cache
INFO: Found TGT with correct principal in ccache file.
INFO: Connecting to LDAP server: DC01.FLUFFY.HTB
INFO: Testing resolved hostname connectivity dead:beef::1189:4e5a:9825:1144
INFO: Trying LDAP connection to dead:beef::1189:4e5a:9825:1144
INFO: Found 1 domains
INFO: Found 1 domains in the forest
INFO: Found 1 computers
INFO: Connecting to LDAP server: DC01.FLUFFY.HTB
INFO: Testing resolved hostname connectivity dead:beef::1189:4e5a:9825:1144
INFO: Trying LDAP connection to dead:beef::1189:4e5a:9825:1144
INFO: Found 10 users
INFO: Found 54 groups
INFO: Found 2 gpos
INFO: Found 1 ous
INFO: Found 19 containers
INFO: Found 0 trusts
INFO: Starting computer enumeration with 10 workers
INFO: Querying computer: DC01.fluffy.htb
INFO: Done in 00M 13S
INFO: Compressing output into 20251101145444_bloodhound.zip
```

#### Workaround for Name Resolving Issue

```console
# Build a DNS server to proxy name resolving request
python3 dnschef.py --fakeip <DC_IP>
``` 

<small>*Ref: [bloodhound-ce-python](https://github.com/dirkjanm/BloodHound.py/tree/bloodhound-ce)*</small>
<br>
<small>*Ref: [dnschef](https://github.com/iphelix/dnschef)*</small>

{{< /tabcontent >}}
{{< tabcontent set1-1 tab2 >}}

```console {class="password"}
# Password
nxc ldap <DC> -u '<USER>' -p '<PASSWORD>' --bloodhound --collection All --dns-server <DC_IP>
```

```console {class="sample-code"}
$ nxc ldap DC01.FLUFFY.HTB -u 'j.fleischman' -p 'J0elTHEM4n1990!' --bloodhound --collection All --dns-server 10.129.232.88
LDAP        10.129.232.88   389    DC01             [*] Windows 10 / Server 2019 Build 17763 (name:DC01) (domain:fluffy.htb)
LDAP        10.129.232.88   389    DC01             [+] fluffy.htb\j.fleischman:J0elTHEM4n1990! 
LDAP        10.129.232.88   389    DC01             Resolved collection methods: acl, group, session, objectprops, trusts, dcom, container, psremote, rdp, localadmin
LDAP        10.129.232.88   389    DC01             Done in 00M 13S
LDAP        10.129.232.88   389    DC01             Compressing output into /home/kali/.nxc/logs/DC01_10.129.232.88_2025-11-01_150856_bloodhound.zip
```

```console {class="ntlm"}
# NTLM
nxc ldap <DC> -u '<USER>' -H '<HASH>' --bloodhound --collection All --dns-server <DC_IP>
```

```console {class="sample-code"}
$ nxc ldap DC01.FLUFFY.HTB -u 'j.fleischman' -H '10842EAD8D1D060A2DE1394E4B2EA460' --bloodhound --collection All --dns-server 10.129.232.88
LDAP        10.129.232.88   389    DC01             [*] Windows 10 / Server 2019 Build 17763 (name:DC01) (domain:fluffy.htb)
LDAP        10.129.232.88   389    DC01             [+] fluffy.htb\j.fleischman:10842EAD8D1D060A2DE1394E4B2EA460 
LDAP        10.129.232.88   389    DC01             Resolved collection methods: dcom, psremote, rdp, objectprops, session, acl, container, trusts, group, localadmin
LDAP        10.129.232.88   389    DC01             Done in 00M 10S
LDAP        10.129.232.88   389    DC01             Compressing output into /home/kali/.nxc/logs/DC01_10.129.232.88_2025-11-01_150933_bloodhound.zip
```

```console {class="password-based-kerberos"}
# Password-based Kerberos
nxc ldap <DC> -u '<USER>' -p '<PASSWORD>' -k --kdcHost <DC> --bloodhound --collection All --dns-server <DC_IP>
```

```console {class="sample-code"}
$ nxc ldap DC01.FLUFFY.HTB -u 'j.fleischman' -p 'J0elTHEM4n1990!' -k --kdcHost DC01.FLUFFY.HTB --bloodhound --collection All --dns-server 10.129.232.88       
LDAP        DC01.FLUFFY.HTB 389    DC01             [*] Windows 10 / Server 2019 Build 17763 (name:DC01) (domain:fluffy.htb)
LDAP        DC01.FLUFFY.HTB 389    DC01             [+] fluffy.htb\j.fleischman:J0elTHEM4n1990! 
LDAP        DC01.FLUFFY.HTB 389    DC01             Resolved collection methods: group, dcom, psremote, acl, objectprops, rdp, session, localadmin, container, trusts
LDAP        DC01.FLUFFY.HTB 389    DC01             Using kerberos auth without ccache, getting TGT
LDAP        DC01.FLUFFY.HTB 389    DC01             Done in 00M 10S
LDAP        DC01.FLUFFY.HTB 389    DC01             Compressing output into /home/kali/.nxc/logs/DC01_DC01.FLUFFY.HTB_2025-11-01_151351_bloodhound.zip
```

```console {class="ntlm-based-kerberos"}
# NTLM-based Kerberos
nxc ldap <DC> -u '<USER>' -H '<HASH>' -k --kdcHost <DC> --bloodhound --collection All --dns-server <DC_IP>
```

```console {class="sample-code"}
$ nxc ldap DC01.FLUFFY.HTB -u 'j.fleischman' -H '10842EAD8D1D060A2DE1394E4B2EA460' -k --kdcHost DC01.FLUFFY.HTB --bloodhound --collection All --dns-server 10.129.232.88
LDAP        DC01.FLUFFY.HTB 389    DC01             [*] Windows 10 / Server 2019 Build 17763 (name:DC01) (domain:fluffy.htb)
LDAP        DC01.FLUFFY.HTB 389    DC01             [+] fluffy.htb\j.fleischman:10842EAD8D1D060A2DE1394E4B2EA460 
LDAP        DC01.FLUFFY.HTB 389    DC01             Resolved collection methods: dcom, psremote, rdp, session, group, trusts, acl, localadmin, container, objectprops
LDAP        DC01.FLUFFY.HTB 389    DC01             Using kerberos auth without ccache, getting TGT
LDAP        DC01.FLUFFY.HTB 389    DC01             Done in 00M 09S
LDAP        DC01.FLUFFY.HTB 389    DC01             Compressing output into /home/kali/.nxc/logs/DC01_DC01.FLUFFY.HTB_2025-11-01_151601_bloodhound.zip
```

```console {class="ticket-based-kerberos"}
# Ticket-based Kerberos
nxc ldap <DC> -u '<USER>' -k --use-kcache --kdcHost <DC> --bloodhound --collection All --dns-server <DC_IP>
```

```console {class="sample-code"}
$ nxc ldap DC01.FLUFFY.HTB -u 'j.fleischman' -k --use-kcache --kdcHost DC01.FLUFFY.HTB --bloodhound --collection All --dns-server 10.129.232.88
LDAP        DC01.FLUFFY.HTB 389    DC01             [*] Windows 10 / Server 2019 Build 17763 (name:DC01) (domain:fluffy.htb)
LDAP        DC01.FLUFFY.HTB 389    DC01             [+] fluffy.htb\j.fleischman from ccache 
LDAP        DC01.FLUFFY.HTB 389    DC01             Resolved collection methods: session, objectprops, rdp, trusts, psremote, container, group, acl, localadmin, dcom
LDAP        DC01.FLUFFY.HTB 389    DC01             Using kerberos auth without ccache, getting TGT
LDAP        DC01.FLUFFY.HTB 389    DC01             Using kerberos auth from ccache
LDAP        DC01.FLUFFY.HTB 389    DC01             Done in 00M 09S
LDAP        DC01.FLUFFY.HTB 389    DC01             Compressing output into /home/kali/.nxc/logs/DC01_DC01.FLUFFY.HTB_2025-11-01_151629_bloodhound.zip
```

#### Socks5

```console {class="password"}
# Password
proxychains4 -q nxc ldap <DC> -u '<USER>' -p '<PASSWORD>' --bloodhound --collection All --dns-tcp --dns-server <DC_IP>
```

```console {class="ntlm"}
# NTLM
proxychains4 -q nxc ldap <DC> -u '<USER>' -H '<HASH>' --bloodhound --collection All --dns-tcp --dns-server <DC_IP>
```

```console {class="password-based-kerberos"}
# Password-based Kerberos
proxychains4 -q nxc ldap <DC> -u '<USER>' -p '<PASSWORD>' -k --kdcHost <DC> --bloodhound --collection All --dns-tcp --dns-server <DC_IP>
```

```console {class="ntlm-based-kerberos"}
# Password-based Kerberos
proxychains4 -q nxc ldap <DC> -u '<USER>' -H '<HASH>' -k --kdcHost <DC> --bloodhound --collection All --dns-tcp --dns-server <DC_IP>
```

```console {class="ticket-based-kerberos"}
# Ticket-based Kerberos
proxychains4 -q nxc ldap <DC> -u '<USER>' -k --use-kcache --kdcHost <DC> --bloodhound --collection All --dns-tcp --dns-server <DC_IP>
```

{{< /tabcontent >}}
{{< tabcontent set1-1 tab3 >}}

#### 1. Installation \[Optional\]

```console
sudo apt install libsasl2-modules-gssapi-mit
```

#### 2. Configure /etc/krb5.conf

```console
# In UPPERCASE

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
    default_realm = FLUFFY.HTB

[realms]
    FLUFFY.HTB = {
        kdc = DC01.FLUFFY.HTB:88
        admin_server = DC01.FLUFFY.HTB
        default_domain = FLUFFY.HTB
    }
    
[domain_realm]
    .domain.internal = FLUFFY.HTB
    domain.internal = FLUFFY.HTB
```

#### 3. LDAP Search

```console {class="password"}
# Password
ldapsearch -LLL -H ldap://<DC> -D '<DN>' -w '<PASSWORD>' -b "DC=<EXAMPLE>,DC=<COM>" -N -o ldif-wrap=no -E '!1.2.840.113556.1.4.801=::MAMCAQc=' "(&(objectClass=*))" | tee ldap.txt
```

```console {class="sample-code"}
$ ldapsearch -LLL -H ldap://DC01.FLUFFY.HTB -D 'CN=JOEL FLEISCHMAN,CN=USERS,DC=FLUFFY,DC=HTB' -w 'J0elTHEM4n1990!' -b "DC=FLUFFY,DC=HTB" -N -o ldif-wrap=no -E '!1.2.840.113556.1.4.801=::MAMCAQc=' "(&(objectClass=*))" | tee ldap.txt
dn: DC=fluffy,DC=htb
objectClass: top
objectClass: domain
objectClass: domainDNS
distinguishedName: DC=fluffy,DC=htb
instanceType: 5
whenCreated: 20250417155921.0Z
whenChanged: 20251101141739.0Z
subRefs: DC=ForestDnsZones,DC=fluffy,DC=htb
subRefs: DC=DomainDnsZones,DC=fluffy,DC=htb
---[SNIP]---
```

```console {class="ticket-based-kerberos"}
# Ticket-based Kerberos
ldapsearch -LLL -H ldap://<DC> -Y GSSAPI -b "DC=<EXAMPLE>,DC=<COM>" -N -o ldif-wrap=no -E '!1.2.840.113556.1.4.801=::MAMCAQc=' "(&(objectClass=*))" | tee ldap.txt
```

```console {class="sample-code"}
$ ldapsearch -LLL -H ldap://DC01.FLUFFY.HTB -Y GSSAPI -b "DC=FLUFFY,DC=HTB" -N -o ldif-wrap=no -E '!1.2.840.113556.1.4.801=::MAMCAQc=' "(&(objectClass=*))" | tee ldap.txt
SASL/GSSAPI authentication started
SASL username: j.fleischman@FLUFFY.HTB
SASL SSF: 256
SASL data security layer installed.
dn: DC=fluffy,DC=htb
objectClass: top
objectClass: domain
objectClass: domainDNS
distinguishedName: DC=fluffy,DC=htb
instanceType: 5
---[SNIP]---
```

#### 4. Convert to BofHound Format

```console
python3 ldapsearch_parser.py ldap.txt ldap2.txt
```

```console {class="sample-code"}
$ python3 ldapsearch_parser.py ldap.txt ldap2.txt
```

#### 5. Convert to Bloodhound Format

```console
bofhound --input ldap2.txt --output <DC>_bloodhound --zip
```

```console {class="sample-code"}
$ bofhound --input ldap2.txt --output DC01.FLUFFY.HTB_bloodhound --zip

 _____________________________ __    __    ______    __    __   __   __   _______
|   _   /  /  __   / |   ____/|  |  |  |  /  __  \  |  |  |  | |  \ |  | |       \
|  |_)  | |  |  |  | |  |__   |  |__|  | |  |  |  | |  |  |  | |   \|  | |  .--.  |
|   _  <  |  |  |  | |   __|  |   __   | |  |  |  | |  |  |  | |  . `  | |  |  |  |
|  |_)  | |  `--'  | |  |     |  |  |  | |  `--'  | |  `--'  | |  |\   | |  '--'  |
|______/   \______/  |__|     |__|  |___\_\________\_\________\|__| \___\|_________\

                              by Fortalice ✪
    
[15:56:32] INFO     Parsed 219 objects from 1 log files
[15:56:32] INFO     Sorting parsed objects by type...
[15:56:32] INFO     Parsed 10 Users
[15:56:32] INFO     Parsed 52 Groups
[15:56:32] INFO     Parsed 1 Computers
[15:56:32] INFO     Parsed 1 Domains
[15:56:32] INFO     Parsed 0 Trust Accounts
[15:56:32] INFO     Parsed 1 OUs
[15:56:32] INFO     Parsed 2 GPOs
[15:56:32] INFO     Parsed 0 Schemas
[15:56:32] INFO     Parsed 152 Unknown Objects
[15:56:32] INFO     Parsed 541 ACL relationships
[15:56:32] INFO     Created default users
[15:56:32] INFO     Created default groups
[15:56:32] INFO     Resolved group memberships
[15:56:32] INFO     Resolved delegation relationships
[15:56:32] INFO     Resolved OU memberships
[15:56:32] INFO     Linked GPOs to OUs
[15:56:32] INFO     JSON files written to DC01.FLUFFY.HTB_bloodhound
[15:56:32] INFO     Files compressed into DC01.FLUFFY.HTB_bloodhound/bloodhound_20251101_155632.zip
```

<small>*Ref: [ldapsearch_parser](https://gist.github.com/kozmer/725cde788e4b3c8bdd870468c243916b)*</small>
<br>
<small>*Ref [bofhound](https://github.com/fortalice/bofhound)*</small>

{{< /tabcontent >}}
{{< /tabcontent >}}
{{< tabcontent set1 tab2 >}}
{{< tab set1-2 tab1 active>}}SharpHound.exe{{< /tab >}}{{< tab set1-2 tab2 >}}SharpHound.ps1{{< /tab >}}
{{< tabcontent set1-2 tab1 >}}

```console
# Current User
.\SharpHound.exe -c all --outputdirectory C:\ProgramData
```

```console {class="sample-code"}
evil-winrm-py PS C:\programdata> .\SharpHound.exe -c all --outputdirectory C:\ProgramData
2025-11-01T09:14:26.1622770-07:00|INFORMATION|This version of SharpHound is compatible with the 5.0.0 Release of BloodHound
2025-11-01T09:14:26.4123048-07:00|INFORMATION|Resolved Collection Methods: Group, LocalAdmin, GPOLocalGroup, Session, LoggedOn, Trusts, ACL, Container, RDP, ObjectProps, DCOM, SPNTargets, PSRemote, UserRights, CARegistry, DCRegistry, CertServices, LdapServices, WebClientService, SmbInfo, NTLMRegistry
2025-11-01T09:14:26.4591557-07:00|INFORMATION|Initializing SharpHound at 9:14 AM on 11/1/2025
2025-11-01T09:14:26.5060314-07:00|INFORMATION|Resolved current domain to fluffy.htb
2025-11-01T09:14:27.0529030-07:00|INFORMATION|Loaded cache with stats: 21 ID to type mappings.
 1 name to SID mappings.
 1 machine sid mappings.
 4 sid to domain mappings.
 0 global catalog mappings.
2025-11-01T09:14:27.0685751-07:00|INFORMATION|Flags: Group, LocalAdmin, GPOLocalGroup, Session, LoggedOn, Trusts, ACL, Container, RDP, ObjectProps, DCOM, SPNTargets, PSRemote, UserRights, CARegistry, DCRegistry, CertServices, LdapServices, WebClientService, SmbInfo, NTLMRegistry
2025-11-01T09:14:27.2404147-07:00|INFORMATION|Beginning LDAP search for fluffy.htb
2025-11-01T09:14:27.2404147-07:00|INFORMATION|Collecting AdminSDHolder data for fluffy.htb
2025-11-01T09:14:27.3497747-07:00|INFORMATION|AdminSDHolder ACL hash 54AA997A4487E89B4EB9CDF51A87397CD6BACAD5 calculated for fluffy.htb.
2025-11-01T09:14:27.5216544-07:00|INFORMATION|[CommonLib ACLProc]Building GUID Cache for FLUFFY.HTB
2025-11-01T09:14:28.3654012-07:00|INFORMATION|Beginning LDAP search for fluffy.htb Configuration NC
2025-11-01T09:14:29.7247797-07:00|INFORMATION|Producer has finished, closing LDAP channel
2025-11-01T09:14:29.7404000-07:00|INFORMATION|LDAP channel closed, waiting for consumers
2025-11-01T09:14:36.1154062-07:00|INFORMATION|Consumers finished, closing output channel
2025-11-01T09:14:36.1466533-07:00|INFORMATION|Output channel closed, waiting for output task to complete
Closing writers
2025-11-01T09:14:36.4278971-07:00|INFORMATION|Status: 341 objects finished (+341 37.88889)/s -- Using 85 MB RAM
2025-11-01T09:14:36.4278971-07:00|INFORMATION|Enumeration finished in 00:00:09.2277532
2025-11-01T09:14:36.5529014-07:00|INFORMATION|Saving cache with stats: 21 ID to type mappings.
 1 name to SID mappings.
 1 machine sid mappings.
 4 sid to domain mappings.
 0 global catalog mappings.
2025-11-01T09:14:36.5685274-07:00|INFORMATION|SharpHound Enumeration Completed at 9:14 AM on 11/1/2025! Happy Graphing!
```

```console
# Runas
.\SharpHound.exe -c all --outputdirectory C:\ProgramData --ldapusername '<USER>' --ldappassword '<PASSWORD>'
```

```console {class="sample-code"}
evil-winrm-py PS C:\programdata> .\SharpHound.exe -c all --outputdirectory C:\ProgramData --ldapusername 'j.fleischman' --ldappassword 'J0elTHEM4n1990!'
2025-11-01T09:15:10.1466795-07:00|INFORMATION|This version of SharpHound is compatible with the 5.0.0 Release of BloodHound
2025-11-01T09:15:10.4279174-07:00|INFORMATION|Resolved Collection Methods: Group, LocalAdmin, GPOLocalGroup, Session, LoggedOn, Trusts, ACL, Container, RDP, ObjectProps, DCOM, SPNTargets, PSRemote, UserRights, CARegistry, DCRegistry, CertServices, LdapServices, WebClientService, SmbInfo, NTLMRegistry
2025-11-01T09:15:10.4748000-07:00|INFORMATION|Initializing SharpHound at 9:15 AM on 11/1/2025
2025-11-01T09:15:10.5372963-07:00|INFORMATION|Resolved current domain to fluffy.htb
2025-11-01T09:15:11.0842992-07:00|INFORMATION|Loaded cache with stats: 21 ID to type mappings.
 1 name to SID mappings.
 1 machine sid mappings.
 4 sid to domain mappings.
 0 global catalog mappings.
2025-11-01T09:15:11.0997840-07:00|INFORMATION|Flags: Group, LocalAdmin, GPOLocalGroup, Session, LoggedOn, Trusts, ACL, Container, RDP, ObjectProps, DCOM, SPNTargets, PSRemote, UserRights, CARegistry, DCRegistry, CertServices, LdapServices, WebClientService, SmbInfo, NTLMRegistry
2025-11-01T09:15:11.2561253-07:00|INFORMATION|Beginning LDAP search for fluffy.htb
2025-11-01T09:15:11.2561253-07:00|INFORMATION|Collecting AdminSDHolder data for fluffy.htb
2025-11-01T09:15:11.3498824-07:00|INFORMATION|AdminSDHolder ACL hash 54AA997A4487E89B4EB9CDF51A87397CD6BACAD5 calculated for fluffy.htb.
2025-11-01T09:15:11.5372788-07:00|INFORMATION|[CommonLib ACLProc]Building GUID Cache for FLUFFY.HTB
2025-11-01T09:15:12.3185354-07:00|INFORMATION|Beginning LDAP search for fluffy.htb Configuration NC
2025-11-01T09:15:13.8028996-07:00|INFORMATION|Producer has finished, closing LDAP channel
2025-11-01T09:15:13.8028996-07:00|INFORMATION|LDAP channel closed, waiting for consumers
2025-11-01T09:15:23.3029018-07:00|INFORMATION|Consumers finished, closing output channel
Closing writers
2025-11-01T09:15:23.3341562-07:00|INFORMATION|Output channel closed, waiting for output task to complete
2025-11-01T09:15:23.5841543-07:00|INFORMATION|Status: 341 objects finished (+341 28.41667)/s -- Using 94 MB RAM
2025-11-01T09:15:23.5841543-07:00|INFORMATION|Enumeration finished in 00:00:12.3560977
2025-11-01T09:15:23.7091522-07:00|INFORMATION|Saving cache with stats: 21 ID to type mappings.
 1 name to SID mappings.
 1 machine sid mappings.
 4 sid to domain mappings.
 0 global catalog mappings.
2025-11-01T09:15:23.7247794-07:00|INFORMATION|SharpHound Enumeration Completed at 9:15 AM on 11/1/2025! Happy Graphing!
```

<small>*Ref: [sharphound.exe](https://github.com/SpecterOps/SharpHound)*</small>

{{< /tabcontent >}}
{{< tabcontent set1-2 tab2 >}}

```console
# Import module
. .\SharpHound.ps1
```

```console {class="sample-code"}
evil-winrm-py PS C:\programdata> . .\SharpHound.ps1
```

```console
# Run
Invoke-BloodHound -CollectionMethods All -OutputDirectory C:\ProgramData
```

```console {class="sample-code"}
evil-winrm-py PS C:\programdata> Invoke-BloodHound -CollectionMethods All -OutputDirectory C:\ProgramData
```

<small>*Ref: [sharphound.ps1](https://github.com/SpecterOps/SharpHound)*</small>

{{< /tabcontent >}}
{{< /tabcontent >}}
{{< tabcontent set1 tab3 >}}
{{< tab set1-3 tab1 active>}}sliver{{< /tab >}}
{{< tabcontent set1-3 tab1 >}}

```console
sharp-hound-4 -- '-c all --outputdirectory C:\ProgramData'
```

{{< /tabcontent >}}
{{< /tabcontent >}}
