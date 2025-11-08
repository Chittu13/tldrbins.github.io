---
title: "MSSQL General"
tags: ["Database Dumping", "Privilege Escalation In Databases", "MSSQL", "Database", "Windows"]
---

{{< filter_buttons >}}

### Connection

{{< tab set1 tab1 >}}Linux{{< /tab >}}
{{< tab set1 tab2 >}}Windows{{< /tab >}}
{{< tabcontent set1 tab1 >}}

```console {class="password"}
# Password
impacket-mssqlclient '<USER>:<PASSWORD>@<TARGET>'
```

```console {class="ntlm"}
# NTLM
impacket-mssqlclient '<USER>@<TARGET>' -hashes :<HASH>
```

```console {class="password-based-kerberos"}
# Password-based Kerberos
impacket-mssqlclient '<USER>:<PASSWORD>@<TARGET>' -k -dc-ip <DC_IP>
```

```console {class="ntlm-based-kerberos"}
# NTLM-based Kerberos
impacket-mssqlclient '<USER>@<TARGET>' -hashes :<HASH> -k -dc-ip <DC_IP>
```

```console {class="ticket-based-kerberos"}
# Ticket-based Kerberos
impacket-mssqlclient '<USER>@<TARGET>' -k -no-pass -dc-ip <DC_IP>
```

#### Windows Auth

```console {class="password"}
# Password
impacket-mssqlclient '<USER>:<PASSWORD>@<TARGET>' -windows-auth
```

```console {class="ntlm"}
# NTLM
impacket-mssqlclient '<USER>@<TARGET>' -hashes :<HASH> -windows-auth
```

{{< /tabcontent >}}
{{< tabcontent set1 tab2 >}}

```console
# Current user
sqlcmd -S '<TARGET>' -Q "<QUERY>"
```

```console
# Password
sqlcmd -S '<TARGET>' -U '<USER>' -P '<PASSWORD>' -d '<DB_NAME>' -Q "<QUERY>"
```

{{< /tabcontent >}}

---

### General

```console
# Check mssql version
SELECT @@version;
```

```console
# Check current user
SELECT suser_name();
```

```console
# Check users
SELECT name FROM master..syslogins
```

```console
# Check sysadmin
SELECT name FROM master..syslogins WHERE sysadmin = '1';
```

```console
# Check service name and the account authorized to control the service
SELECT servicename, service_account FROM sys.dm_server_services;
```

```console
# List principals
SELECT name FROM sys.database_principals;
```

```console
# Check privilege over a principal from current user
SELECT entity_name, permission_name FROM fn_my_permissions('<PRINCIPAL>', 'USER');
```

```console
# Fix : Cannot resolve the collation conflict between "Latin1_General_CI_AI" and "SQL_Latin1_General_CP1_CI_AS"
SELECT entity_name collate DATABASE_DEFAULT,permission_name collate DATABASE_DEFAULT FROM fn_my_permissions('<PRINCIPAL>', 'USER');
```

```console
# Check current user privilege
SELECT entity_name, permission_name FROM fn_my_permissions(NULL, 'SERVER');
```

```console
# Check impersonate
SELECT name FROM sys.server_principals WHERE HAS_PERMS_BY_NAME(name, 'SERVER', 'IMPERSONATE') = 1;
```

```console
# Show databases
SELECT name FROM master..sysdatabases;
```

```console
# Show current database
SELECT DB_NAME();
```

```console
# List tables and schema
SELECT table_name,table_schema from <DB_NAME>.INFORMATION_SCHEMA.TABLES;
```

```console
# Select all from table
SELECT * from <DB_NAME>.<TABLE_SCHEMA>.<TABLE_NAME>;
```

```console
# Get domain name
SELECT DEFAULT_DOMAIN();
```

```console
# Get user SID
SELECT master.dbo.fn_varbintohexstr(SUSER_SID('<DOMAIN>\<USER>'))
```

```console
# Get group SID
SELECT master.dbo.fn_varbintohexstr(SUSER_SID('<DOMAIN>\<GROUP>'))
```

```console
# Read a text file
SELECT * FROM OPENROWSET(BULK N'<FILE>', SINGLE_CLOB) AS Contents
```

```console
# Read file system
xp_dirtree C:\
```

---

### Create sa User

```console
CREATE LOGIN '<USER>' WITH PASSWORD = '<PASSWORD>';
```

```console
EXEC sp_addsrvrolemember '<USER>', 'sysadmin';
```
