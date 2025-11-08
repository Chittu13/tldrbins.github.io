---
title: "WebDAV"
tags: ["Active Directory", "Http File Transfer", "Curl", "WebDAV", "Http", "Web", "Enumeration", "WebClient Service", "Windows"]
---

{{< filter_buttons >}}

### Enumeration

{{< tab set1 tab1 >}}davtest{{< /tab >}}
{{< tab set1 tab2 >}}nxc{{< /tab >}}
{{< tabcontent set1 tab1 >}}

```console
# Anonymous
davtest -url http://<TARGET>
```

```console
# Password
davtest -url http://<TARGET> -auth '<USER>:<PASSWORD>'
```

<small>*Ref: [davtest](https://github.com/cldrn/davtest)*</small>

{{< /tabcontent >}}
{{< tabcontent set1 tab2 >}}

```console {class="password"}
# Password
nxc smb <TARGET> -d <DOMAIN> -u '<USER>' -p '<PASSWORD>' -M webdav
```

```console {class="ntlm"}
# NTLM
nxc smb <TARGET> -d <DOMAIN> -u '<USER>' -H '<HASH>' -M webdav
```

```console {class="password-based-kerberos"}
# Password-based Kerberos
nxc smb <TARGET> -d <DOMAIN> -u '<USER>' -p '<PASSWORD>' -k --kdcHost <DC> -M webdav
```

```console {class="ntlm-based-kerberos"}
# NTLM-based Kerberos
nxc smb <TARGET> -d <DOMAIN> -u '<USER>' -H '<HASH>' -k --kdcHost <DC> -M webdav
```

```console {class="ticket-based-kerberos"}
# Ticket-based Kerberos
nxc smb <TARGET> -d <DOMAIN> -u '<USER>' -k --kdcHost <DC> --use-kcache -M webdav
```

{{< /tabcontent >}}

### General

{{< tab set2 tab1 >}}curl{{< /tab >}}
{{< tabcontent set2 tab1 >}}

```console
# Rename a remote file
curl -X MOVE -H 'Destination:http://<TARGET>/<NEW_FILENAME>' http://<TARGET>/<FILE>
```

{{< /tabcontent >}}