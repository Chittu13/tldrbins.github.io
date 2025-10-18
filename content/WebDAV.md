---
title: "WebDAV"
tags: ["Http File Transfer", "Curl", "WebDAV", "Http", "Web", "Enumeration", "WebClient Service", "Windows"]
---

### Enum

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

```console
# Check WebClient service in Windows
nxc <PROTOCOL> <TARGET> -u '<USER>' -p '<PASSWORD>' -d <DOMAIN> -M webdav
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