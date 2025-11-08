---
title: "Wordpress"
tags: ["Wpscan", "Wordpress", "Reconnaissance", "Enumeration"]
---

#### Default Config Location

```console
/var/www/html/wp-config.php
```

{{< tab set1 tab1 >}}wpscan{{< /tab >}}
{{< tab set1 tab2 >}}wpprobe{{< /tab >}}
{{< tabcontent set1 tab1 >}}

```console
# HTTP
wpscan --url <TARGET> -e ap,t,tt,u
```

```console
# HTTPS
wpscan --url <TARGET> -e ap,t,tt,u --disable-tls-checks
```

```console
# Scan vulns
wpscan --url <TARGET> -e ap,t,tt,u --api-token <API_KEY>
```

```console
# Brute-force wp-admin
wpscan --url <TARGET> --passwords <WORDLIST> --usernames admin
```

<small>*Ref: [Wpscan API key](https://wpscan.com/)*</small>

{{< /tabcontent >}}
{{< tabcontent set1 tab2 >}}

```console
# HTTP
wpprobe scan --url <TARGET>
```

<small>*Ref: [wpprobe](https://github.com/Chocapikk/wpprobe)*</small>

{{< /tabcontent >}}