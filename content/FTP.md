---
title: "FTP"
tags: ["FTP", "LFTP", "File Transfer", "Secure Transfer"]
---

### Config Location

```console
/etc/vsftpd.conf
```

### General

```console
# Anonymous
ftp ftp://anonymous:@<TARGET>
```

```console
# Anonymous
ftp ftp://ftp:ftp@<TARGET>
```

```console
# Password
ftp ftp://<USER>:<PASSWORD>@<TARGET>
```

```console
# Interactive
ftp <TARGET>
```

```console
# Over SSL/TLS
lftp <TARGET>
```

```console
# Disable SSL certificate verification
echo -n 'set ssl:verify-certificate no' >> ~/.lftp/rc
```

```console
# List directory
ls
```

```console
# Use for non-text files
binary
```

```console
# Download
get "<FILE>"
```

```console
# Upload
put "<FILE>"
```

```console
# For firewall/NAT compatibility
passive
```

```console
# Exit
quit
```

### Recusive download

```console
# Anonymous
wget -r ftp://anonymous:@<TARGET>
```

```console
# Password
wget --user <USER> --password '<PASSWORD>' -m ftp://<TARGET>
```

<small>*Note: Always check what's in there first*</small>
