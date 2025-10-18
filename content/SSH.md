---
title: "SSH"
tags: ["SSH", "Private Key", "Public Key", "id_Rsa", "Ppk", "Pem", "Openssh", "Remote Access", "SFTP"]
---

### Check SSH Version

[openssh-server (ubuntu)](https://packages.ubuntu.com/search?keywords=openssh-server)

[openssh-server (debian)](https://packages.debian.org/search?keywords=openssh-server)

### Config Location

```console
/etc/ssh/sshd_config
```

```console
# Grep contents
grep -Ev "^#" /etc/ssh/sshd_config | grep .
```

---

### Generate SSH Key

```console
ssh-keygen
```

```console
# Set filename, leave passphase blank
./id_rsa
```

```console
# After creation
chmod 600 id_rsa
```

### Check Public Key

```console
ssh-keygen -l -f id_rsa
```

### Generate No Passphrase SSH Key from Encrypted Key

```console
openssl rsa -in <ENC_KEY> -out ./id_rsa
```

```console
# OpenSSH format
ssh-keygen -p -P '<PASSPHRASE>' -N '' -f <ENC_KEY>
```

### Convert .ppk to .pem Format

```console
# Install
sudo apt install putty-tools
```

```console
# Convert to private key in pem format
puttygen key.ppk -O private-openssh -o key.pem
```

```console
# Convert to public key in pem format
puttygen key.ppk -O public-openssh -o key.pem.pub
```

---

### Add SSH Access to Target (Linux)

```console
cat id_rsa.pub
```

```console
echo <BASE64_PUB_KEY> >> /home/<USER>/.ssh/authorized_keys
```

---

### Add SSH Access To Target (Windows)

#### User

```console
Add-Content -Path "C:\Users\<USER>\.ssh\authorized_keys" -Value "<BASE64_PUB_KEY>"
```

#### Administrator

```console
Add-Content -Path "C:\ProgramData\ssh\administrators_authorized_keys" -Value "<BASE64_PUB_KEY>"
```

```console
# Set file permissions
icacls "C:\ProgramData\ssh\administrators_authorized_keys" /remove "Everyone"
icacls "C:\ProgramData\ssh\administrators_authorized_keys" /inheritance:r
icacls "C:\ProgramData\ssh\administrators_authorized_keys" /grant:r "Administrators:F"
icacls "C:\ProgramData\ssh\administrators_authorized_keys" /grant:r "SYSTEM:F"
```

---

### SSH Connect

{{< tab set1 tab1 >}}Password{{< /tab >}}
{{< tab set1 tab2 >}}Private Key{{< /tab >}}
{{< tab set1 tab3 >}}GSSAPI{{< /tab >}}
{{< tab set1 tab4 >}}Target Shell{{< /tab >}}
{{< tabcontent set1 tab1 >}}

```console
ssh <USER>@<TARGET>
```

```console
# After first connection (i.e., after 'yes' to fingerprint prompt)
sshpass -p '<PASSWORD>' ssh <USER>@<TARGET>
```

```console
# Connect to a domain-joined machine
ssh -l <USER>@<DOMAIN> <TARGET_DOMAIN>
```

{{< /tabcontent >}}
{{< tabcontent set1 tab2 >}}

```console
ssh <USER>@<TARGET> -i id_rsa
```

```console
# Fix: no matching host key type found. Their offer: ssh-rsa,ssh-dss
ssh <USER>@<TARGET> -i id_rsa -oHostKeyAlgorithms=+ssh-rsa
```

```console
# Fix: sign_and_send_pubkey: no mutual signature supported 
ssh <USER>@<TARGET> -i id_rsa -o PubkeyAcceptedKeyTypes=ssh-rsa
```

<small>*Note: Always append a new line in id_rsa key*</small>

{{< /tabcontent >}}
{{< tabcontent set1 tab3 >}}

#### 1. Edit '/etc/ssh/sshd_config'

```console
# GSSAPI options
GSSAPIAuthentication yes
GSSAPICleanupCredentials yes
```

#### 2. Edit '/etc/krb5.conf'

```console
# In UPPER case
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
    default_realm = ABSOLUTE.HTB

[realms]
    ABSOLUTE.HTB = {
        kdc = DC.ABSOLUTE.HTB:88
        admin_server = DC.ABSOLUTE.HTB
        default_domain = ABSOLUTE.HTB
    }
    
[domain_realm]
    .domain.internal = ABSOLUTE.HTB
    domain.internal = ABSOLUTE.HTB
```

#### 3. Import TGT

```console
# Import TGT
export KRB5CCNAME=<CCACHE>
```

```console
# Check
klist
```

#### 4. Connect

```console
ssh -K -l <USER>@<DOMAIN> <TARGET_DOMAIN>
```

{{< /tabcontent >}}
{{< tabcontent set1 tab4 >}}

```console
# Spawn target shell to escape restricted shell
ssh <USER>@<TARGET> -t bash
```

{{< /tabcontent >}}

---

### SFTP Connect

{{< tab set2 tab1 >}}Password{{< /tab >}}
{{< tabcontent set2 tab1 >}}

```console
sftp <USER>@<TARGET>
```

```console
# After first connection (i.e., after 'yes' to fingerprint prompt)
sshpass -p '<PASSWORD>' sftp <USER>@<TARGET>
```

{{< /tabcontent >}}