---
title: Windows lateral movement notes
---

## Process spawning via PsExec
PsExec is Sysinternals tool. It can execute processes remotely on any machine where we can access. PsExec uses SMB protocol (445/TCP). Target account must be a member of _Administrators_ group. 

PsExec workflow:
1. Connect to Admin$ share and upload a `psexesvc.exe` service binary.
2. Connect to the Service Control Manager (SCM), run a service named `PSEXESVC` and associate the service binary with `C:\Windows\psexesvc.exe`.
3. Create named pipes to handle stdin/out/err.

## Process spawning via WinRM
Main purpose of the WinRM protocol is to run PowerShell commands remotely. It can be used to the lateral movement. Target account must be member of the _Remote Management Users_ group.

## Command execution via services
Windows services can be used to run arbitrary commands because they execute a command when started. Standard tool for creating a service on remote host is the `sc.exe`. It exploits default ability of Windows services to execute arbitrary commands at the start of the service. Target account must be member of the _Administrators_ group. The victim's OS is in charge of starting the service, so the attacker is not be able to look at the command's output - it's blind attack.

It tries to connect to the Service Control Manager (SVCCTL) throught RPC in two ways:
1. The client will first connect to the Endpoint Mapper (EPM) at port 135 (catalogue of available RPC endpoints) and request information on the SVCCTL service program. The EPM will respond with the IP:PORT of SVCCTL (usually a dynamic port in the range of 49152-65535).
2. The client will try to reach SVCCTL through SMB named pipes on port 445 (SMB) or 139 (SMB over NetBIOS).

**Reverse shell**
If we try to run a reverse shell using this method, the reverse shell disconnects immediately after execution. Service executables are different to standard `.exe` files, and therefore non-service executables are killed by the service manager almost immediately. `Msfvenom` supports the `exe-service` format, which will encapsulate any payload inside a fully functional service executable, preventing it from getting killed.

## Command execution via scheduled tasks
Scheduled tasks can be created remotely. The `schtasks` tool is available in any Windows installation. The victim's OS is in charge of running the scheduled task, so the attacker is not able to look at the command's output - it's blind attack.

## Abusing WMI
WMI allows administrators to perform standard management tasks that attacker can abuse to perform lateral movement. Abusing WMI an attacker is able to remotely create a process or a scheduled task, run a service, install a MSI package.

## NTLM - Pass-the-Hash
As a result of extracting credentials from a host an attacker might get NTLM hash. Sometimes it can be too hard to crack the hash but it's possible to authenticate with the hash itself.  

## Kerberos - Pass-the-Ticket
Sometimes it is possible to extract Kerberos tickets and session keys (both are required) from LSASS memory using e.g. `mimikatz`. Best tickets to steal are TGTs because they can be used to access any service. TGSs are only good for some specific services. 