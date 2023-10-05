---
title: Windows services notes
---

- [1. Services and Service Control Manager (SCM)](#1-services-and-service-control-manager-scm)
- [2. SNMP (Simple Network Management Protocol)](#2-snmp-simple-network-management-protocol)
- [3. IIS - Windows web server](#3-iis---windows-web-server)
- [4. MSRPC - Microsoft Remote Procedure Call (135, 593)](#4-msrpc---microsoft-remote-procedure-call-135-593)
- [5. Endpoint Mapper (EPM)](#5-endpoint-mapper-epm)
- [6. NetBIOS Name Service (139)](#6-netbios-name-service-139)
  - [6.1. Security](#61-security)
  - [6.2. NetBIOS/domain/DNS/hostname](#62-netbiosdomaindnshostname)
- [7. Resource sharing](#7-resource-sharing)
  - [7.1. SMB - Server Message Block (139, 445)](#71-smb---server-message-block-139-445)
  - [7.2. NFS - Network File System](#72-nfs---network-file-system)
  - [7.3. FTP - File Transfer Protocol](#73-ftp---file-transfer-protocol)

## 1. Services and Service Control Manager (SCM)
_Services_ are _daemons_ in the Linux world. They are basically standard processes (with PID associated) that run in the background, and are managed by the OS. They are managed by the **Service Control Manager** (SCM). The SCM is a special system process in charge of managing the state of services, checking their current state and providing a way to configure and enumerate them. It's started at system boot. The SCM is an RCP server, so the services can be controlled from remote machines.

SCM executable is located in: `%SystemRoot%\System32\services.exe`.

Each service has an associated executable that is run by the SCM when a service is started. Because of special interface to perform communication with the SCM, not every executable can be started as a service. Each service specifies the account under which the service runs and its DACL (indicates who has permission to start, stop, pause, query status and reconfigure the service). DACL can be seen from `Process Hacker`.

Services configurations are stored in the registry: `HKLM\SYSTEM\CurrentControlSet\Services\`.

```powershell
sc.exe qc <service>                         # Show service configuration
sc.exe stop <service>                       # Stop service
sc.exe start <service>                      # Start service

# List services - PID, Name, State and LogOnAs (StartName) values
Get-CimInstance win32_service | select ProcessId,Name,State,StartName
```

## 2. SNMP (Simple Network Management Protocol)
SNMP is widely used in network management for network monitoring. It exposes management data in the form of variables on the managed systems organized in a management information base (MIB). These data can then be remotely queried and, in some circumstances, manipulated.

## 3. IIS - Windows web server
IIS stands for Internet Information Services. It's just web server for Windows.It's included in most Windows versions, except home editions. Usually there is a new IIS version for every new OS.

## 4. MSRPC - Microsoft Remote Procedure Call (135, 593)
MSRPC is protocol that uses the client-server model in order to allow one program to request service from a program on another host.

The RPC endpoint can be accessed through TCP and UDP port 135, via SMB with a null or authenticated session (TCP 139 and 445), and as a web service listening on TCP port 593.

## 5. Endpoint Mapper (EPM)
TBD

## 6. NetBIOS Name Service (139)
It's name service for name registration and resolution. Every machine has a name inside the NetBios network.

### 6.1. Security
By enumerating a NetBIOS service you can obtain names the server is using and the its MAC address.

### 6.2. NetBIOS/domain/DNS/hostname
Every computer on the internet has DNS name (network hostname). Every computer on the internet running Windows OS has NetBIOS name as well. It's the same as local computer name.

Computer running Windows in an Active Directory domain has both:

- DNS domain name - classic `sub.example.com`
- NetBIOS domain name - typically that name is subdomain of DNS domain name. For example, DNS name = "corp.com", NetBIOS name = "corp"

## 7. Resource sharing

### 7.1. SMB - Server Message Block (139, 445)
SMB is a client-server protocol that regulates access to files and entire directories and other network resources. An SMB server can provide arbitrary parts of its local file system as shares. Access rights are defined by ACL. SMB can be used only within LOCAL networks, it's not routable.

**Security**: SMB most often uses NTLM to authentication. NTLM challenge might be sniffed and cracked offline. Cracking NTLM challenge is slower than cracking the hash directly, but it's still possible. SMB is very widely used by services in LAN, so there are usually a lot of these challanges flying on the network.

### 7.2. NFS - Network File System
By NFS protocol, you can transfer files between computers running Windows and other non-Windows OS. NFS in Windows Server includes Server for NFS and Client for NFS.

NFS is automatic protocol (FTP is manual). Once mounted, files appear as if they are local files. Blocks of the files are transferred in the background; no need to copy the entire files to read them. NFS works best in fast, stable, low loss LOCAL networks.

### 7.3. FTP - File Transfer Protocol
FTP is good for far-away connections, when you transfer between two different OSes. It sends only entire files.
