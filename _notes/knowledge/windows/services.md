---
title: Windows services notes
---

## Services and SCM
_Services_ are _daemons_ in the Linux world. They are managed by the **Service Control Manager** (SCM). The SCM is a special system process in charge of managing the state of services, checking their current state and providing a way to configure and enumerate them. It's started at system boot. The SCM is an RCP server, so the services can be controlled from remote machines.

SCM executable is located in: `%SystemRoot%\System32\services.exe`.

Each service has an associated executable that is run by the SCM when a service is started. Because of special interface to perform communication with the SCM, not every executable can be started as a service. Each service specifies the account under which the service runs and Discretionary Access Control List (DACL), which indicates who has permission to start, stop, pause, query status and reconfigure the service. DACL can be seen from `Process Hacker`.

Services configurations are stored in the registry: `HKLM\SYSTEM\CurrentControlSet\Services\`.

```powershell
sc.exe qc <service>                         # Show service configuration
sc.exe stop <service>                       # Stop service
sc.exe start <service>                      # Start service
```

## SNMP (Simple Network Management Protocol)
SNMP is widely used in network management for network monitoring. It exposes management data in the form of variables on the managed systems organized in a management information base (MIB). These data can then be remotely queried and, in some circumstances, manipulated.

## IIS - Windows web server
IIS stands for Internet Information Services. It's just web server for Windows.It's included in most Windows versions, except home editions. Usually there is a new IIS version for every new OS.

## MSRPC - Microsoft Remote Procedure Call (135, 593)
MSRPC is protocol that uses the client-server model in order to allow one program to request service from a program on another host.

The RPC endpoint can be accessed through TCP and UDP port 135, via SMB with a null or authenticated session (TCP 139 and 445), and as a web service listening on TCP port 593.

## Endpoint Mapper (EPM)
TBD

## NetBIOS Name Service (139)
It's name service for name registration and resolution. Every machine has a name inside the NetBios network.

### Security
By enumerating a NetBIOS service you can obtain names the server is using and the its MAC address.

### NetBIOS name vs domain Name vs DNS name vs hostname
Every computer on the internet has DNS name (network hostname). Every computer on the internet running Windows OS has NetBIOS name as well. It's the same as local computer name.

Computer running Windows in an Active Directory domain has both:

- DNS domain name - classic `sub.example.com`
- NetBIOS domain name - typically that name is subdomain of DNS domain name. For example, DNS name = "corp.com", NetBIOS name = "corp"
