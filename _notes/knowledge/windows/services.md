---
title: Windows Server common services
---

_Services_ are _daemons_ in the Linux world.

## SNMP (Simple Network Management Protocol)
SNMP is widely used in network management for network monitoring. It exposes management data in the form of variables on the managed systems organized in a management information base (MIB). These data can then be remotely queried and, in some circumstances, manipulated.

## LDAP - Lightweight Directory Access Protocol
What LDAP is:

- LDAP is TCP/IP open and cross platform protocol.
- LDAP is one way of speaking to Active Directory.
- LDAP is protocol that many different directory services and access management solutions can understand.
- Relation between LDAP and AD is like HTTP and Apache. AD is directory server that uses the LDAP protocol.

### LDAP Query
It's a command that asks a directory service (e.g. AD) for some information.

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

## Service Control Manager (SCM)
TBD
