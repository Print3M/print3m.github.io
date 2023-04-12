---
title: Active Directory notes
---

## Domain Controller
**AD Domain** - part of the network that groups users, hosts, resources. It's used to perform privileges, security policies and access management. At least one Domain Controller must be present to create Domain. The main idea behing a domain is to centralise the administration of Windows components in a single repository called Active Directory.

Each AD domain is also a DNS domain, and each AD domain controller is also a DNS nameserver – but not the other way around.

**AD Forest** - collection of domains that trust each other.

**Domain Controller** - administrator of the Domain. The server that runs AD services. Every user in the network must authenticate via Kerberos or LDAP protocol sent to DC. DC is responsible for security policies and account management. If you have DC, you are god in the network. DC holds AD database file.

## Active Directory
AD is service used by Domain Controller to perform authentication, groups, users and security policies management. AD is not cross platform. AD supports both Kerberos and LDAP authentication. AD database file is called NTDS.dit and it's stored on Domain Controller server.

#### Security
Even with low-privileged user an attacker can make useful enumeration and lateral movement.

## AD Domain Service (AD DS)
It's catalogue that holds the information of all "objects" that exist on the network. An object might be: user, group, machine, printer, share, etc.

#### Users
- most common object type in AD.
- people - represents persons in the organisation
- services - every service (IIS or MSSQL) requires a user to run. They only have privileges needed to run their specific service (ideally).
    
#### Machines
- represents every computer that joins the AD domain
- every machine have Machine Account - local administrator on the computer, is not supposed to be accessed by anyone except the computer itself but it uses normal password (120 random chars). MA name is the computer's name + dollar sign: PC-1 (computer name) -> PC-1$ (MA name).

#### Security groups
- group includes AD machines and AD users as members
- group can include other groups
- several groups are created by default in a domain, e.g. Domain Admins, Domain Users, Domain Computers, Domain Controllers.

## Users / accounts
AD users are different than built-in local users (these are are used to manage the system locally, which is not part of the AD environment). Domain/AD accounts can use the AD services.

Types of AD Administrator accounts:
* BUILTIN\Administrator - local admin on a domain controller.
* Domain Admin - admin to all resources in the domain.
* Enterprise Admin - forest root only.
* Schema Admin - capable of modifying domain/forest.

## Group Policy Objects (GPO)
Collection of settings (rules) that can be applied to Organizational Unit (organized objects: users, hosts, etc.). GPOs are distributed to the network via a network share SYSVOL (stored in the DC) which points to path `C:\Windows\SYSVOL\sysvol\` on each of the DCs.

##### Security
Any AD account, no matter how low-privileged, can read the contents of the SYSVOL directory. It's nice way to check if provided domain credentials are correct.

## Distinguished Name (DN)
Collection of comma-separated key and value pairs used to identify unique AD record (object). The DN consists of:
* Domain Component (DC)
* Organizational Unit Name (OU)
* Common Name (CN)
* others

> **Example** of DN: "CN=Administrator, OU=Users, DC=amazon, DC=com" 

## Local workgroup
TBD