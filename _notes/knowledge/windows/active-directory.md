---
title: Active Directory notes
---

- [1. Domain Controller](#1-domain-controller)
- [2. Active Directory \& LDAP](#2-active-directory--ldap)
  - [2.1. Security](#21-security)
- [3. AD Domain Service (AD DS)](#3-ad-domain-service-ad-ds)
  - [3.1. Users](#31-users)
  - [3.2. Machines](#32-machines)
  - [3.3. Security groups](#33-security-groups)
- [4. Users / accounts](#4-users--accounts)
- [5. Group Policy Objects (GPO)](#5-group-policy-objects-gpo)
  - [5.1. Security](#51-security)
- [6. Distinguished Name (DN)](#6-distinguished-name-dn)
- [7. Local workgroup](#7-local-workgroup)
- [8. Active Directory Certificate Services (AD CS)](#8-active-directory-certificate-services-ad-cs)

## 1. Domain Controller
**AD Domain** - part of the network that groups users, hosts, resources. It's used to perform privileges, security policies and access management. At least one Domain Controller must be present to create Domain. The main idea behing a domain is to centralise the administration of Windows components in a single repository called Active Directory.

Each AD domain is also a DNS domain, and each AD domain controller is also a DNS nameserver – but not the other way around.

**AD Forest** - collection of domains that trust each other.

**Domain Controller** - administrator of the Domain. The server that runs AD services. Every user in the network must authenticate via Kerberos or NTLM protocol sent to the DC. DC is responsible for security policies and account management. If you have DC, you are god in the network. DC holds AD database file.

## 2. Active Directory & LDAP
AD is service used by Domain Controller to perform authentication, groups, users and security policies management. It is not cross-platform commercial implementation of open and cross-platform **LDAP** (_Lightweight Directory Access Protocol_) used for accessing and maintaining distributed directory information services over IP network. LDAP query is a command that asks a directory service (e.g. Active Directory) for some information.

AD database file is called NTDS.dit and it's stored on Domain Controller server.

### 2.1. Security
Even with low-privileged user an attacker can make useful enumeration and lateral movement.

## 3. AD Domain Service (AD DS)
It's catalogue that holds the information of all "objects" that exist on the network. An object might be: user, group, machine, printer, share, etc.

### 3.1. Users

- most common object type in AD.
- people - represents persons in the organisation
- services - every service (IIS or MSSQL) requires a user to run. They only have privileges needed to run their specific service (ideally).

### 3.2. Machines

- represents every computer that joins the AD domain
- every machine have Machine Account - local administrator on the computer, is not supposed to be accessed by anyone except the computer itself but it uses normal password (120 random chars). MA name is the computer's name + dollar sign: PC-1 (computer name) -> PC-1$ (MA name).

### 3.3. Security groups

- group includes AD machines and AD users as members
- group can include other groups
- several groups are created by default in a domain, e.g. Domain Admins, Domain Users, Domain Computers, Domain Controllers.

## 4. Users / accounts
AD users are different than built-in local users (these are used to manage the system locally, which is not part of the AD environment). Domain/AD accounts can use the AD services.

Types of AD Administrator accounts:

- BUILTIN\Administrator - local admin on a domain controller.
- Domain Admin - admin to all resources in the domain.
- Enterprise Admin - forest root only.
- Schema Admin - capable of modifying domain/forest.

## 5. Group Policy Objects (GPO)
Collection of settings (rules) that can be applied to Organizational Unit (organized objects: users, hosts, etc.). GPOs are distributed to the network via a network share SYSVOL (stored in the DC) which points to path `C:\Windows\SYSVOL\sysvol\` on each of the DCs.

### 5.1. Security
Any AD account, no matter how low-privileged, can read the contents of the SYSVOL directory. It's nice way to **check if provided domain credentials are correct**.

## 6. Distinguished Name (DN)
Collection of comma-separated key and value pairs used to identify unique AD record (object). The DN consists of:

- Domain Component (DC)
- Organizational Unit Name (OU)
- Common Name (CN)
- others

> **Example** of DN: "CN=Administrator, OU=Users, DC=amazon, DC=com"

## 7. Local workgroup
TBD

## 8. Active Directory Certificate Services (AD CS)
AD CS is a Microsoft's implementation of Public Key Infrastructure.
