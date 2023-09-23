---
title: Active Directory overview
---

- [1. Domain Controller](#1-domain-controller)
  - [1.1. DC Synchronisation](#11-dc-synchronisation)
- [2. Active Directory \& LDAP](#2-active-directory--ldap)
- [3. AD Domain Service (AD DS)](#3-ad-domain-service-ad-ds)
  - [3.1. Users](#31-users)
  - [3.2. Machines](#32-machines)
  - [3.3. Security groups](#33-security-groups)
- [4. Users / accounts](#4-users--accounts)
- [5. Local Administrator Password Solution (LAPS)](#5-local-administrator-password-solution-laps)
- [6. Group Policy Objects (GPO)](#6-group-policy-objects-gpo)
- [7. Organizational Unit](#7-organizational-unit)
- [8. Distinguished Name (DN)](#8-distinguished-name-dn)
- [9. User Principal Name (UPN)](#9-user-principal-name-upn)
- [10. Service Principal Name (SPN)](#10-service-principal-name-spn)
- [11. Local workgroup](#11-local-workgroup)
- [12. Active Directory Certificate Services (AD CS)](#12-active-directory-certificate-services-ad-cs)

## 1. Domain Controller
**AD Domain** - part of the network that groups users, hosts, resources. It's used to perform privileges, security policies and access management. At least one Domain Controller must be present to create Domain. The main idea behing a domain is to centralise the administration of Windows components in a single repository called Active Directory.

Each AD domain is also a DNS domain, and each AD domain controller is also a DNS nameserver – but not the other way around.

**AD Forest** - collection of domains that trust each other.

**Domain Controller** - administrator of the Domain. The server that runs AD services. Every user in the network must authenticate via Kerberos or NTLM protocol sent to the DC. DC is responsible for security policies and account management. If you have DC, you are god in the network. DC holds AD database file.

**AD Database** - AD DB file is called `ntds.dit` and it's stored on a Domain Controller server (`C:\Windows\NTDS\ntds.dit`).

### 1.1. DC Synchronisation
Typical organization has more than one DC per domain. Each domain controller runs a process called the _Knowledge Consistency Checker_ (KCC). The KCC automatically connects to other domain controllers through RPC protocol to synchronise information (e.g. policies, permissions, credentials, privileges, membership).

## 2. Active Directory & LDAP
AD is service used by Domain Controller to perform authentication, groups, users and security policies management. It is not cross-platform commercial implementation of open and cross-platform **LDAP** (_Lightweight Directory Access Protocol_) used for accessing and maintaining distributed directory information services over IP network. LDAP query is a command that asks a directory service (e.g. Active Directory) for some information.

**Security**: Even with low-privileged user an attacker can make useful enumeration and lateral movement.

## 3. AD Domain Service (AD DS)
It's catalogue that holds the information of all "objects" that exist on the network. An object might be: user, group, machine, printer, share, etc.

### 3.1. Users

- most common object type in AD.
- people - represents persons in the organisation
- services - every service (IIS or MSSQL) requires a user to run. They only have privileges needed to run their specific service (ideally).

### 3.2. Machines

- represents every computer that joins the AD domain
- every machine have Machine Account - local administrator on the computer, is not supposed to be accessed by anyone except the computer itself but it uses normal password. MA name is the computer's name + dollar sign: PC-1 (computer name) -> PC-1$ (MA name). Unless someone tampered with the account of the host, the passwords of these accounts are uncrackable. By default, they are 120 characters (UTF16) long and are automatically rotated every 30 days.

### 3.3. Security groups

- group includes AD machines and AD users as members
- group can include other groups
- several groups are created by default in a domain, e.g. Domain Admins, Domain Users, Domain Computers, Domain Controllers.

## 4. Users / accounts
AD users are different than built-in local users (these are used to manage the system locally, which is not part of the AD environment). Domain/AD accounts can use the AD services.

Types of AD Administrator accounts:

- BUILTIN\Administrator - local admin on a domain controller.d
- Domain Admin - admin to all resources in the domain.
- Enterprise Admin - forest root only.
- Schema Admin - capable of modifying domain/forest.

## 5. Local Administrator Password Solution (LAPS)
TBD

## 6. Group Policy Objects (GPO)
GPOs are collections of settings and configurations that can be applied to users and computers within a defined Organizational Unit. This is a central management tool. GPOs define policy settings that govern the behavior of user accounts and computer accounts. These settings can include security policies, desktop settings, software installation, and more. It's the way to enforce consistent configurations and security settings across multiple computers and users in a defined scope. Groups cannot have GPOs assigned - it's an OU feature.

GPOs are distributed to the network via a network share SYSVOL (stored in the DC) which points to path `C:\Windows\SYSVOL\sysvol\` on each of the DCs.

**Security**: Any AD account, no matter how low-privileged, can read the contents of the SYSVOL directory. It's nice way to check if provided domain credentials are correct.

## 7. Organizational Unit
TBD

## 8. Distinguished Name (DN)
Collection of comma-separated key and value pairs used to identify unique AD record (object). The DN consists of:

- Domain Component (DC)
- Organizational Unit (OU)
- Common Name (CN)
- others

> **Example** of DN: "CN=Administrator, OU=Users, DC=amazon, DC=com"

## 9. User Principal Name (UPN)
In AD, a User Principal Name (UPN) is the name of a system user in an email address format. It consists of the user name (logon name), separator (`@`), and domain name (UPN suffix). A UPN might not be the same as an email address. It can be used during logon process.

## 10. Service Principal Name (SPN)
TBD

## 11. Local workgroup
TBD

## 12. Active Directory Certificate Services (AD CS)
AD CS is a Microsoft's implementation of Public Key Infrastructure.
