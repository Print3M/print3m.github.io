---
title: Active Directory overview
---

- [1. AD Structure](#1-ad-structure)
  - [1.1. Forest](#11-forest)
  - [1.2. Domain](#12-domain)
  - [1.3. Organization Unit (OU)](#13-organization-unit-ou)
- [2. Domain Controller](#2-domain-controller)
  - [2.1. DC Synchronisation](#21-dc-synchronisation)
- [3. Active Directory \& LDAP](#3-active-directory--ldap)
- [4. AD Domain Service (AD DS)](#4-ad-domain-service-ad-ds)
  - [4.1. Users](#41-users)
  - [4.2. Machines](#42-machines)
  - [4.3. Security groups](#43-security-groups)
- [5. Users / accounts](#5-users--accounts)
- [6. Local Administrator Password Solution (LAPS)](#6-local-administrator-password-solution-laps)
- [7. Group Policy Objects (GPO)](#7-group-policy-objects-gpo)
  - [7.1. Restrictive Groups](#71-restrictive-groups)
- [8. Organizational Unit](#8-organizational-unit)
- [9. Distinguished Name (DN)](#9-distinguished-name-dn)
- [10. User Principal Name (UPN)](#10-user-principal-name-upn)
- [11. Service Principal Name (SPN)](#11-service-principal-name-spn)
- [12. Local workgroup](#12-local-workgroup)
- [13. Active Directory Certificate Services (AD CS)](#13-active-directory-certificate-services-ad-cs)
- [14. Computer objects](#14-computer-objects)
- [15. Trust](#15-trust)
  - [15.1. Domain trusts](#151-domain-trusts)
  - [15.2. Forest trusts](#152-forest-trusts)

## 1. AD Structure
Forests, domains and OUs are the basic blocks of any AD structure.

### 1.1. Forest
**Forrest** is a collection of domains that trust each other.

### 1.2. Domain
**Domain** is a part of the network that groups users, hosts, resources. It's used to perform privileges, security policies and access management. At least one Domain Controller must be present to create Domain. The main idea behind a domain is to centralise the administration of Windows components in a single repository called Active Directory. Domain consists of multiple OUs.

### 1.3. Organization Unit (OU)
**Organization Unit** is a...

## 2. Domain Controller
**Domain Controller** is an administrator of the Domain. The server that runs AD services. Every user in the network must authenticate via Kerberos or NTLM protocol sent to the DC. DC is responsible for security policies and account management. If you have DC, you are god in the network. DC holds AD database file.

### 2.1. DC Synchronisation
Typical organization has more than one DC per domain. Each domain controller runs a process called the _Knowledge Consistency Checker_ (KCC). The KCC automatically connects to other domain controllers through RPC protocol to synchronise information (e.g. policies, permissions, credentials, privileges, membership).

## 3. Active Directory & LDAP
AD is service used by Domain Controller to perform authentication, groups, users and security policies management. It is not cross-platform commercial implementation of open and cross-platform **LDAP** (_Lightweight Directory Access Protocol_) used for accessing and maintaining distributed directory information services over IP network. LDAP query is a command that asks a directory service (e.g. Active Directory) for some information.

**Security**: Even with low-privileged user an attacker can make useful enumeration and lateral movement.

## 4. AD Domain Service (AD DS)
It's catalogue that holds the information of all "objects" that exist on the network. An object might be: user, group, machine, printer, share, etc.

### 4.1. Users

- most common object type in AD.
- people - represents persons in the organisation
- services - every service (IIS or MSSQL) requires a user to run. They only have privileges needed to run their specific service (ideally).

### 4.2. Machines

- represents every computer that joins the AD domain
- every machine have Machine Account - local administrator on the computer, is not supposed to be accessed by anyone except the computer itself but it uses normal password. MA name is the computer's name + dollar sign: PC-1 (computer name) -> PC-1$ (MA name). Unless someone tampered with the account of the host, the passwords of these accounts are uncrackable. By default, they are 120 characters (UTF16) long and are automatically rotated every 30 days.

### 4.3. Security groups

- group includes AD machines and AD users as members
- group can include other groups
- several groups are created by default in a domain, e.g. Domain Admins, Domain Users, Domain Computers, Domain Controllers.

There are important security groups (e.g. `Enterprise Admins`, `Schema Admins`, `Enterprise Key Admins`) that are saved only in the **root domain** of the forest. To get them usually the `-server <root-domain>` property is needed.

## 5. Users / accounts
AD users are different than built-in local users (these are used to manage the system locally, which is not part of the AD environment). Domain/AD accounts can use the AD services.

Types of AD Administrator accounts:

- BUILTIN\Administrator - local admin on a domain controller.d
- Domain Admin - admin to all resources in the domain.
- Enterprise Admin - forest root only.
- Schema Admin - capable of modifying domain/forest.

## 6. Local Administrator Password Solution (LAPS)
TBD

## 7. Group Policy Objects (GPO)
GPOs are collections of settings and configurations that can be applied to users and computers within a defined Organizational Unit. This is a central management tool. GPOs define policy settings that govern the behavior of user accounts and computer accounts. These settings can include security policies, desktop settings, software installation, startup/shutdown scripts, software installation, registry-based settings and more. There are more than 1500 rules to configure. It's the way to enforce consistent configurations and security settings across multiple computers and users in a defined scope. Groups cannot have GPOs assigned - it's an OU feature.

GPOs are distributed to the network via a network share SYSVOL (stored in the DC) which points to path `C:\Windows\SYSVOL\sysvol\` on each of the DCs.

**Security**: Any AD account, no matter how low-privileged, can read the contents of the SYSVOL directory. It's nice way to check if provided domain credentials are correct. GPOs are often abused for privilege escalation, backdoors and persistence techniques.

### 7.1. Restrictive Groups
TBD

## 8. Organizational Unit
TBD

## 9. Distinguished Name (DN)
Collection of comma-separated key and value pairs used to identify unique AD record (object). The DN consists of:

- Domain Component (DC)
- Organizational Unit (OU)
- Common Name (CN)
- others

> **Example** of DN: "CN=Administrator, OU=Users, DC=amazon, DC=com"

## 10. User Principal Name (UPN)
User Principal Name (UPN) is the name of a system user in an email address format. It consists of the user name (logon name), separator (`@`), and domain name (UPN suffix). **A UPN might not be the same as an email address**. It can be used during logon process.

## 11. Service Principal Name (SPN)
Service Principal Name (SPN) is a unique (within a domain) indentifier assigned to a service in a network that uses the Kerberos authentication. SPNs are used to associate a service with its account (usually a service account). The primary purpose of an SPN is to enable Kerberos authentication to locate the service in the network. When a user requests access to a service, it uses the service's SPN to request a TGT.

SPNs have standarized format `service_class/host:port/service_name`.

- `service_class` - general class of the service (e.g. HTTP for web services).
- `host` - hostname or IP address of the machine where the service is running.
- `port` - port number on which the service is listening.
- `service_name` - the name of the specific service.

SPNs are associated with service accounts which are used to run the corresponding services.

## 12. Local workgroup
TBD

## 13. Active Directory Certificate Services (AD CS)
AD CS is a Microsoft's implementation of Public Key Infrastructure.

## 14. Computer objects
Executing the `Get-ADComputer -Filter *` command we can list all computer objects present in the domain. **It's not guaranteed that any of these objects represents an actual physcial machine**. Any administrator is able to create a computer object in the domain. We can test their physical existence using ICMP echo packets (this method may give us false-negatives).

## 15. Trust
Trust is a relationship between **two domains** or **two forests**. Trust allows users of one domain/forest to access resources in the other domain/forest. Trust relationship in a domain is represented by _Trusted Domain Objects_ (TDOs).

Trust can be defined by different parameters:

- Direction:
  - One-way (unidirectional) - users in the trusted domain can access resources in the trusting domain but other way around it's not true. The trusting domain has trust settings enabled.
  - Two-way (bidirectional) - users of both domains can access resources in the other domain.
- Transitivity:
  - Transitive - can be extended to establish trust relationship with other domains. Example: if domain A trusts domain B and domain B trusts domain C, then the domain A trusts domain C.
  - Nontransitive - cannot be extended to other domains in the forest. It's default between two domains in different forests when forests do not have a trust relationship.

### 15.1. Domain trusts

#### Automatic Trust

- Parent-child trust - created automatically between the new domain and its parent in the namespace hierarchy.
- It's always bidirectional transitive type of trust.
- In result, all domains in a forest by default trust each other. Microsoft consider a forest as a security boundary of a network - not a domain.

#### Shortcut Trust

- Used to reduce access times in a complex trust networks.
- It can be uni- or bidirectional transitive.

#### External Trust

- Between two domains in different forests when forests do not have a trust relationship.
- It can be uni- or bidirectional nontransitive only (!)

### 15.2. Forest trusts

- Established between forest root domains.
- Cannot be extended to a third forest.
- Can be uni- or bidirectional, transitive or nontransitive.
