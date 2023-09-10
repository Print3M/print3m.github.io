---
title: Active Directory notes
---

- [1. Components](#1-components)
  - [1.1. Domain Controller](#11-domain-controller)
  - [1.2. Active Directory \& LDAP](#12-active-directory--ldap)
    - [1.2.1. Security](#121-security)
  - [1.3. AD Domain Service (AD DS)](#13-ad-domain-service-ad-ds)
    - [1.3.1. Users](#131-users)
    - [1.3.2. Machines](#132-machines)
    - [1.3.3. Security groups](#133-security-groups)
  - [1.4. Users / accounts](#14-users--accounts)
  - [1.5. Group Policy Objects (GPO)](#15-group-policy-objects-gpo)
    - [1.5.1. Security](#151-security)
  - [1.6. Distinguished Name (DN)](#16-distinguished-name-dn)
  - [1.7. User Principal Name (UPN)](#17-user-principal-name-upn)
  - [1.8. Local workgroup](#18-local-workgroup)
  - [1.9. Active Directory Certificate Services (AD CS)](#19-active-directory-certificate-services-ad-cs)
- [2. Exploitation](#2-exploitation)
  - [2.1. Permission Delegation](#21-permission-delegation)
    - [2.1.1. Bloodhound](#211-bloodhound)
  - [2.2. Kerberos (Credential) Delegation](#22-kerberos-credential-delegation)
    - [2.2.1. Unconstrained Delegation](#221-unconstrained-delegation)
    - [2.2.2. Constrained Delegation](#222-constrained-delegation)
    - [2.2.3. Resource-Based Constrained Delegation](#223-resource-based-constrained-delegation)
  - [2.3. Automated Relays](#23-automated-relays)
  - [2.4. Golden Ticket](#24-golden-ticket)
- [3. Persistence](#3-persistence)

## 1. Components

### 1.1. Domain Controller
**AD Domain** - part of the network that groups users, hosts, resources. It's used to perform privileges, security policies and access management. At least one Domain Controller must be present to create Domain. The main idea behing a domain is to centralise the administration of Windows components in a single repository called Active Directory.

Each AD domain is also a DNS domain, and each AD domain controller is also a DNS nameserver – but not the other way around.

**AD Forest** - collection of domains that trust each other.

**Domain Controller** - administrator of the Domain. The server that runs AD services. Every user in the network must authenticate via Kerberos or NTLM protocol sent to the DC. DC is responsible for security policies and account management. If you have DC, you are god in the network. DC holds AD database file.

### 1.2. Active Directory & LDAP
AD is service used by Domain Controller to perform authentication, groups, users and security policies management. It is not cross-platform commercial implementation of open and cross-platform **LDAP** (_Lightweight Directory Access Protocol_) used for accessing and maintaining distributed directory information services over IP network. LDAP query is a command that asks a directory service (e.g. Active Directory) for some information.

AD database file is called NTDS.dit and it's stored on Domain Controller server.

#### 1.2.1. Security
Even with low-privileged user an attacker can make useful enumeration and lateral movement.

### 1.3. AD Domain Service (AD DS)
It's catalogue that holds the information of all "objects" that exist on the network. An object might be: user, group, machine, printer, share, etc.

#### 1.3.1. Users

- most common object type in AD.
- people - represents persons in the organisation
- services - every service (IIS or MSSQL) requires a user to run. They only have privileges needed to run their specific service (ideally).

#### 1.3.2. Machines

- represents every computer that joins the AD domain
- every machine have Machine Account - local administrator on the computer, is not supposed to be accessed by anyone except the computer itself but it uses normal password. MA name is the computer's name + dollar sign: PC-1 (computer name) -> PC-1$ (MA name). Unless someone tampered with the account of the host, the passwords of these accounts are uncrackable. By default, they are 120 characters (UTF16) long and are automatically rotated every 30 days.

#### 1.3.3. Security groups

- group includes AD machines and AD users as members
- group can include other groups
- several groups are created by default in a domain, e.g. Domain Admins, Domain Users, Domain Computers, Domain Controllers.

### 1.4. Users / accounts
AD users are different than built-in local users (these are used to manage the system locally, which is not part of the AD environment). Domain/AD accounts can use the AD services.

Types of AD Administrator accounts:

- BUILTIN\Administrator - local admin on a domain controller.d
- Domain Admin - admin to all resources in the domain.
- Enterprise Admin - forest root only.
- Schema Admin - capable of modifying domain/forest.

### 1.5. Group Policy Objects (GPO)
Collection of settings (rules) that can be applied to Organizational Unit (organized objects: users, hosts, etc.). GPOs are distributed to the network via a network share SYSVOL (stored in the DC) which points to path `C:\Windows\SYSVOL\sysvol\` on each of the DCs.

#### 1.5.1. Security
Any AD account, no matter how low-privileged, can read the contents of the SYSVOL directory. It's nice way to **check if provided domain credentials are correct**.

### 1.6. Distinguished Name (DN)
Collection of comma-separated key and value pairs used to identify unique AD record (object). The DN consists of:

- Domain Component (DC)
- Organizational Unit Name (OU)
- Common Name (CN)
- others

> **Example** of DN: "CN=Administrator, OU=Users, DC=amazon, DC=com"

### 1.7. User Principal Name (UPN)
In AD, a User Principal Name (UPN) is the name of a system user in an email address format. It consists of the user name (logon name), separator (`@`), and domain name (UPN suffix). A UPN might not be the same as an email address. It can be used during logon process.

### 1.8. Local workgroup
TBD

### 1.9. Active Directory Certificate Services (AD CS)
AD CS is a Microsoft's implementation of Public Key Infrastructure.

## 2. Exploitation

### 2.1. Permission Delegation
AD can delegate permissions using a feature called _Permission Delegation_. For example: in an organization three users have access to AD credentials. It would be hard to manage all the tasks by only 3 people so they can delegate the permission e.g. to change a user's password to the Helpdesk team. Now the helpdesk team has permission to change passwords. In large organization there is a problem to keep track of all delegations and keep them secure. Misconfigurations are very common.

If you accidentally can add yourself for example to the _IT Support_ group and then you have permissions to change a password of any _Admins_, you can escalate your privileges.

#### 2.1.1. Bloodhound
Some misconfigured ACEs associated with user groups can lead to interesting vulnerabilities. Bloodhound identifies potential mosconfigurations and explains how to exploit them:

- `ForceChangePassword` - reset the user's current password.
- `AddMembers` - add users, groups or machines to the target group.
- `GenericAll` - complete control over the object (add members and reset password included).
- `GenericWrite` - update any non-protected parameters of target object (update the `scriptPath` parameter included).
- `WriteOwner` - update owner of the target object (making ourselves the owner included).
- `WriteDACL` - write new ACEs to the target object's DACL (writing full access ACE included).
- `AllExtendedRights` - perform any action associated with extended AD rights against the target object (changing user's password included).

### 2.2. Kerberos (Credential) Delegation

> **NOTE**: Most often in the AD context the _Kerberos Delegation_ is the one being duscussed, not _Permission Delegation_.

The practical use of Kerberos delegation is to enable an application to access resources hosted on a different server.

#### 2.2.1. Unconstrained Delegation
_Unconstrained Delegation_ provides no limits to the delegation.

#### 2.2.2. Constrained Delegation
_Constrained Delegation_ restricts what services an account can be delegated to, limiting exposure if an account is compromised. Exploiting Constrained Delegation is more complex than exploiting Unconstrained Delegation since the delegated account can't be used for everything.  

#### 2.2.3. Resource-Based Constrained Delegation
TBD

### 2.3. Automated Relays
All Windows hosts have a _machine account_. Passwords of these accounts are uncrackable. They are used quite a bit in different services. It's common to see that one machine has admin rights over another machine.

TBD

### 2.4. Golden Ticket
In order to forge TGTs, we the following information are required:

- The FQDN of the domain
- The Security Identifier (SID) of the domain
- The username of the account we want to impersonate
- The `krbtgt` password hash

The first three are easy to recover. The last one requires a domain compromise since the KRBTGT password hash is only stored on domain controllers. It can be retrieved using `mimikatz`.

## 3. Persistence
