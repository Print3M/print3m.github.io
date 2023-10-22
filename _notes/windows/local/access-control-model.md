---
title: Windows Access Control Model
---

- [1. Securable objects](#1-securable-objects)
  - [1.1. Security Descriptor](#11-security-descriptor)
- [2. Security principal](#2-security-principal)
  - [2.1. Logon process](#21-logon-process)
  - [2.2. Security (Access) Token](#22-security-access-token)
- [3. User Account Control (UAC)](#3-user-account-control-uac)
  - [3.1. UAC Elevation](#31-uac-elevation)
  - [3.2. Integrity Levels](#32-integrity-levels)
- [4. Constrained Language Mode (CLM)](#4-constrained-language-mode-clm)
- [5. Special accounts](#5-special-accounts)
  - [5.1. SYSTEM](#51-system)
  - [5.2. Administrator](#52-administrator)
  - [5.3. Guest](#53-guest)

## 1. Securable objects
A securable object is an object that can have a Security Descriptor:

- files and directories
- processes and threads
- named and anonymous pipes
- services
- access tokens
- registry keys
- [and more](https://learn.microsoft.com/en-us/windows/win32/secauthz/securable-objects)

### 1.1. Security Descriptor
Security Descriptor is the highest-level concept in Windows access control model. It encompasses all the components required to define and control access to an object. Each securable object in the system has its own security descriptor.

Security descriptor includes:

- ACL
  - DACL
  - SACL (optional)
- Owner SID
- Primary Group SID
- Control Flags

```powershell
# Get Security Descriptor of an object.
Get-Acl <object>
```

**Access Control List** (ACL) is more abstract term. It consists of DACL and SACL (optionally) within a security descriptor.

#### 1.1.1. Discretionary Access Control List (DACL)
DACL is responsible for specifying which users or groups are allowed or denied to access a particular object and the specific permissions granted or denied to them. It governs who and how can access and manipulate this object on the system.

DACL contains **Access Control Entries** (ACEs). ACEs are fundamental components of DACL. They specify permissions granted to a user or group. Each ACE defines:

- ACE Type - _allow_ (explicitly grant permissions) or _deny_ ()
- Security Principal - a user or group to which the permissions apply.
- Permissions - what actions the principal is allowed or denied. They can include actions such as read, write, execute, delete and so on. They are represented as a combination of flags or access rights.
- Inheritence Flags - how the permissions are inherited by child objects.

The order of ACEs matters. _Deny_ ACEs are evaluated first, followed by _Allow_ ACEs. The first applicable ACE encountered determines whether access is allowed or denied.

#### 1.1.2. System Access Control List (SACL)
SACL is used for auditing purposes. It specifies which types of access attempts on the object should be logged and audited. It does not control access but provides a record of access-related events.

ACEs of SACL define the audit and logging policy for specific users, groups and actions. For example, they can define that an access to the object done by specific group of users needs to be logged.

#### 1.1.3. Owner SID
That identifies the security principal who owns or has primary control over a securable object. The owner of an object can modify ACL and transfer ownership. Basically the owner has full control over the object.

## 2. Security principal
Security Principal refers to any entity that can be authenticated and assigned permissions within the system's security model. Each security principal is represented in the operating system by a unique security identifier (SID).

- user accounts
- groups
- computer accounts
- service accounts

### 2.1. Logon process
The Windows OS require all users to log on (authenticate itself) to the computer with a valid account to access local and network resources. The logon process secures resources. There is couple of ways to perform logon process. A successful logon results in the issuance of an Access Token.

#### 2.1.1. Interactive Logon
It's a logon where a user uses a local keyboard to enter credentials in the logon screen. Interactive logon can be performed using:

- Local user account - authenticates against a local SAM database.
- Domain user account - authenticates against DC. Domain can be defined in the domain field or typed within UPN in the username field.

Every time a user logins interactively `explorer.exe` is executed under the logged user. It's the main GUI process of the logged user.

#### 2.1.2. Remote Interactive Logon
Looks the same as Interactive Logon but initiated remotely during RDP session. There are many nuances in how they are reported, logged in various security event logs etc.

#### 2.1.3. Network Logon
Network Logon can only be used after user, service, or computer authentication has already taken place. This logon method does not use the credentials entry dialog boxes. Previously established credentials (during Interactive Logon for example) is used. This process confirms the user's identity to a network resource using Kerberos or NTLM protocol. For example, Network Logon is performed when accessing shared network resources or connecting to a machine via WinRM. This process is typically invisible to the user unless alternate credentials have to be provided.

#### 2.1.4. Service Logon
TBD

### 2.2. Security (Access) Token
Access Token, also known as _Security Token_, is a data structure that represents the security context of a user or process. It's used by the OS to check permissions and privileges of an user or process. It's issued after a successfull logon process. Most important properties of an Access Token:

- Identity Information - username, domain and SID.
- Group Memberships - list of security groups to which the user belongs.
- User Rights - list of actions the user can do.
- Authentication Information - the token may contain information about how the user was authenticated, such as the authentication protocol used (e.g. Kerberos or NTLM) and the logon type (e.g., interactive, network, service).
- Token Type - _primary_ or _impersonation_.
- Integrity Level - used in MIC to control access between processes.

> **NOTE**: In general, each user session is associated with a single Access Token. However, there are some scenarios in which a user can have more than one Access Token:
>
> - Primary Token and Impersonation Token
> - Delegation Tokens - when a user's credentials are delegated to access remote resources, a delegation token may be created to represent the user's security context on the remote server.

```powershell
# Get detailed information about the user's security token
whoami /all
```

#### 2.2.1. Security Identifier (SID)
SID is a unique alphanumeric string that represents the security principal. SIDs are a fundamental part of the Windows security model and play a crucial role in access control and security.

Windows defines several well-known SIDs for built-in groups and special identities, like "Everyone" or "Administrators".

> **Example SID**: `S-1-5-21-3623811015-3361044348-30300820-1013`.

#### 2.2.2. Rights (privileges)
[Full list of Windows rights](https://learn.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/user-rights-assignment).

User rights are sometimes called _privileges_. They define what actions a user or a process is allowed to perform at the system level. They are not used to control access to individual objects. Rights affect the overall behavior and capabilities of user accounts or processes in the entire system. For example, `SeBackupPrivilege` allows user to ignore DACL when performing backups of files and directories.

#### 2.2.3. Token Type
Tokens can be categorized as _Primary Tokens_ or _Impersonation Tokens_:

- Primary Token - represents the original security context of a user or process. It is created during the logon process.
- Impersonation Token - is issued when a process temporarily assumes the security context of another user. Impersonation allows a process to perform actions on behalf of a different user but with restricted privileges.

## 3. User Account Control (UAC)
UAC is mechanism introduced in Windows Vista. UAC is a security feature that forces any new process to run in the security context of a non-privileged account by default.

For example, when a **local** user logs into a system, the current session doesn't run with full administrator permissions even if the user is a member of the _Administrators_ group (almost every user by default). When UAC is enabled, a running application doesn't inherit access token privileges of the privileged user by default. Same situation occurs when local account is connected via RPC, SMB or WinRM, etc. The only local account that will get full privileges by default is the default local **Administrator** account itself.

AD account (AD), which is a member of the AD _Administrators_ group, will run with a full administrator acces and UAC won't be in effect.

### 3.1. UAC Elevation
When an operation requires higher privileges, the user will be prompted to confirm if they permit to elevate privileges for that particual application. It is done in a form of yellow popup (GUI) with `yes` or `no` question. `Run as administrator` option requests elevation.

### 3.2. Integrity Levels
UAC works on a basis of _Mandatory Integrity Control_ (MIC). MIC is a concept of additional security control over resources taking into account their **Integrity Level** (IL). Integrity Level is an attribute of processes and users. In general, a user with a higher IL can use processes with lower or equal ILs. IL of a process can be checked using `Process Hacker`. IL of the current user can be checked using `whoami /groups` (_Mandatory Label_).

- LOW - very limited permissions.
- MEDIUM - assigned to standard users and members of the _Administrators_ group.
- HIGH - used by elevated tokens if UAC is enabled. If UAC is disabled, all administrators use this IL by default.
- SYSTEM - reserved for system use.

During logon, non-administrators receive a single access token with medium IL. Administrators receive so-called _Filtered Token_ used for regular operations (medium IL) and _Elevated Token_ with full admin privileges (high IL).

## 4. Constrained Language Mode (CLM)
CLM is a Powershell feature. It consists of a number of restrictions that limit unconstrained Powershell code execution on a system. There is [plenty of different restrictions](https://devblogs.microsoft.com/powershell/powershell-constrained-language-mode/#what-does-constrained-language-constrain). It's designed to support day-to-day administrative tasks, yet restrict access to sensitive language elements that can be used to invoke arbitrary Windows APIs.

## 5. Special accounts

### 5.1. SYSTEM
SYSTEM is an internal account which doesn't show up in User Manager.

- the highest privilege level in the Windows user model.
- used by the OS and by services running under Windows.
- can't be added to any groups and cannot have user rights assigned to it.

If the computer is joined to a domain, processes running as SYSTEM can access domain servers in the context of the computer's domain account without credentials.

### 5.2. Administrator
Every computer has Administrator account. It's the first account that is created during the Windows installation. Processes running as Administrator have no access to domain computers unless the credentials are explicitly provided.

Administrator has following privileges:

- full control of the files, directories, services, and other resources on the local computer.
- creation of other local users, assign user rights, and assign permissions.
- can't be deleted or locked out, but it can be renamed or disabled.
- it's member of the Adminitrators group and it can't be removed from the Administrators group but it can be renamed.

### 5.3. Guest
TBD
