---
title: Windows default security settings
createdAt: 29/04/2024
---

Below is a set of default Windows client and server settings right after installing and configuring the domain. List compiled from my own observations, may vary between Windows versions. I used Windows Server 2022 Evaluation and Windows 10 Evaluation systems. This can be useful for [domain lateral movement](https://securitree.xyz/windows-lateral-movement) or [domain privilege escalation](https://securitree.xyz/windows-domain-privesc).

> **NOTE**: this list may be updated over time.

## Domain settings

* There is `domain\Administrator` domain account in `Domain Admins`, `Schema Admins`, `Enterprise Admins`, `Group Policy Creator`, and local `Administrators` group on DC.
* There is `krbtgt` in `Domain Users` group.
* There is `Guest` account in domain.
* An example: `ADLAB\hpotter`, `adlab.local\hpotter`, `adlab\hpotter` and even `hpotter` (wihout domain part) works the same in most of the logons. Logon by default uses domain user. If there are two users (local and domain) with the same name, it uses the local user first and domain part must be specified explictly to use the domain user.
* `Domain Admins`, `Enterprise Admins`, `Administrators` and `Domain Controllers` have privileges to perform [DCSync](https://securitree.xyz/windows-domain-privesc/dcsync) operation.

## Domain Controller settings

* Domain `domain\Administrator` account is local Administrator on DC as well. There's no other (local-only) `Administrator` account on DC - only domain one.
* `Domain Admins` are placed in local `Administrators` group on DC.
* There is Active Directory PowerShell module present on Windows Server.
* Remote UAC affects non-built-in local Administrators. [Read more here](https://securitree.xyz/windows-lateral-movement/remote-uac).
* [WinRM](https://securitree.xyz/windows-lateral-movement/winrm) is enabled on DC (`winrs` connection to DC does work).
* [RDP](https://securitree.xyz/windows-lateral-movement/rdp) service is disabled.
* RDP Pass-The-Hash (Restricted Admin Mode) is disabled. [Read more here](https://securitree.xyz/windows-lateral-movement/rdp).
* [WMI](https://securitree.xyz/windows-lateral-movement/ms-wmi) is allowed on firewall.
* SMB is allowed on firewall. This is especially important for [RPC-named-pipe-based lateral movement techniques](https://securitree.xyz/windows-lateral-movement/ms-rpc) such as [PsExec or SmbExec](https://securitree.xyz/windows-lateral-movement/ms-scmr).

Default Domain Controller (with AD DS enabled) port scan:

```text
Not shown: 989 filtered tcp ports (no-response)
PORT     STATE SERVICE          REASON
53/tcp   open  domain           syn-ack ttl 128
88/tcp   open  kerberos-sec     syn-ack ttl 128
135/tcp  open  msrpc            syn-ack ttl 128
139/tcp  open  netbios-ssn      syn-ack ttl 128
389/tcp  open  ldap             syn-ack ttl 128
445/tcp  open  microsoft-ds     syn-ack ttl 128
464/tcp  open  kpasswd5         syn-ack ttl 128
593/tcp  open  http-rpc-epmap   syn-ack ttl 128
636/tcp  open  ldapssl          syn-ack ttl 128
3268/tcp open  globalcatLDAP    syn-ack ttl 128
3269/tcp open  globalcatLDAPssl syn-ack ttl 128
```

Default DC SMB shares from non-admin user point of view. Admin user has access to all of the SMB shares.

```text
ADMIN$               NO ACCESS       Remote Admin
C$                   NO ACCESS       Default share
IPC$                 READ ONLY       Remote IPC
NETLOGON             READ ONLY       Logon server share 
SYSVOL               READ ONLY       Logon server share
```

## Windows client settings

* The local `Administrator` account is present on a machine but it is disabled (the presence of a domain doesn't matter).
* `Domain Admins` group is added to local `Administrators` group on every machine in the domain (after domain join). Because of that, any domain admin is local admin as well.
* Remote UAC affects non-built-in local Administrators. [Read more here](https://securitree.xyz/windows-lateral-movement/remote-uac).
* There's no Active Directory PowerShell module on machines (the presence of a domain doesn't matter).
* [WinRM](https://securitree.xyz/windows-lateral-movement/winrm) is disabled.
* [RDP](https://securitree.xyz/windows-lateral-movement/rdp) service is disabled.
* RDP Pass-The-Hash (Restricted Admin Mode) is disabled. [Read more here](https://securitree.xyz/windows-lateral-movement/rdp).
* [WMI](https://securitree.xyz/windows-lateral-movement/ms-wmi) is not allowed on firewall.
* SMB shares are present but SMB is not allowed on firewall. The firewall SMB exception is enabled when, for example, a new share is created. This is especially important for [RPC-named-pipe-based lateral movement techniques](https://securitree.xyz/windows-lateral-movement/ms-rpc) such as [PsExec or SmbExec](https://securitree.xyz/windows-lateral-movement/ms-scmr).

Default Windows client machine open ports before domain connection:

```text
Not shown: 999 filtered tcp ports (no-response)
PORT     STATE SERVICE REASON
5357/tcp open  wsdapi  syn-ack ttl 128
```

Default Windows client machine open ports after domain connection:

```text
135/tcp  open  msrpc   syn-ack ttl 128
2869/tcp open  icslap  syn-ack ttl 128
```
