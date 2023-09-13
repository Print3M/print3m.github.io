---
title: Network authentication protocols
---

- [1. General](#1-general)
- [2. LDAP](#2-ldap)
  - [2.1. Anonymous bind](#21-anonymous-bind)
  - [2.2. LDAP Pass-back attack](#22-ldap-pass-back-attack)
- [3. NTLM (aka Net-NTML)](#3-ntlm-aka-net-ntml)
  - [3.1. Workflow of NTLM authentication](#31-workflow-of-ntlm-authentication)
  - [3.2. Security](#32-security)
  - [3.3. Hashes](#33-hashes)
- [4. Kerberos](#4-kerberos)
  - [4.1. Key Distribution Center (KDC)](#41-key-distribution-center-kdc)
  - [4.2. Ticket Granting Ticket (TGT)](#42-ticket-granting-ticket-tgt)
  - [4.3. Security](#43-security)

## 1. General
Using Windows domains, all credentials are stored in the DC. Every authentication is performed via DC, using (usually) one of two protocols:

- Kerberos
- NTLM

## 2. LDAP
LDAP is used to communicate with directory services (e.g. Active Directory). It provides built-in basic LDAP authentication mechanism (username and password) but it is rarely used. Most often enterprise networks want to use more convenient (and secure) auth methods. LDAP protocol supports _pluggable_ external authentication methods. This feature is called SASL (_Simple Authentication and Security Layer_). When Active Directory service is installed, Kerberos or NTLM authentication over LDAP is implemented for sure.

### 2.1. Anonymous bind
Sometimes it is possible to perform LDAP anonymous bind (no authentication), execute LDAP queries and retrieve interesting data. LDAP anonymous bind should be disabled.

### 2.2. LDAP Pass-back attack
If we can alter the LDAP configuration in the application (e.g. printer config), we can force device to try to authenticate with the attacker IP, instead of DC LDAP server. We can intercept this auth attempt and recover the LDAP credentials.

## 3. NTLM (aka Net-NTML)
NTLM was the default authentication protocol used in old Windows versions. If for any reason Kerberos fails, NTLM will be used instead. It's still commonly used especially in large networks due to backward compatibility and smaller infrastructure overhead.

> **NOTE**: NTLM (v1 or v2) is the protocol, not the hash!

### 3.1. Workflow of NTLM authentication
CLIENT => SERVER => DOMAIN CONTROLER

1. The _client_ sends an authentication request to the _server_.
2. The _server_ generates a random number and sends it to the _client_ (_challenge_).
3. The _client_ combines his NTLM password hash with the challenge and sends it back to the _server_ for verification (_response_).
4. The _server_ forwards both the _challenge_ and the _response_ to the _DC_ for verification.
5. The _DC_ compares the _challenge_ and the _response_ and sends the result to the _server_.  
6. The server forwards result to the _client_.

### 3.2. Security

- NTLM uses a challenge/response mechanism, which exposes its password to offline cracking when responding to the challenge.
- NTLMv1 hashes could be cracked in seconds with today’s computing. They are always the same length and are not salted.
- NTLMv2 is a little better, since it variables length and salted hash. Even though hash it's salted before it's sent, it's saved unsalted in a machine’s memory.

### 3.3. Hashes
Windows store user's account password using two hashes. These hashes are stored in the local SAM database or the domain NTDS file.

**LM hash** (_Lan Manager_) is a very weak hash function used for storing users' passwords. If enabled, it's stored along with NT hash in the format `LM-hash:NT-hash`. Nowadays, most often it's disabled (it's highly recommended) and only the NT hash is generated. LM hash requires a short password and can be cracked within seconds.

**NT hash** is often called misleadingly an `NTLM` hash. NT hash is the way users' passwords are stored on modern Windows OS. It is the one used to **pass-the-hash**. NTLMv1, NTLMv2 and Kerberos all use the NT hash.

## 4. Kerberos
Kerberos is the authentication protocol. It’s the default authentication protocol on Windows versions above Windows 2000, replacing the NTLM.

Security advantages over NTLM:

- More secure: No password stored locally or sent over the net.
- Supports MFA (Multi Factor Authentication).

### 4.1. Key Distribution Center (KDC)
KDC is a service usually installed on the Domain Controller. Its main task is to create Kerberos tickets on the network.

### 4.2. Ticket Granting Ticket (TGT)
TGT was designed to avoid asking the user for a password all the time. It works like a authorization token to ask for other services - if you have TGT, you are authorized.

User sends a timestamp symetrically encrypted with the **Key** derived from the user's password. KDC has this Key as well so both sides are able to verify each other. It's used in during the pre-authentication process (it might be disabled making Kerberos prone to _Kerberoast_ attack).

When the requester's identity is verified, The KDC generates a TGT. The TGT is symmetrically encrypted using the `krbtgt` account's password hash and it includes a **Session Key** (value used to identify single logon session) so the KDC doesn't need to store the Session Key (it can be rocovered by decrypting the TGT).

> **NOTE**: `krbtgt` account acts as the service account for the KDC service, which handles all Kerberos ticket requests.

### 4.3. Security
LDAP application which is exposed on the internet might be password-sprayed as good as standard NTLM auth. But that app has its own credentials for LDAP quering DC. They are used to check if our credentials are correct. Now we don't have to hack users AD credentials. We might just hack the app AD credentials - one more vector to attack. App's credentials are most often stored in the plain text on the app's server (config files).
