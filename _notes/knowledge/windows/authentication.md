---
title: Network authentication protocols
---

Using Windows domains, all credentials are stored in the DC. Every authentication is performed via DC, using one of two protocols:

- Kerberos
- NTLM

There is also internal (third-party to DC) method: LDAP auth.

## NTLM (aka Net-NTML)
NTLM was the default authentication protocol used in old Windows versions. If for any reason Kerberos fails, NTLM will be used instead.

### Workflow of AD authentication
CLIENT => SERVER => DOMAIN CONTROLER

1. The _client_ sends an authentication request to the _server_.
2. The _server_ generates a random number and sends it to the _client_ (_challenge_).
3. The _client_ combines his NTLM password hash with the challenge and sends it back to the _server_ for verification (_response_).
4. The _server_ forwards both the _challenge_ and the _response_ to the _DC_ for verification.
5. The _DC_ compares the _challenge_ and the _response_ and sends the result to the _server_.  
6. The server forwards result to the _client_.

## Security

- NTLM uses a challenge/response mechanism, which exposes its password to offline cracking when responding to the challenge.
- NTLMv1 hashes could be cracked in seconds with today’s computing. They are always the same length and are not salted.
- NTLMv2 is a little better, since it variables length and salted hash. Even though hash it's salted before it's sent, it's saved unsalted in a machine’s memory.

## Kerberos
Kerberos is the authentication protocol. It’s the default authentication protocol on Windows versions above Windows 2000, replacing the NTLM.

Security advantages over NTLM:

- More secure: No password stored locally or sent over the net.
- Supports MFA (Multi Factor Authentication).

## LDAP
LDAP is another method of AD authentication. It is similar to NTLM auth but the application directly verifies the user's credentials (don't neeed to pass them to AD for verification). Popular mechanism with third-party applications which integrate with AD. E.g. Gitlab, Jenkins, printers, etc. It's more like auth mechanism between third-party service and DC.

### Security
LDAP application which is exposed on the internet might be password-sprayed good as standard NTLM auth. But that app has its own credentials for LDAP quering DC. They are used to check if our credentials are correct. Now we don't have to hack users AD credentials. We might just hack the app AD credentials - one more vector to attack. App's credentials are most often stored in the plain text on the app's server (config files).

### LDAP Pass-back attack
If we can alter the LDAP configuration in the application (e.g. printer config), we can force device to try to authenticate with the attacker IP, instead of DC LDAP server. We can intercept this auth attempt and recover the LDAP credentials.
