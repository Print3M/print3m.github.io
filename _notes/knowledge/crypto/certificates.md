---
title: Certificates notes
---

## Digitial signature

A digital signature is the way of ensuring two things:

1. Receiver can be sure who sent the message.
2. The message wasn't changed during the travel.

```text
                           Shared values:
       Prv-A                   Pub-A              
                            
       User-A                                            User-B     
|'''''''''''''''''|                             |'''''''''''''''''''''''|
|     Document    | ----,                 ,---> |        Document       |
|                 |     |                 |     |                       |
|----Signature----|     |   *Document *   |     |---Sig. Verification---|
|                 |     +---*    +    *---'     |                       |
| +hash(Document) |     |   *Signature*         | h = Signature - Pub-A |
| +Prv-A          |     |                       | hash(Document) == h   |
| =Signature      | ----'                       |                       |
|,,,,,,,,,,,,,,,,,|                             |,,,,,,,,,,,,,,,,,,,,,,,|
```

The hash of a message is encrypted using a sender's private key. It can be decrypted only with correspoding public key (it ensures the sender identity). The hash is calculated twice: on the sender side and verified by a receiver. Even if the signature was decrypted along the way (in order to change the message and the hash), it could not be changed and encrypted once again, because the private key is secret.

## Certificates

The problem with asymmetric encryption is "how I can be sure that the public key really belongs to the sender?". If the public key was substituted, the signature could be decrypted along the way (man-in-the-middle attack) and changed using the attacker's private key. There must be a way to prove the correlation between the sender and its public key. And this is where certificates come is.

Certificate is a standarized way to prove the correlation between sender and its public key.

### Standard X.509
Standard X.509 defines the format of public key certificates. It's the most common certificate format in the world. X.509 certificate binds an identity (organization, domain etc.) to a public key using a digital signature. Certificates are issued by Certification Authority.

Simplified structure of X.509 certificate:

* Issuer Name - who certifies the public key.
* Subject Name - whose public key is certified.
* Validity Period - start and end date of the certificate validity.
* Public Key - subject's public key.
* Signature - the certificate hash + CA's private key

### Certification Authority (CA)
CA is an entity that verifies and issues digitial certificates. CA ensures that the public key has definitely been issued by that organization. The CA is responsible for saying "yes, this person is who they say they are, this is its public key, and we, the CA, certify that". The server sends its certificate (issued by a CA) to the client and the client can be sure that the public key, which is included in the certificate, is not forged.

#### Root CA
Root CA issues a root certificate with its own public key (self-signed certificate). There is no higher authority to certify a Root CA. It's the root of the chain of trust (client cert -> CA -> Root CA). Usually, client software - e.g. browsers or operating systems - include a pre-installed set of trusted Root CA certificates. Root CAs are strictly controlled by different companies to ensure the reliability and security of the certificates they issue. Firefox has around 150 built-in certificates represeting around 50 Root CAs.

#### Chain of Trust

Typical TLS chain of trust contains three certificates. Root CA certificates have usually very long term of validation (usually 20-30 years). Because of that Root CA often creates intermediate CA to improve security and flexibility in their certificate issuance process. Root CA's priv-key singing is very complicated process due to security measures and it's better to issue a shorter-term intermediate CA certificate.

```text
                Root CA <------------ CA <------------ End-user
           
Cert owner :   GlobalSign   |    GlobalSign CA   |   BBC
                            |                    |         
Issuer     :   GlobalSign   |    GlobalSign      |   GlobalSign CA
Subject    :   GlobalSign   |    GlobalSign CA   |   *.bbc.com
Pub-key    :   AAAAAAAAAA   |    BBBBBBBBBB      |   CCCCCCCCCC
                            |                    |
Signed with:   GlobalSign's |    GlobalSign's    |   GlobalSign CA's 
               priv-key     |    priv-key        |   priv-key
```

### File format
X.509 certificates, public keys, private keys and other data are usually stored in a file format called PEM (_Privacy-Enhanced Main_). The [RFC 7468](https://datatracker.ietf.org/doc/html/rfc7468) defines labels and encoding of different cryptographic data stored in a PEM format.

Textual representation of X.509 certificates is base64(DER(ASN.1)) structure. It looks like the following:

```text
-----BEGIN CERTIFICATE-----
MIIF8zCCBNugAwIBAgIQBRN5pMil5XuDXkK78PSX/zANBgkqhkiG9w0BAQsFADA8
<...removed...>
or+08AlE4+46g7ICDbol8LsdsTL9in6R078m4K/h6nuhLjPlstHI
-----END CERTIFICATE-----

-----BEGIN PRIVATE KEY-----
078m4Dbol8LsdswIBAgIQBqhkiG9wugAwIXuDXdsTE4+stHK/lE4+RN5pMil5FAi
<...removed...>
K/h6oBNugAwrsdsN5pMil5FAi46g7ICDzANBgbol8LsdsTLRN5pM
-----END PRIVATE KEY-----
```

Useful commands:

```bash
# Parse PEM-file certificate information
openssl x509 -in <file.pem> -text -noout
```

The actual extension of the file on the disk is not that important. Certificates are usually stored with a `.pem` or `.crt` suffixes and cryptographic keys with a `.key` suffix but it's a matter of convention. More important are `BEGIN` / `END` labels.
