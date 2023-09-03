---
title: Network security notes
---

- [1. IDS vs IPS](#1-ids-vs-ips)
  - [1.1. Evading](#11-evading)
    - [1.1.1. Protocol Manipulation](#111-protocol-manipulation)
    - [1.1.2. Payload Manipulation](#112-payload-manipulation)
    - [Route Manipulation](#route-manipulation)
    - [Tactical Denial of Service](#tactical-denial-of-service)

## 1. IDS vs IPS
**Intrusion Detection System** (IDS) is a system that monitors network activity and detects network or system intrusions. IDS is just a monitoring - it only alerts about suspicious activities but cannot stop them. **Intrusion Prevention System** (IPS) can also actively prevent the malicious actions. These systems can be host-based (monitoring the traffic going in and out of the host) or network-based (monitoring the traffic in the entire network).

### 1.1. Evading
IDS performs signature-based detection using predefined rules. Each IDS/IPS has a certain syntax to define its rules. Example of Snort IDS/IPS rule:

```text
drop icmp any any -> any any (msg: "ICMP Ping Scan"; dsize:0; sid:1000020; rev: 1;)
```

There is couple of techniques how to evade signature-based detection:

- protocol manipulation
- payload manipulation
- route manipulation
- tactical Denial of Service

#### 1.1.1. Protocol Manipulation

**Different protocol**
Most of the rules are defined to monitor specific protocols. You can assume that DNS or HTTPS protocols are not so intrusively controlled because most of the normal traffic uses these protocols. It might take some testing to define which protocols are less restrictive.

**Port manipulation**
Without **Deep Packet Inspection** (DPI), the port numbers are the primary indicator of the service used in the connection. Network traffic involving 22/TCP most propably will be interpreted as SSH traffic.

Nmap has an option to camouflage the scanner's TCP traffic. The `-g` (or `--source-port`) parameter allows to define the source port from which the scanning packets are going outbound. Using `-g 22` we can fake SSH connection.

**Session Splicing**
The idea is that if you break the malicious packet into smaller packets, you will avoid matching the IDS signatures. There's a possibility that IDS is able take a look at the one stream of bytes at once.

**Invalid Packets**
It's possible that invalid TCP packets (e.g. invalid flags, fields values, checksum) would be ignored by IDS.

#### 1.1.2. Payload Manipulation

**Obfuscation, Encoding and Encryption**
IDS rules are pretty specific so using payload obfuscation, encoding or encryption we can avoid detection.

#### Route Manipulation
Source routing and proxy servers can be used to force the packets to use a certain route to the destination. Some routes in the network might be filtered by IDS.

#### Tactical Denial of Service
An IDS requires a high processing power as the number of rules and traffic grows. Moreover, the primary response is most of the time logging traffic information matching the signature. There are two options:

- Generate a huge amount of legit traffic that would overload the processing capacity of the system.
- Generate a huge amount of false-positive traffic. It can exceed logging capacity, disk space etc.
