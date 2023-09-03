---
title: Host security measures and evasion
---

- [1. Antivirus (AV)](#1-antivirus-av)
  - [1.1. Features](#11-features)
  - [1.2. Windows Defender](#12-windows-defender)
- [2. Endpoint Detection and Response (EDR)](#2-endpoint-detection-and-response-edr)
- [3. Firewall](#3-firewall)
  - [3.1. Evasion during network scan](#31-evasion-during-network-scan)
    - [3.1.1. Controlling the Source MAC/IP/Port](#311-controlling-the-source-macipport)
- [4. System Monitor (Sysmon)](#4-system-monitor-sysmon)
- [5. User Account Control (UAC)](#5-user-account-control-uac)

## 1. Antivirus (AV)
Antivirus software works in real-time scanning all open and used files in the background. Full system scan is usually performed during the installation of the antivirus. AV software performs scanning, detecting and removing malicious files. Traditionally, it works only with files.

Common malware detection techniques:

- Signature-based detection - AV compares the scanned file with a database of known malicious signatures and patterns. The database must be up to date. It tries to find unique strings, checksums and sequence of bytes of known malicious code.
- Heuristic-based detection - most often engages machine learning to decide whether a file is malicious. It scans and statically analyses binary and behavior in real-time.
- Behavior-based detection - AV monitors and examines the execution of binary to find suspicious activities and API calls (e.g. register editing, process spawning, filesystem modifications, log events, web requests).

> **NOTE**: _EICAR_ file is a special standarized file to test AV abilities (fake malware).
> **NOTE**: Nowadays, many antivirus softwares integrate traditional AV functionalities with some of the EDR features.

### 1.1. Features

- Compressors and Archives - AVs usually support various file formats, including compressed and archived files, where it can self-extract and inspect all compressed files. Malicious code often tries to hide itself in compressed files.
- PE Parsing and Unpackers - malware hides and packs its code by compressing and encrypting it within a executable (PE). It decompresses and decrypts itself only during runtime. It makes it hard to perform static analysis. AVs should support unpacking most of the known PE packers (UPX, Armidillo, ASPack) for static analysis. AV also parses PE headers and looks for suspicious fields.
- Emulators - emulator can run suspicious files (PE, DLL, etc.) in a virtualized environment, performing the behavior-based detection. Malware developers implement checks to not work within the virtual or simulated environment.

### 1.2. Windows Defender
It is a pre-installed antivirus that runs on users' machine. MS defender runs in:

- Active mode - when is used as primary AV software
- Passive mode - when there is another 3rd party AV software installed

## 2. Endpoint Detection and Response (EDR)
EDR software provides real-time protection based on behavioral analytics. EDR monitors various security aspects in the target machine, including memory, network connections, executed commands, processes and Windows registry.

## 3. Firewall
It's main purpose is to control the inbound and outbound traffic that goes through the device's interface. A firewall acts as control access at the network layer. It is capable of allowing and denying network packets. It can be a seperate physical device (usually very expensive) or a software. `Windows Defender Firewall` and `Linux Iptables` are examples of software firewalls. A firewall compares the packets against a set of rules before passing or blocking it. It might block TCP packets sent to a certain port or packets from a certain host.

Most often firewalls focus on layer 3 (IPv4, IPv6) and 4 (TCP, UDP). Advanced firewalls also can inspect other ISO/OSI layers, such as application layers (HTTP, FTP, SMTP, etc.) - e.g. they can detect and block SQL injection or reflected XSS payloads.

### 3.1. Evasion during network scan

#### 3.1.1. Controlling the Source MAC/IP/Port

**Decoy**
`Nmap` has an option to hide IP of the attacker's host using decoys - sending many packets with spoofed IPs. Because of the flood of different IPs, it's difficult for the firewall to find out where the scan is coming from. Also it can exhaust the blue team resources to investigate all IPs.

```bash
# Specified IPs
nmap <IP> -D <decoy-IPs-comma-seperated>

# Random IPs + one specific
nmap <IP> -D RND,RND,RND,192.168.1.25
```

**MAC Spoofing**
Spofing the MAC address (`--spoof-mac <MAC>`) works only if your system is on the same network sagment. The target system is going to reply to a spoofed MAC address. If you are not on the same network segment, sharing the same Ethernet, you won’t be able to capture and read the responses.

**IP Spoofing**
Spoofing the IP address (`-S <IP>`) works only if your system is on the subnetwork. This technique can be used to exploit trust relationships on the network based on IP addresses.

**IP Packet fragmentation**
`-f` (8 bytes) and `-ff` (16 bytes) options in Nmap allow to split IP packet into smaller packets. Using `--mtu <number>` parameter you can specify the maximum packet size (IP data). One IP packet can be divided into multiple smaller packets carring legit TCP connection but evading the firewall.


## 4. System Monitor (Sysmon)
Sysmon is a service and device driver - one of the MS Sysinternals suites. It's not installed by default. This logging system helps system administrators and blue teamers to detect and investigate malicious activity.

Sysmon can log many default and custom events, e.g.:

- Process creation and termination
- Network connections
- File manipulation
- Memory access

[More info about Sysmon.](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon)

> **NOTE**: For a red-teamer it is essential to know whether the Sysmon logging software is installed or not. It is important to avoid causing generating and alerting events.

## 5. User Account Control (UAC)
UAC is mechanism introduced in Windows Vista. When a user with the **local** account, which is member of the local _Administrators_ group, logs into a system (majority of users), the current session doesn't run with full administrator permissions. When an operation requires higher-level privileges, the user will be prompted to confirm if they permit the operation to run (in the GUI - yellow popup with 'yes' or 'no' question). Same situation occurs when local account is connected via RPC, SMB or WinRM, etc. The only local account that will get full privileges by default is the default local **Administrator** account itself.

AD account (AD), which is a member of the AD _Administrators_ group, will run with a full administrator acces and UAC won't be in effect.

> **NOTE**: This security feature might be disabled. Sometimes there is no difference between local and domain account in the administrator's group.
