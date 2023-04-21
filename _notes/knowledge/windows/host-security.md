---
title: Host security measures
---

## Antivirus Software (AV)
In the background scanning, the antivirus software works in real-time and scans all open and used files in the background. Full system scan is usually performed during the installation of the antivirus.

Common malware detection techniques:

* **Signature-based detection** - AV compares the scanned file with a database of known signatures for possible attacks and malware.
* **Heuristic-based detection** - most often engages machine learning to decide whether a file is malicious. It scans and statically analyses binary and behavior in real-time.
* **Behavior-based detection** - AV monitors and examines the execution of binary to find suspicious and uncommon activities (e.g. register editing, process spawning).

### Windows Defender
It is a pre-installed antivirus that runs on users' machine. MS defender runs in:

* Active mode - when is used as primary AV software
* Passive mode - when there is another 3rd party AV software installed

## Host-based Firewall
It's main purpose is to control the inbound and outbound traffic that goes through the device's interface. A firewall acts as control access at the network layer. It is capable of allowing and denying network packets. Advanced firewalls also can inspect other ISO/OSI layers, such as application layers (HTTP, etc.) - e.g. they can detect and block SQL injection or reflected XSS payloads.

## System Monitor (Sysmon)
Sysmon is a service and device driver - one of the MS Sysinternals suites. It's not installed by default. This logging system helps system administrators and blue teamers to detect and investigate malicious activity.

Sysmon can log many default and custom events, e.g.:

* Process creation and termination
* Network connections
* File manipulation
* Memory access

[More info about Sysmon.](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon)

### Security

For red-teamer it is essential to know whether the Sysmon logging software is installed or not. It is important to avoid causing generating and alerting events.

## User Account Control (UAC)
Mechanism introduced in Windows Vista. When a user with the **local** account, which is member of the local _Administrators_ group, logs into a system (majority of users), the current session doesn't run with full administrator permissions. When an operation requires higher-level privileges, the user will be prompted to confirm if they permit the operation to run (in the GUI - yellow popup with 'yes' or 'no' question). Same situation occurs when local account is connected via RPC, SMB or WinRM, etc. The only local account that will get full privileges by default is the default local **Administrator** account itself.

AD account (AD) that is a member of the AD _Administrators_ group will run with a full administrator acces and UAC won't be in effect.

> **NOTE**: This security feature might be disabled. Sometimes there is no difference between local and domain account in the administrator's group.
