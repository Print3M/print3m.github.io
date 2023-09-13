---
title: Windows red-team tools
---

- [1. Bloodhound \& Sharphound](#1-bloodhound--sharphound)
- [2. Living of The Land](#2-living-of-the-land)
  - [2.1. LOLBAS](#21-lolbas)
  - [2.2. Sysinternals](#22-sysinternals)
  - [2.3. Bypassing Application Whitelisting (AWL)](#23-bypassing-application-whitelisting-awl)
  - [2.4. Blocked powershell](#24-blocked-powershell)

## 1. Bloodhound & Sharphound
Bloodhound allowed attackers to visualise the AD environment in a graph format with interconnected nodes. It's a tool for visualization of AD organization structure in the form of a graph.

Sharphound is the enumeration tool of Bloodhound. It is used to enumerate the AD information that can then be visually displayed in Bloodhound. Bloodhound is the actual GUI used to display the AD attack graphs. Three Sharphound collectors are available:

- Sharphound.exe
- Sharphound.ps1
- AzureHound.ps1 (for Azure enumeration)
When using these collector scripts, these files most probably would be detected as malware and raise an alert to the blue team.

After uploading the data grabbed with Sharphound to Bloodhound, it shows possible attack vectors exploiting different privileges of AD objects.

## 2. Living of The Land
Living Off the Land_ means to do post-exploitation operations (recon, lateral movement, code execution) using only built-in unsuspicious software which we can find on the victim's machine. The idea is to use Microsoft-signed programs, scripts, and libraries to blend in and evade defensive controls.

### 2.1. LOLBAS
[Living Off The Land Binaries, Scripts and Libraries (LOLBAS)](https://lolbas-project.github.io/#) - binaries that are commonly present on Windows machines and how to use them in some malicious way (privilege escalation, lateral-movement).

### 2.2. Sysinternals
[Windows Sysinternals](https://learn.microsoft.com/en-us/sysinternals/downloads/sysinternals-suite) is a set of advanced tools developed to profesionally manage and diagnose the Windows OS. Sysinternals Suite is divided into categories:

- Disk management
- Process management
- Networking
- System information
- Security

Some of the popular tools from Sysinternals Suite:

- AccessChk - check access for resources.
- PsExec - execute program on a remote system.
- ProcMon - process monitoring.
- TCPView - list all TCP and UDP connections.
- Whois - info for a domain name or IP address.

Some of them are so popular they are even ported to Linux. There is no installation required to use Sysinternalls. The executables are free to [download from the web-server](https://live.sysinternals.com/) or from the network resource (`\\live.sysinternals.com\tools` in Windows Explorer).

### 2.3. Bypassing Application Whitelisting (AWL)
Application whitelisting is rule-based list of executables that are allowed to be executed. For this type of operation there is a special category in LOLBAS project called `AWL bypass`.

### 2.4. Blocked powershell
Sometimes even the execution of `powershell.exe` is blocked. There is a tool to bypass this rule: [PowerLessShell](https://github.com/Mr-Un1k0d3r/PowerLessShell). It is able to run powershell commands without spawning the powershell.exe process.
