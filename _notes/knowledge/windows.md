---
title: Windows environment notes
---

## Active Directory environment
### Domain Controller
**AD Domain** - part of the network that groups users, hosts, resources. It's used to perform privileges, security policies and access management. At least one Domain Controller must be present to create Domain. The main idea behing a domain is to centralise the administration of Windows components in a single repository called Active Directory.

Each AD domain is also a DNS domain, and each AD domain controller is also a DNS nameserver – but not the other way around.

**AD Forest** - collection of domains that trust each other.

**Domain Controller** - administrator of the Domain. The server that runs AD services. Every user in the network must authenticate via Kerberos or LDAP protocol sent to DC. DC is responsible for security policies and account management. If you have DC, you are god in the network. DC holds AD database file.

### Active Directory
AD is service used by Domain Controller to perform authentication, groups, users and security policies management. AD is not cross platform. AD supports both Kerberos and LDAP authentication. AD database file is called NTDS.dit and it's stored on Domain Controller server.

**Security**:
- even with low-privileged user an attacker can make useful enumeration and lateral movement.

### AD Domain Service (AD DS)
It's catalogue that holds the information of all "objects" that exist on the network. An object might be: user, group, machine, printer, share, etc.

**Users**:
- most common object type in AD.
- people - represents persons in the organisation
- services - every service (IIS or MSSQL) requires a user to run. They only have privileges needed to run their specific service (ideally).
    
**Machines**:
- represents every computer that joins the AD domain
- every machine have Machine Account - local administrator on the computer, is not supposed to be accessed by anyone except the computer itself but it uses normal password (120 random chars). MA name is the computer's name + dollar sign: PC-1 (computer name) -> PC-1$ (MA name).

**Security groups**:
- group includes AD machines and AD users as members
- group can include other groups
- several groups are created by default in a domain, e.g. Domain Admins, Domain Users, Domain Computers, Domain Controllers.

### Users / accounts
AD users are different than built-in local users (these are are used to manage the system locally, which is not part of the AD environment). Domain/AD accounts can use the AD services.

Types of AD Administrator accounts:
* BUILTIN\Administrator - local admin on a domain controller.
* Domain Admin - admin to all resources in the domain.
* Enterprise Admin - forest root only.
* Schema Admin - capable of modifying domain/forest.

### Group Policy Objects (GPO)
Collection of settings (rules) that can be applied to Organizational Unit (organized objects: users, hosts, etc.). GPOs are distributed to the network via a network share SYSVOL (stored in the DC) which points to path `C:\Windows\SYSVOL\sysvol\` on each of the DCs.

**Security**: 
Any AD account, no matter how low-privileged, can read the contents of the SYSVOL directory. It's nice way to check if provided domain credentials are correct.

### Distinguished Name (DN)
Collection of comma-separated key and value pairs used to identify unique AD record (object). The DN consists of:
* Domain Component (DC)
* Organizational Unit Name (OU)
* Common Name (CN)
* others

> **Example** of DN: "CN=Administrator,OU=Users,DC=amazon,DC=com" 

### Local workgroup
TBD

## Services
_Services_ are _daemons_ in the Linux world. 

### SNMP (Simple Network Management Protocol)
SNMP is widely used in network management for network monitoring. It exposes management data in the form of variables on the managed systems organized in a management information base (MIB). These data can then be remotely queried and, in some circumstances, manipulated.

### LDAP - Lightweight Directory Access Protocol
What LDAP is:
- LDAP is TCP/IP open and cross platform protocol.
- LDAP is one way of speaking to Active Directory.
- LDAP is protocol that many different directory services and access management solutions can understand.
- Relation between LDAP and AD is like HTTP and Apache. AD is directory server that uses the LDAP protocol.

**LDAP Query**:
- It's a command that asks a directory service (e.g. AD) for some information.

### IIS - Windows web server
IIS stands for Internet Information Services. It's just web server for Windows.It's included in most Windows versions, except home editions. Usually there is a new IIS version for every new OS.
    
### MSRPC - Microsoft Remote Procedure Call (135, 593)
MSRPC is protocol that uses the client-server model in order to allow one program to request service from a program on another host.
    
The RPC endpoint can be accessed through TCP and UDP port 135, via SMB with a null or authenticated session (TCP 139 and 445), and as a web service listening on TCP port 593.

### NetBIOS Name Service (139)
It's name service for name registration and resolution. Every machine has a name inside the NetBios network.

**Security**:
- Enumerating a NetBIOS service you can obtain the names the server is using and the its MAC address.

### NetBIOS name vs domain Name vs DNS name vs host name
Every computer on the internet has DNS name (network host name). Every computer on the internet running Windows OS has NetBIOS name as well. It's the same as local computer name.
    
Computer running Windows in an Active Directory domain has both:
- DNS domain name - classic `sub.example.com`
- NetBIOS domain name - typically that name is subdomain of DNS domain name. For example, DNS name = "corp.com", NetBIOS name = "corp"

### File transfer protocols
#### SMB - Server Message Block (139, 445)
SMB is a client-server protocol that regulates access to files and entire directories and other network resources. An SMB server can provide arbitrary parts of its local file system as shares. Access rights are defined by Access Control Lists (ACL). SMB can be used only within LOCAL networks, it's not routable.

**Security**: 
SMB most often uses NTLM to authentication. NTLM challenge might be sniffed and cracked offline. Cracking NTLM challenge is slower than cracking the hash directly, but it's still possible. SMB is very widely used by services in LAN, so there are usually a lot of these challanges flying on the network.

**DNS poisoning attack**:
Responder is used to poison the responses during NTLM authentication, tricking the victim into talking to the attacker instead of legit servers. Responder will attempt to poison any of the following requests:
- Link-Local Multicast Name Resolution (LLMNR)
- NetBIOS Name Server (NBT-NS)
- Web Proxy Auto-Discovery (WPAD) These protocols are used to perform local DNS resolution for all hosts in the LAN. They relay on requests broadcasted on the LAN, so the attacker can receive these requests. Responder actively listens to the requests and sends poisoned responses lying that attacker is a searched hostname. Responder basically attempts to win the race for hostname resolution. Tricked server attempts to perform NTLM auth with the attacker.

**NTLM relay attack**: 
In some cases attacker can try to relay the challenge intead of capturing it directly. It's harder and not usually popular for initial foothold.
- SMB singing should be disabled or enabled but not enforced - attacker is going to make some changes in the request passed along.
- Associated account needs the permissions to access these resources - ideally attacker hopes for an admin account.
- A little bit of guessing which account has which permissions etc. It's more useful for lateral movement and privilege escalation.

#### NFS - Network File System
By NFS protocol, you can transfer files between computers running Windows and other non-Windows OS. NFS in Windows Server includes Server for NFS and Client for NFS.
    
NFS is automatic protocol (FTP is manual). Once mounted, files appear as if they are local files. Blocks of the files are transferred in the background; no need to copy the entire files to read them. NFS works best in fast, stable, low loss LOCAL networks.

#### FTP - File Transfer Protocol
FTP is good for far-away connections, when you transfer between two different OSes. It sends only entire files.

### Network authentication protocols
Using Windows domains, all credentials are stored in the DC. Every authentication is performed via DC, using one of two protocols:
- Kerberos
- NTLM 
There is also internal (third-party to DC) method: LDAP auth

#### NTLM (aka Net-NTML)
NTLM was the default authentication protocol used in old Windows versions. If for any reason Kerberos fails, NTLM will be used instead.

**Security**:
- NTLM uses a challenge/response mechanism, which exposes its password to offline cracking when responding to the challenge.
- NTLMv1 hashes could be cracked in seconds with today’s computing since they are always the same length and are not salted.
- NTLMv2 is a little better, since it variables length and salted hash, but not that much better. Even though hash it's salted before it's sent, it's saved unsalted in a machine’s memory. 

#### Kerberos
Kerberos is the authentication protocol. It’s the default authentication protocol on Windows versions above Windows 2000, replacing the NTLM.

Security advantages over NTLM:
- More secure: No password stored locally or sent over the net.
- Supports MFA (Multi Factor Authentication)

#### LDAP
LDAP is another method of AD authentication. It is similar to NTLM auth but the application directly verifies the user's credentials (don't neeed to pass them to AD for verification). Popular mechanism with third-party applications which integrate with AD. E.g. Gitlab, Jenkins, printers, etc. It's more like auth mechanism between third-party service and DC.

**Security**: 
LDAP application which is exposed on the internet might be password-sprayed good as standard NTLM auth. But that app has its own credentials for LDAP quering DC. They are used to check if our credentials are correct. Now we don't have to hack users AD credentials. We might just hack the app AD credentials - one more vector to attack. App's credentials are most often stored in the plain text on the app's server (config files).

**LDAP Pass-back attack**: 
If we can alter the LDAP configuration in the application (e.g. printer config), we can force device to try to authenticate with the attacker IP, instead of DC LDAP server. We can intercept this auth attempt and recover the LDAP credentials.

### Microsoft Deployment Toolkit (MDT)
This service automates the deployment of new images of Windows across the organisation. The base image can be maintained in a central location. It allows the IT team to preconfigure and manage boot images. If they need to configure a new machine, they just plug in a network cable and everyting happens automatically. They can pre-install default corpo-software like Office or anti-virus.

**Preboot Execution Environment (PXE)**: 
It allows new devices which are connected to the network to install the OS image directly over a network. MDT is used to create, manage and host PXE boot images. PXE image might be nice target for:
- Injecting a privilege escalation vector (e.g. local admin account) or any other back-door things
- Password scraping to recover AD credentials used during the installation from PXE boot file - Windows image extracton -> data extraction.

### System Center Configuration Manager (SCCM)
This service can be seen as the big brother to MDT. It manages the software after installation. It allows the IT team to remotely install updates to all software across the organization.

### Windows Imaging Format (WMI)
Bootable images of Windows OS.

## Info
### Accounts
To show GUI with all users and groups run: `lusrmgr.msc`

### User Account Control (UAC)
Mechanism introduced in Windows Vista. When a user with the administrator type account logs into a system (majority of users), the current session doesn't run with admininstrator permissions. When an operation requires higher-level privileges, the user will be prompted to confirm if they permit the operation to run (yellow popup with 'yes' or 'no' question).

#### SYSTEM
SYSTEM is internal account which doesn't show up in User Manager.
- the highest privilege level in the Windows user model.
- used by the OS and by services running under Windows.
- can't be added to any groups and cannot have user rights assigned to it.
    
If the computer is joined to a domain, processes running as SYSTEM can access domain servers in the context of the computer's domain account without credentials.

#### Administrator
Every computer has Administrator account. It's the first account that is created during the Windows installation. Processes running as Administrator have no access to domain computers unless the credentials are explicitly provided.

**Privileges**:
- full control of the files, directories, services, and other resources on the local computer.
- creation of other local users, assign user rights, and assign permissions.
- can't be deleted or locked out, but it can be renamed or disabled.
- it's member of the Adminitrators group and it can't be removed from the Administrators group but it can be renamed.

#### Guest
TBD

### Files and folders
On Windows file extensions are meaningful.
- .bat - Batch script. Equivalent of bash scripts for Linux.
- .dll - Dynamic Link Library. It's linked during run-time.
- .lib - Library. It's linked during compilation.

Permission tables (special and basic) for files and folders: https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-2000-server/bb727008(v=technet.10)?redirectedfrom=MSDN

### PowerShell
Windows new shell (from Windows 7).

### System environmental variables
Environment variables store information about the operating system environment. This information includes details such as the operating system path, the number of processors used by the operating system, and the location of temporary folders.

**Standard**:
- %TEMP% / %TMP%    -> C:\Windows\TEMP
- %windir%          -> C:\Windows
- %USERNAME%        -> Current username

### LSASS
TBD

### SAM file
TBD

### Bloodhound && Sharphound
Bloodhound allowed attackers to visualise the AD environment in a graph format with interconnected nodes. It's a tool for visualization of AD organization structure in the form of a graph.
    
Sharphound is the enumeration tool of Bloodhound. It is used to enumerate the AD information that can then be visually displayed in Bloodhound. Bloodhound is the actual GUI used to display the AD attack graphs. Three Sharphound collectors are available:
- Sharphound.exe
- Sharphound.ps1
- AzureHound.ps1 (for Azure enumeration)
When using these collector scripts, these files propably will be detected as malware and raise an alert to the blue team.

After uploading the data grabbed with Sharphound to Bloodhound, it shows possible attack vectors exploiting different privileges of AD objects.

### Antivirus Software (AV)
In the background scanning, the antivirus software works in real-time and scans all open and used files in the background. Full system scan is usually performed during the installation of the antivirus.

Common malware detection techniques:
* **Signature-based detection** - AV compares the scanned file with a database of known signatures for possible attacks and malware.
* **Heuristic-based detection** - most often engages machine learning to decide whether a file is malicious. It scans and statically analyses binary and behavior in real-time.
* **Behavior-based detection** - AV monitors and examines the execution of binary to find suspicious and uncommon activities (e.g. register editing, process spawning).

##### Windows Defender
It is a pre-installed antivirus that runs on users' machine. MS defender runs in:
* Active mode - when is used as primary AV software
* Passive mode - when there is another 3rd party AV software installed

### Host-based Firewall
It's main purpose is to control the inbound and outbound traffic that goes through the device's interface. A firewall acts as control access at the network layer. It is capable of allowing and denying network packets. Advanced firewalls also can inspect other ISO/OSI layers, such as application layers (HTTP, etc.) - e.g. they can detect and block SQL injection or reflected XSS payloads.

### Logging
#### System Monitor (Sysmon)
Sysmon is a service and device driver - one of the MS Sysinternals suites. It's not installed by default. This logging system helps system administrators and blue teamers to detect and investigate malicious activity.

Sysmon can log many default and custom events, e.g.:
* Process creation and termination
* Network connections
* File manipulation
* Memory access

More info: https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon

##### Security
For red-teamer it is essential to know whether the Sysmon logging software is installed or not. It is important to avoid causing generating and alerting events.

### Windows Management Instrumentation (WMI)
System administrators can use WMI in all Windows-based applications. It's most useful in enterprise applications and administrative scripts. 
TBD

### Common Information Model (CMI)
**CIM** provides a common definition of management information for systems, networks, applications, and services, and it allows for vendor extensions. CMI is an extensible, object-oriented data model that contains information about different parts of an enterprise. The CIM is a language-independent programming model. The CIM is a cross-platform standard maintained by the Distributed Management Task Force.

CIM defines 3 levels of classes:
* Core - classes that applay to all management areas.
* Common - classes that applay to specific management areas.
* Extended - classes that applay to technology-specific additions to the common classes.

##### CIM vs WMI
The best Powershell interface to get CMI objects is the `Get-CimInstace` cmdlet. The `Get-WmiObject` cmdlet (**WMI** is the Microsoft implementation of CIM for the Windows platform) works almost the same but the first one should be used (Microsoft said). The latter might be deprecated someday, it is slower and it has less capabilities. The big drawback to the WMI cmdlets is that they use DCOM to access remote machines. DCOM isn’t firewall friendly, can be blocked by networking equipment, and gives some arcane errors when things go wrong.