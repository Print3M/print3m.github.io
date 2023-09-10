---
title: Windows resource sharing services
---

- [1. SMB - Server Message Block (139, 445)](#1-smb---server-message-block-139-445)
  - [1.1. Security](#11-security)
  - [1.2. DNS poisoning attack](#12-dns-poisoning-attack)
  - [1.3. NTLM relay attack](#13-ntlm-relay-attack)
- [2. NFS - Network File System](#2-nfs---network-file-system)
- [3. FTP - File Transfer Protocol](#3-ftp---file-transfer-protocol)

## 1. SMB - Server Message Block (139, 445)
SMB is a client-server protocol that regulates access to files and entire directories and other network resources. An SMB server can provide arbitrary parts of its local file system as shares. Access rights are defined by ACL. SMB can be used only within LOCAL networks, it's not routable.

### 1.1. Security
SMB most often uses NTLM to authentication. NTLM challenge might be sniffed and cracked offline. Cracking NTLM challenge is slower than cracking the hash directly, but it's still possible. SMB is very widely used by services in LAN, so there are usually a lot of these challanges flying on the network.

### 1.2. DNS poisoning attack
`Responder` is used to poison the responses during NTLM authentication, tricking the victim into talking to the attacker instead of legit servers. Responder will attempt to poison any of the following requests:

- Link-Local Multicast Name Resolution (LLMNR)
- NetBIOS Name Server (NBT-NS)
- Web Proxy Auto-Discovery (WPAD) These protocols are used to perform local DNS resolution for all hosts in the LAN. They relay on requests broadcasted on the LAN, so the attacker can receive these requests. Responder actively listens to the requests and sends poisoned responses lying that attacker is a searched hostname. Responder basically attempts to win the race for hostname resolution. Tricked server attempts to perform NTLM auth with the attacker.

### 1.3. NTLM relay attack
In some cases attacker can try to relay the challenge intead of capturing it directly. It's harder and not usually popular for initial foothold.

- SMB singing should be disabled or enabled but not enforced - attacker is going to make some changes in the request passed along.
- Associated account needs the permissions to access these resources - ideally attacker hopes for an admin account.
- A little bit of guessing which account has which permissions etc. It's more useful for lateral movement and privilege escalation.

## 2. NFS - Network File System
By NFS protocol, you can transfer files between computers running Windows and other non-Windows OS. NFS in Windows Server includes Server for NFS and Client for NFS.

NFS is automatic protocol (FTP is manual). Once mounted, files appear as if they are local files. Blocks of the files are transferred in the background; no need to copy the entire files to read them. NFS works best in fast, stable, low loss LOCAL networks.

## 3. FTP - File Transfer Protocol
FTP is good for far-away connections, when you transfer between two different OSes. It sends only entire files.
