---
title: Windows environment notes
---
## Scheduled tasks
_Scheduled tasks_ are _cron jobs_ in the Linux world.  

## Accounts
To show GUI with all users and groups run: `lusrmgr.msc`

### SYSTEM
SYSTEM is internal account which doesn't show up in User Manager.
- the highest privilege level in the Windows user model.
- used by the OS and by services running under Windows.
- can't be added to any groups and cannot have user rights assigned to it.
    
If the computer is joined to a domain, processes running as SYSTEM can access domain servers in the context of the computer's domain account without credentials.

### Administrator
Every computer has Administrator account. It's the first account that is created during the Windows installation. Processes running as Administrator have no access to domain computers unless the credentials are explicitly provided.

Administrator has following privileges:
- full control of the files, directories, services, and other resources on the local computer.
- creation of other local users, assign user rights, and assign permissions.
- can't be deleted or locked out, but it can be renamed or disabled.
- it's member of the Adminitrators group and it can't be removed from the Administrators group but it can be renamed.

### Guest
TBD

## Files and folders
On Windows file extensions are meaningful.
- .bat - Batch script. Equivalent of bash scripts for Linux.
- .dll - Dynamic Link Library. It's linked during run-time.
- .lib - Library. It's linked during compilation.

[Permission tables (special and basic) for files and folders](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-2000-server/bb727008(v=technet.10)?redirectedfrom=MSDN)

## System environmental variables
Environment variables store information about the operating system environment. This information includes details such as the operating system path, the number of processors used by the operating system, and the location of temporary folders.

#### Standard
- %TEMP% / %TMP%    -> C:\Windows\TEMP
- %windir%          -> C:\Windows
- %USERNAME%        -> Current username

## LSASS
TBD

## SAM file
TBD
