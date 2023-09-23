---
title: Windows powerShell CLI
---

- [1. Commands](#1-commands)

## 1. Commands

```powershell
Get-Help <command>                          # Get help about :command
Get-Help <command> -Examples                # Get usage examples with params
Get-Command                                 # Get all commands          
Get-Command <verb>-*                        # Get all commands with :verb
Get-ChildItem                               # List files and folders
Get-Service                                 # List running services
Get-Process                                 # List running processes
Get-ScheduledTask                           # List scheduled tasks
Get-Location                                # Get current working directory
Get-Content <file>                          # Get :file content
Get-FileHash -Algorithm <alg> <file>        # Get :file hash
Test-Path <path>                            # Check if path exists
Invoke-WebRequest                           # Get content from a web resource
Get-LocalUser                               # List all local users
Get-LocalGroup                              # List all local groups
Get-NetIPAddress                            # List all network interfaces
Get-NetTCPConnection                        # List open TCP ports (connections)
Get-HotFix                                  # List Windows patches installed
Select-String                               # Find text in strings and files
Get-Acl                                     # Get ACL of a file/folder
Get-Alias                                   # List all command aliasses

# Find file
Get-Childitem 
    -Path C:\
    -Recurse 
    -ErrorAction SilentlyContinue 
    -File
    -Include *<file-name>*

# CIM interface
Get-CimInstace <class-name>                 # List CIM objects of :class
Get-CimClass *Process | select CimClassName # List all CIM Process classes
Get-CimInstance Win32_Product               # List installed software
Get-CimInstace Win32_Service                # List running services
Get-CimInstace Win32_Process                # List running processes
```
