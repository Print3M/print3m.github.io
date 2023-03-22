---
title: Powershell notes
---

## What is Powershell & cmdlets?
Powershell (PS) is the Windows Scripting Language built using the **.NET** framework. PS is able to execute .NET functions directly from its shell. PS commands are called **_cmdlets_** - most of them is written in .NET. The output of _cmdlets_ are **objects**. This approach makes PS shell modular - it's easy to apply some actions on the output objects or pass them to another _cmdlet_.

Format of _cmdlet_ command: **Verb**-**Noun**. Common verbs:
* Get
* Start
* Stop
* Read
* Write
* New
* Out
* Invoke

[All _cmdlet_ verbs.](https://docs.microsoft.com/en-us/powershell/scripting/developer/cmdlet/approved-verbs-for-windows-powershell-commands?view=powershell-7)

##### PowerShell scripts
*Powershell ISE* is the Powershell Text Editor most often used to write longer PowerShell scripts. Most common extension of PowerShell files is `.ps1`.

##### What is a cmdlet?
Cmdlets (pronounced: command-lets) are native PS commands, not stand-alone executables. Cmdlets are collected into **PowerShell modules** that can be loaded on demand. They can be written in any compiled .NET language or in the PS scripting language itself.  

## Pipeline
To pass output from one cmdlet to another the pipline is used. Instead of passing text, PowerShell passes an object to next cmdlet. Object contains methods and properties. Objects returned by the last command in a chain are printed out on the screen.

```powershell
# Get members of command's output object
<command> | Get-Member -MemberType <Method | Property>

# Get only specific properties (show only selected fields)
<command> | Select-Object -Property <prop1>,<prop2> <modifier>
Modifiers:
    -first <x>                              # Get first :x objects
    -last <x>                               # Get last :x objects
    -unique                                 # Show unique objects
<command> | select <prop1>,<prop2>          # Alias

# Filter objects (get only these which match a specific value)
<command> | Where-Object <property-name> -<operator> <value>
Operators:
    -like                                   # String wildcard matching (*abc*)
    -contains                               # Property value contains
    -eq                                     # Property value equals
    -gt                                     # Property value is greater

# Sort objects
<command> | Sort-Object

# Measure object (get number of objects, etc.)
<command> | Measure-Object
```

## Commands / cmdlets
> **NOTE**: Cmdlets and their parameters are case-insensitive. However, Microsoft generally recommends entering a PowerShell cmdlet (or a parameter with the first letter of each word capitalized.
 
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

## Scripting
### Variables
```powershell
$var = Get-NetTCPConnection                 # Save returned object into var
```
### If statement
```powershell
if ($obj1 -<operator> $obj2) {
    # Do something
}
```

###### Operators
[Full list of operators](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_comparison_operators?view=powershell-7.3&viewFallbackFrom=powershell-6)

> NOTE: String comparisions are case-insensitive unless you use the explicit case-sensitive operator. To make a comparison operator case-sensitive, add a `c` after the `-` (`-ceq` is the case-sensitive version of `-eq`).

Most common:
```powershell
-eq, -ne                                  # Equal / not equal
-gt, -ge                                  # Greater than / greater or equal
-lt, -le                                  # Less than / less or equal
-is, -isnot                               # Type comparision
-in, -notin                               # Value A in in a collection B
-like, -notlike                           # String wildcard matching
-match, -notmatch                         # String regex matching     
```

### Loops   
```powershell
# Iterate over set of objects
foreach ($item in $items) {
    echo $item
}
```