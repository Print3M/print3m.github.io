---
title: Windows powerShell CLI
---

- [1. Execution Policy](#1-execution-policy)
- [2. Aliases](#2-aliases)
- [3. Special variables](#3-special-variables)
- [4. Calculated properties](#4-calculated-properties)
- [5. Loops](#5-loops)
- [6. String interpolation](#6-string-interpolation)
- [7. Cmdlet parameters](#7-cmdlet-parameters)
- [8. Utils](#8-utils)
- [9. Help](#9-help)
- [10. Active Directory](#10-active-directory)
  - [Built-in cmdlets](#built-in-cmdlets)
  - [10.1. Interesting user properties](#101-interesting-user-properties)
  - [AD module convention](#ad-module-convention)
  - [10.2. AD module](#102-ad-module)
  - [10.3. PowerView module](#103-powerview-module)
- [11. Commands](#11-commands)

## 1. Execution Policy
Execution Policy is not a security measure. It's present to prevent user from accidentally executing scripts. PowerShell Execution Policy is by default set to `Restriced`. It means that user can execute single commands but not to run any PS script (`.ps1` files).

Bypass methods don't require administrator privileges:

```powershell
powershell -ExecutionPolicy bypass
powershell -c <cmd>
powershell -encodedcommand
$env:PSExecutionPolicyPreference="bypass"
```

## 2. Aliases
Most of the filtering cmdlets have useful aliases. All aliases can be listed using `Get-Alias` cmdlet. Most common ones:

```text
select  -> Select-Object
where   -> Where-Object
sls     -> Select-String
measure -> Measure-Object
member  -> Get-Member
```

## 3. Special variables

```powershell
$_                  # Current object
$?                  # Success ($true) or failure ($false) of the last command
$args               # Array of args passed to a function or script
$error              # Array of recent error objects ($Error[0] - most recent)
$false              # False value
$true               # True value
$null               # Null value
```

## 4. Calculated properties
Using `@{}` syntax we can specify calculated properties in one-liners. Inside the `@{}` we can specify [many parameters](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_calculated_properties?view=powershell-7.3#hashtable-key-definitions). The most important ones are:

- `name` (`n`) - name of the created property
- `expression` (`e`) - script used to calculate the new property

```powershell
# Example usage
<command> | select name,@{n="NewProp",e={ $_.Id + 1 }}
```

## 5. Loops

```powershell
# Faster one-liner
$Objects.ForEach({
  # Your code here to be executed on every object
  Do-Something $_.ObjectProperty 
})

# Slower one-liner
$Objects | ForEach-Object -Process { $_.Length * 2 }
# Same as above but `%` is an alias
$Objects | %{ $_.Length * 2} 
```

## 6. String interpolation
TBD

## 7. Cmdlet parameters
Parameters like all names in Powershell are case-insensitive. Powershell allows abbreviated parameter names until the parameter is no longer unambiguous. In shell use it's helpful but it's not recommended practice in scripts since a later version of the cmdlet may no longer have the abbreviation be unambiguous.

```powershell
# Each of them are currently correct and unambigugous
$sth | Select-Object -First 10
$sth | Select-Object -fir 10 
$sth | Select-Object -f 10
```

To see exactly which parameters can be passed by pipeline or positionaly type `Get-Help <command> -Full`. There is a standarized list of all parameters with helpful attributes.

## 8. Utils

```powershell
Get-Command | Out-File <file_path>          # Save output to :file_path
```

## 9. Help

```powershell
Get-Help <command|"About_<topic>">          # Get help about :command or :topic
    -Examples                               # Usage examples 
    -Full                                   # Full help content

Get-Command                                 # Get all commands          
Get-Command <verb>-*                        # Get all commands with :verb
Get-Command -Module <module>                # Get all commands from :module
```

## 10. Active Directory

### Built-in cmdlets
Many built-in PowerShell cmdlets can work on Distiguished Names of objects. To use them in the Active Directory context add `AD:\` before the actual DN string. Example usage:

```powershell
(Get-Acl "AD:\<...DN...>").Access           # Get ACEs of an object
Get-ChildItem "AD:\<...DN...>"              # Get children items
```

### 10.1. Interesting user properties

```powershell
Get-ADUser <user> -Properties *

# Using the following properties you can identify real users
badpwdcount                     # Number of invalid password attempts
logoncount                      # Number of logons
```

### AD module convention
**Server**: AD commands can be executed against different domains or servers - select them using `-server <domain>` parameter:

```powershell
Get-ADUser -Filter * -Server dom1.local
Get-ADComputer -Filter * -Server dom2.local
```

**Filter**: AD objects can be filtered before the response is generated (it's faster than filtering objects after the response is received already). Use `-Filter '<query>'` to filter objects (or `*` to fetch them all). Syntax inside the `'<query>'` is basically the same as for the `Where-Object` command: `PropertyName -operator "value"`.

```powershell
Get-ADComputer -Filter 'OperatingSystem -like "*2016*"'
```

>**IMPORTANT**: A filter query needs to be written as a string! Best option is to use a single quote sign `'`.

**Properties**: AD objects usually have a large amount of properties. By default only small amount of them is actually returned from the DC. Use `-Properties <prop1>,<prop2>` to specify additional properties to fetch or `*` to select all of them.

```powershell
Get-ADUser "user1" -Properties *
```

### 10.2. AD module

```powershell
import-module ActiveDirectory

Get-ADObject <DN> -Properties *             # Get generic AD object

Get-ADDomain                                # Get object of current domain
Get-ADDomain <domain>                       # Get object of another domain

Get-ADDomainController                      # Get current Domain Controller
# Get Domain Controller of :domain
Get-ADDomainController -DomainName <domain> -Discover

Get-ADUser -Filter * -Properties *          # Get all users and properties
Get-ADUser <user> -Properties *             # Get all data of :user
# List built-in (default) users using their description field
Get-ADUser -Filter 'Description -like "*built*"' -Properties Description | select name,Description

Get-ADComputer -Filter *                    # Get all machines
Get-AdComputer <computer> -Properties*      # Get all data of :computer 

Get-ADGroup -Filter *                       # Get all groups
Get-ADGroup <group> -Properties *           # Get all data of :group
Get-ADGroup -Filter 'Name -like "*admin*"'  # Get all admin groups

Get-ADGroupMember <group> -Recursive        # Get members of :group
Get-ADPrincipalGroupMembership <user>       # Get group membership of :user

# GroupPolicy module required!
Get-GPO -All                                # Get all group policies
# Built-in tool
gpresult /R /V                              # Get policies TBD

Get-ADOrganizationalUnit -Filter *          # Get all OUs of current domain

Get-ADTrust -Filter *                       # Get current domain trust objects
Get-ADTrust -Filter * -Server <domain>      # Get :domain trust objects

Get-ADForest                                # Get current forest
Get-ADForest <forest>                       # Get current forest
(Get-ADForest).Domains                      # Get all domains of the forest
```

### 10.3. PowerView module
[PowerView](https://github.com/PowerShellMafia/PowerSploit/blob/master/Recon/PowerView.ps1) script propably will be detected by AMSI. An AMSI bypass method needs to be applied.

```powershell
. .\PowerView.ps1                           # Load PowerView module

Get-DomainPolicy                            # Get domain policies
(Get-DomainPolicy).SystemAccess             # System access policy
(Get-DomainPolicy).KerberosPolicy           # Kerberos policy

# List all the local groups on a machine (admin privs required)
Get-NetLocalGroup -ComputerName <computer> -ListGroups
# List members of all the local groups on a machine (admin privs requored)
Get-NetLocalGroup -ComputerName <computer> -Recursive

# Get logged users on a computer (local admin privs on the target required)
Get-NetLoggedOn -ComputerName <computer>
# Get the last logged user on a computer (admin privs and remote registry on the target required) 
Get-LastLoggedOn -ComputerName <computer>

Invoke-ShareFinder -Verbose                 # Get shares in current domain
Invoke-FileFinder -Verbose                  # Get sensitive files in the domain
Get-NetFileServer                           # Get all file-servers in the domain

Get-NetGPO                                  # Get all group policies
Get-NetGPO -ComputerName <computer>         # Get GPOs for :computer
Get-NetGPO "{guid}"                         # Get GPO using :guid

# Get interesting ACEs associated with a :user
Get-ObjectAcl -SamAccountName <user> -ResolveGUIDs
Get-ObjectAcl -ADSprefix "<CN=...>"

Invoke-ACLScanner -ResolveGUIDs             # List interesting ACEs

# Find all machines in the current domain where the current user is local admin (very noisy!)
Find-LocalAdminAccess -Verbose
# Check if we have admin access to any machine
Invoke-UserHunter -CheckAccess
```

## 11. Commands

```powershell
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
Get-Alias                                   # List all command aliases
Test-Connection                             # Ping

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
