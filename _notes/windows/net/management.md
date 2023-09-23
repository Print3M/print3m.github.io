---
title: Windows management services
---

- [1. Windows Remote Management (WinRM)](#1-windows-remote-management-winrm)
- [2. Windows Management Instrumentation (WMI)](#2-windows-management-instrumentation-wmi)
- [3. Common Information Model (CMI)](#3-common-information-model-cmi)
  - [3.1. CIM vs WMI](#31-cim-vs-wmi)
  - [3.2. Microsoft Deployment Toolkit (MDT)](#32-microsoft-deployment-toolkit-mdt)
  - [3.3. Preboot Execution Environment (PXE)](#33-preboot-execution-environment-pxe)
  - [3.4. System Center Configuration Manager (SCCM)](#34-system-center-configuration-manager-sccm)
  - [3.5. Windows Imaging Format (WIM)](#35-windows-imaging-format-wim)

## 1. Windows Remote Management (WinRM)
WinRM is a web-based protocol used to send Powershell commands to Windows hosts remotely. Ports: 5985/TCP (HTTP) and 5986/TCP (HTTPS). Most Windows Server machines have WinRM enabled by default.

## 2. Windows Management Instrumentation (WMI)
WMI is Windows implementation of _Web-Based Enterprise Management_ (WBEM) standard for accessing management information across devices. WMI allows administrators to perform standard management tasks. System administrators can use WMI in all Windows-based applications. WMI allows you to query and manipulate system settings, receive notifications about system events, and perform various management tasks programmatically. It offers a set of APIs containing information about various aspects of the system, such as hardware, software, network configuration, and more. Built-in `wmic` (WMI Command-line) tool is a command-line interface to access the WMI functionalities.

WMI session might be established using one of the following protocols:

1. **DCOM**  - RPC over IP.
2. **Wsman** - Over WinRM.  

## 3. Common Information Model (CMI)
**CIM** provides a common definition of management information for systems, networks, applications, and services, and it allows for vendor extensions. CMI is an extensible, object-oriented data model that contains information about different parts of an enterprise. The CIM is a language-independent programming model. The CIM is a cross-platform standard maintained by the Distributed Management Task Force.

CIM defines 3 levels of classes:

- Core - classes that apply to all management areas.
- Common - classes that apply to specific management areas.
- Extended - classes that apply to technology-specific additions to the common classes.

### 3.1. CIM vs WMI
The best Powershell interface to get CMI objects is the `Get-CimInstace` cmdlet. The `Get-WmiObject` cmdlet (**WMI** is the Microsoft implementation of CIM for the Windows platform) works almost the same but the first one should be used (Microsoft said). The latter might be deprecated someday, it is slower and it has less capabilities. The big drawback to the WMI cmdlets is that they use DCOM to access remote machines. DCOM isn’t firewall friendly, can be blocked by networking equipment, and gives some arcane errors when things go wrong.

### 3.2. Microsoft Deployment Toolkit (MDT)
This service automates the deployment of new images of Windows across the organisation. The base image can be maintained in a central location. It allows the IT team to preconfigure and manage boot images. If they need to configure a new machine, they just plug in a network cable and everyting happens automatically. They can pre-install default corpo-software like Office or anti-virus.

### 3.3. Preboot Execution Environment (PXE)
It allows new devices which are connected to the network to install the OS image directly over a network. MDT is used to create, manage and host PXE boot images. PXE image might be nice target for:

- Injecting a privilege escalation vector (e.g. local admin account) or any other back-door things
- Password scraping to recover AD credentials used during the installation from PXE boot file - Windows image extracton -> data extraction.

### 3.4. System Center Configuration Manager (SCCM)
This service can be seen as the big brother to MDT. It manages the software after installation. It allows the IT team to remotely install updates to all software across the organization.

### 3.5. Windows Imaging Format (WIM)
Bootable images of Windows OS. It's a file-based disk image format.
