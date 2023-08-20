---
title: Windows internals notes
---

- [1. Processes](#1-processes)
- [2. DLL](#2-dll)

## 1. Processes

Attackers target processes to hide malware as legitimate process. Potential attacks:

- Process Injection
- Process Hollowing
- Process Masquerading

> **NOTE**: `Procmon` is very useful tool if you want to know much more about processes than from the standard task manager.

Important security property of processes is the _Integrity Level_. TBD

## 2. DLL

Dynamic Linking Library (DLL) contains code that can be used by more than one program at the same time. It helps to achive modularization, efficient memory and disk space usage. Since a program is dependent on a DLL, an attacker can target the DLLs to control some aspects of application execution. Potential attacks:

- DLL Hijacking
- DLL Side-Loading
- DLL Injection
