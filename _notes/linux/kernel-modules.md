---
title: Linux Kernel Modules (LKM)
---

- [1. Resources](#1-resources)
- [2. Requirements](#2-requirements)
- [3. What is kernel module?](#3-what-is-kernel-module)
- [4. Operations with modules](#4-operations-with-modules)
- [5. Useful header files](#5-useful-header-files)

## 1. Resources
Additional resources to check out:

- [The Linux Kernel Module Programming Guide](https://sysprog21.github.io/lkmpg)

## 2. Requirements

```bash
apt install kmod build-essential        # Commands to interact with modules
apt install linux-headers-`uname -r`    # Linux kernel headers
```

## 3. What is kernel module?
Kernel module is a piece of code that extends the functionality of the kernel without the need to reboot the OS. A device driver is one type of possible kernel modules (it allows the kernel to communicate with an external hardware). Without modules, every time new driver needs to be loaded, the kernel source code needs be rebuilt.

Kernel modules are compiled into `.ko` (kernel object) files. It is object code (not linked into a complete executable) that can be dynamically linked to the running kernel by the `insmod` program and can be unlinked by the `rmmod` program.

In kernel module there are no standard library functions available. Everything needs to be done using kernel functions. For example, you cannot use `printf()` functions. There is a `printk()` (`linux/printk.h`) function instead. It logs output to the TTY console, so it's not visible in the GUI but it can be read using `journalctl` or `dmesg` commands.

## 4. Operations with modules

```bash
lsmod                                   # List all loaded modules
insmode <ko-file>                       # Load module
rmmod <module-name>                     # Remove module
modinfo <ko-file>                       # Module info
```

## 5. Useful header files

```c
#include <linux/module.h>               // All modules need to have this
#include <linux/printk.h>               // For output logging functions
#include <linux/init.h>                 // For macros 
```
