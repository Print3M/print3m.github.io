---
title: Linux drivers architecture
---

- [1. What is a device driver?](#1-what-is-a-device-driver)
- [2. Linux core API](#2-linux-core-api)
- [3. Devices in Unix-world](#3-devices-in-unix-world)
- [4. Frameworks and subsystems](#4-frameworks-and-subsystems)
- [5. Matching a driver to the device](#5-matching-a-driver-to-the-device)

## 1. What is a device driver?
Drivers are a specific type (or class) of the Linux Kernel Module. The role of driver is to map standard and universal OS calls to device-specific operations. For example, loudspeaker's volume might be low-level controlled in different ways but Linux always expects to change the volume using some operation. It is the driver's responsibility to take that operation and to perform the appropriate action with the device to achieve the desired result. Drivers hide device-specific technical details from Linux eyes.

## 2. Linux core API
Linux core API provides a bunch of utility functions to write a drivers for any kind of common device types. There is API not only for specific plugs, like PCI or USB, but also for a specific type of device, e.g. ALSA for sound devices. It's not possible to use user-space libraries in the kernel-space drivers, so the kernel is responsible for providing a convenient API to allow a programmer no to reinvent the wheel every time they want to communicate with an standarized USB device for instance.

Linux is an open-source OS, so the core API used to write drivers is open-source as well. Windows, for example, is closed-source, so driver developers only has to relay on the official documentation.

## 3. Devices in Unix-world
Every piece of hardware, with a driver associated to it, is represented in the Unix-world as a device file. These files are accessible from user-space in the `/dev/` directory. There are two types of them:

- Character device files (`c`) - sequential, byte-oriented interface for accessing devices. A user can read and write to the file one character at a time, without buffering.
- Block device files (`b`)- block-oriented interface for accessing devices. A user can read and write to the file fixed-size blocks of data. There is also a random access allowed and a buffering mechanism implemented.

The device files are created by the driver successfully attached to the device. Performing operations on these files is actualy interacting with the drivers. The drives have implemented functions what to do if a user wants to read the keyboard dev-file and so on.

## 4. Frameworks and subsystems
There is a problem. The driver creates the device file and the driver is responsible for handling any operation performed on the dev-file, so how we can be sure that every keyboard dev-file has the same interface and understands the same structure of data. This is where Linux frameworks come into play. The thing is that Linux developers noticed that huge part of an avarage driver is a boilerplate code. For example, there is no need to reinvent the sysfs-based interface for controlling LEDs all the time. There is a LED framework, which have unified approach to interact with LEDs, already implemented in the Linux kernel.

The Linux Kernel Module architecture is some kind of module as well. There is a standard way of implementing this thing. The Linux Driver Model is a framework - it provides a standarized way of implementing device drivers across the Linux OSes.

In general, frameworks provide a structured and standardized environment for the development and integration of device drivers. These frameworks offer a set of tools (functions, consts, macros) and libraries that facilitate the creation of drivers, promote code reuse, and ensure compatibility with the Linux kernel.

There is a whole lot of different frameworks implemented in the Linux kernel. Basically any type of modern device can be probably implemented using one of the already implemented Linux frameworks.

Subsystem is more low-level term. A framework provides an API for interacting with the subsystem (part of the kernel). It's not so clear because not every framework is part of the subsystem actually. Most often this distinction doesn't matter. Both terms are frequently used interchangeably (even in the Linux documentation I think).

Examples:

- USB Subsystem
- Video4Linux
- Sound Subsystem (ALSA)
- LED framework
- PCI Bus Subsystem
- Linux Input Subsystem

Every framework and subsystem has its own kernel documentation. There you can find information how it should be used.

## 5. Matching a driver to the device
Every driver is associated with a bus (e.g. PCI or USB). It's done within `module_ini(func)` function. The driver is also associated with a a specific devices. Example for USB driver:

```c
static struct usb_device_id usb_table[] = {
    { USB_DEVICE(USB_DEV_VENDOR_ID, USB_DEV_PRODUCT_ID) },
    {} // Terminator
};

// Associate defined devices with this driver.
MODULE_DEVICE_TABLE(usb, usb_devices_table);
```

When a new device is added, the bus's list of drivers is iterated over to find one that supports that device. The driver defines Vendor ID and Product ID of the device that must match in order to start probing process. A probe function, defined in the driver, is called by the kernel in order to verify whether the driver really supports this specific device. It returns `0` if a provided device (or an interface in case of USB for example) matches its requirements, otherwise - error code. The framework used to register device driver usually handles creating a device-file creation and an interface to interact with it.
