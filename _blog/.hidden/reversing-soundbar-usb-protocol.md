---
slug: init-post
title: Init post
description: Init post
date: "1970-01-01"
hidden: true
---

## Init post
Init post

## How to sniff USB with usbmon and Wireshark
The `usbmon` is a kernel module which is used to collect traces of I/O operations on the USB bus. It needs to be loaded.

```bash
# Load usbmon kernel module
sudo modprobe usbmon

# Check all loaded kernel modules
lsmod
```

Now you can run Wireshark. To identify which USB device you want to sniff, you can use `lsusb` command. The **bus number** and the **device number** are essential. Every USB bus has its own number and it should be also available in the Wireshark menu as `usbmonX`. Example menu items:

```bash
enp5s0
usbmon2 <--,
usbmon1 <----- These are USB buses traffic
usbmon0 <--'
```

Now you can sniff some USB traffic. Filter out the device you want to sniff: `usb.device_address == <device-number>`.

## Get information about USB device
An example output line of `lsusb` (list all USB devices) command:

```text
Bus 001 Device 008: ID 041e:3247 Creative Technology, Ltd Sound BlasterX Katana
```

Vendor ID = `041e`, Product ID = `3247`. To get more information about that specific device use: `lsusb -v -d <vendor-id>:<product-id>`.

## Kernel modules
Show kernel modules associated with USB devices: `lsusb -vt`.

## Decoding SoundBlaster X Katana USB communication
xxx

Katana has no dedicated module and uses couple generic modules:

* [usbhid](https://github.com/torvalds/linux/tree/master/drivers/hid/usbhid)

## Problem with HID user-space drivers
Theoretically the driver uses CONTROL transfer (to the Endpoint 0) in order to change Katana's volume level. Endpoint 0 is not directly connected with any USB interface, so it should be possible not to detach actual interface driver from the kernel. Unfortunately, without detaching, an "Resource busy" error occurs. Why is that?

Katana uses CONTROL transfer indeed but with some special setup parameters:

```text
bmRequestType   = 0x21,
bRequest        = 1,
wValue          = 0x0201 (0x0202 in the second request),
wIndex          = 256,
```

The `bmRequestType` parameter is a bit-field type:

```text
                           0x21 in binary

       0                         01                 00001
host-to-device (OUT)       class-specific         interface
```

I guess it has something to do with HID interface and because of that it doesn't work without detaching interface drivers. Unfortunately, the interfaces we have to disconnect interrupt the sound. I don't feel like implementing a whole audio driver just to change the volume. I was looking for an option to create some kind of "nested driver" that would use the default `snd-usb-audio` underneath, but would add my functionalities. I haven't found any sources on this. You'd probably have to rewrite the entire driver from scratch. The problem is that Katana uses the same interfaces to send audio and change volume level. Theoretically, it is possible to detach and reattach the driver after the script is executed, but of course `dev.attach_kernel_driver(x)` function doesn't work, so the project is stuck.

Maybe I'll figure out some way of using the default `snd-usb-audio` driver underneath in the future.
