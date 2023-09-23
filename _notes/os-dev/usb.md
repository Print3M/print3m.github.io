---
title: USB - Universal Serial Bus
---

- [1. Overview](#1-overview)
- [2. Descriptors](#2-descriptors)
  - [2.1. Device Descriptor](#21-device-descriptor)
  - [2.2. Configuration Descriptor](#22-configuration-descriptor)
  - [2.3. Interface Descriptor](#23-interface-descriptor)
  - [2.4. Endpoint Descriptor](#24-endpoint-descriptor)

## 1. Overview
USB is a huge protocol. It's basicaly a whole stack of technology. A lot of the complexity lies in the hardware, hidden from the software point of view.

## 2. Descriptors
Descriptors are returned by the USB device. It's the standarized way of providing technical information what the device can do. Fields of a descriptor are written in the Systems Hungarian notation (with the data type prefixes). The structure of the descriptors is standarized as well. Not all fields are required to be filled out.

> NOTE: [Descriptor field types](https://www.engineersgarage.com/usb-descriptors-and-their-types-part-3-6/).  

Descriptors are structured in the tree hierarchy:

1. Device Descriptor
2. Configuration Descriptor
3. Interface Descriptor
4. Endpoint Descriptor

### 2.1. Device Descriptor
The most general descriptor - root descriptor of all other descriptors. It must be present on every single USB device. It provides many useful product-specific information which are used by an OS to match proper driver for the device.

> NOTE: USB Vendor ID is unique and it's sold for 5000$ USD per year. Product ID is a unique identifier for this specific device of the vendor.

```bash
bcdUSB                          # USB protocol version
idVendor                        # Unique vendor ID
idProduct                       # Unique product ID
bNumConfigurations              # Num of configuration descriptions present
```

### 2.2. Configuration Descriptor
Usually there is only one configuration descriptor. If there is more, only one configuration can be used at once. Different configurations might specify different ways of powering the device (e.g. with USB or with external power source).

```bash
bConfigurationValue             # Configuration ID
bNumInterfaces                  # Num of interface descriptions present
```

### 2.3. Interface Descriptor
USB device internally has a bunch of **interfaces**. The interface provides high level functionality of the device. Each interface can be controlled independantely. A webcam (USB device) might consist of a camera and a microphone - using interfaces you are able to access them separately.

It's common to write seperate drivers for different interfaces. It works quite like different devices.

```bash
bInterfaceNumber                # Interface ID
bNumEndpoints                   # Num of endpoint descriptions present
```

### 2.4. Endpoint Descriptor
The interface consists of **endpoints**. The endpoint is a place where you can send a message to or from. It's kinda like a port to communicate with interface. When a software communicate with an USB device, in fact it talks to the different endpoints. There are two types of them: IN and OUT. There are considered always from the host (PC) perspective. An OUT endpoint is used when the host wants to send something to the device. An IN endpoint is used when the device sends something to the host.

IN packet from the host is the request of some data from the device. The host is always the site that initializes and requests things. There is no standard interrupt model, that the device can interrupt the host and bring its attention. Always the host asks asks for data from the device.

Each endpoint handles specific transfer type:

- CONTROL - device enumeration, configuration and control operations with small data (up to 64 bytes) and guaranteed delivery (error checking and retransmission). It's the only transfer that has structured data described in the spec.
- INTERRUPT - periodic, small and low-latency data communication (up to 64 bytes per payload).
- BULK - large-volume data transfer in a non-time-sensitive manner (printers, external storage devices).
- ISOCHRONOUS - continous flow of data without error checking or retransmission (video or audio streaming).

#### 2.4.1. Endpoint 0
Endpoint 0 is a special endpoint in USB communication that is used for device enumeration and CONTROL transfers. It is not explicitly defined within the descriptor structure, but rather it is implicitly associated with the device itself. It must be present on every USB device. It's placed outside of the descriptors hierarchy - it must work before any hierarchy is actualy provided to the host.

There is only one bidirectional Endpoint 0 (it handles IN and OUT transfers) per device. It's so default that it's not even explicitly listed in in the descriptors tree (nor in the `lsusb -v` output).
