---
title: High Precision Even Timer
---

- [1. What is HPET?](#1-what-is-hpet)
- [2. Architecture](#2-architecture)
  - [2.1. Timer](#21-timer)
    - [2.1.1. Counter](#211-counter)
    - [2.1.2. Comparators](#212-comparators)
- [3. MMIO configuration](#3-mmio-configuration)
- [4. Interrupts](#4-interrupts)
  - [4.1. Non-Periodic mode](#41-non-periodic-mode)
  - [4.2. Periodic mode](#42-periodic-mode)

## 1. What is HPET?
HPET is a hardware timer developed by Intel and Microsoft, incorporated in chipsets since 2005. The main reason for its introduction was to replace older, less efficient and accurate timers such as PIT (Programmable Interval Timer).

## 2. Architecture
> **More**: HPET Sepcification

### 2.1. Timer
HPET device must implement at least one timer - it is the highest programmable unit of the HPET device. The timer consists of a counter and set of comparators. Each individual timer can generate an interrupt when the value in one of its comparator registers equals the value of the counter. Each timer can have different clocking attributes. The timer is enabled (counts up and generates interrupts) by setting enable bit in _General Configuration_ register.

#### 2.1.1. Counter
The timer has **one counter** (called: _main counter_) only. The counter is a 64-bit (or 32-bit, check _General Capabilities & ID_ reg.) register incremented by hardware every specified number of nanoseconds. The counter increases monotonically. When software does two consecutive reads of the counter, the second read will never return a value that is less than the first read. Software should write to that register only when the timer is halted (not enabled).

#### 2.1.2. Comparators
> **NOTE**: The HPET Specification is confusing. Sometimes _counter_ + _comparator_ is called a _Timer_, and sometimes (most often) comparators are called _timers_. I made a distinction between _timer_ and its _comparators_.

Every timer has set of 3 to 32 comparators. The exact number of available comparators can be read from _General Capabilities & ID_ register.

## 3. MMIO configuration
HPET is programmed using MMIO. The base address of HPET can be found using ACPI Standard Description Table "HPET". Single timer MMIO address space is 1024 bytes. Registers are aligned on 64-bit boundaries.

The layout of the MMIO registers is the same for each timer:

```text
|   Offset      |   Register                    |   Type    |   Chapter |
|------------------------------------------------------------------------   
|   0x000-007   |   General Capabilities & ID   |   R       |   2.3.4   |
|   0x008-00F   |   General Configration        |   RW      |   2.3.5   |
|   0x010-017   |   General Interrupt Status    |   RW      |   2.3.6   |
|   0x018-01F   |   Main Counter Value          |   RW      |   2.3.7   |
|               |                               |           |           |
|------- Comparator 0 ---------------------------------------------------
|   0x100-107   |   Config and Capabilities     |   RW      |   2.3.8   |
|   0x108-10F   |   Comparator Value            |   RW      |   2.3.9   |
|   0x110-117   |   FSB Interrupt Routing       |   RW      |   2.3.10  |
|------- Comparator 1 ---------------------------------------------------
|   0x120-127   |   Config and Capabilities     |   RW      |   2.3.8   |
|   0x128-12F   |   Comparator Value            |   RW      |   2.3.9   |
|   0x130-137   |   FSB Interrupt Routing       |   RW      |   2.3.10  |
|...                                                                    |
|------- Comparator 31 --------------------------------------------------
|...                                                                    |
```

## 4. Interrupts
HPET usually supports many legacy interrupt routings but IO/APIC is required to be supported. Other ones (FSB, PIC) are optional. Mode and configuration related to the fired interrupts is set for each comparator separately (_Config and Capabilities_ register). It's the most complicated part of the whole HPET management.

### 4.1. Non-Periodic mode
Every timer is required to suport the non-periodic mode of operation. This mode can be thought as one-shot timer. Counter is up and comparator is set once. During the run-time, the value in the comparator is not changed by the hardware. Software can change the value. If counter is equal to comparator, an interrupt is generated. To do it properly main counter has to be disabled during the comparator configuration - I don't see any other way to do this correctly.

### 4.2. Periodic mode
The software writes a value in the timer's comparator. If counter is equal to comparator, an interrupt is generated. The hardware will then automatically increase the value in the comparator by the last value written to that register. It generates an interrupt on each hit.
