---
title: Advanced Programmable Interrupt Controller
---

- [1. Terminology](#1-terminology)
- [2. What is it?](#2-what-is-it)
- [3. Architecture](#3-architecture)
  - [3.1. Local APIC](#31-local-apic)
  - [3.2. I/O APIC](#32-io-apic)
- [4. Additional resources](#4-additional-resources)

## 1. Terminology

- **IRQ** - _interrupt request_, an request sent to the CPU in order to stop execution and do something else (execute interrupt handler).
- **Interrupt** - the event that happens on the IRQ.
- **Interrupt handler** - an piece of code which is executed on specific IRQ.
- **Interrupt vector table** - a list of interrupt handlers; it's a technical abstract term; the IVT has different implementations on specific CPUs.
- **Interrupt vector** - an entry in the IVT.
- **Interrupt Descriptor Table** - Intel's x86 implementation of IVT.
- **Global System Interrupt (GSI)** - another name of the IRQ but in the context of I/O APIC.

## 2. What is it?
APIC is a modern replacement for the 8259 Programmable Interrupt Controller (PIC). It is an Intel concept.

> **IMPORTANT**: CPU Interrupt Flag (EFLAGS.IF) must be enabled.

## 3. Architecture
APIC architecture is split into two hardware devices. Information about both parts (installed version, abilities, presence, MMIO addresses) can be found using ACPI Standard Description Table MADT (Multiple APIC Description Table).

### 3.1. Local APIC
> **MORE**: LAPIC is part of the CPU so it's specified in Intel's Manual, volume 3, chapter 10. APIC.

LAPIC is usually integrated into the CPU itself. Every CPU has its own LAPIC. It manages all external IRQs for specific CPU in an SMP system. LAPIC is also able to accept and generate inter-processor interrupts (IPI) used to communication between CPUs. LAPIC can process up to 224 interrupt vectors - first 32 entries are reserved for standard x86 exceptions.

Local APIC receives interrupts from the processor’s interrupt pins, internal sources and an external I/O APIC (or other external interrupt controller). It sends IRQs to the processor core for handling.

Local APIC handles following interrupts:

- IRQs from the I/O APIC
- IPIs (Inter-Processor Interrupts) from other CPUs. They are used in SMP systems.
- Local (self-generated) interrupts (e.g. APIC timer, thermal sensors, etc.). The role of LAPIC for local interrupts is analogous to the role of I/O APIC for external interrupts. It uses the LVT (Local Vector Table) as a redirection table for local interrupts.

LAPIC has one set of registers. See all of them in "Table 10-1" in Intel's Manual, volume 3. It is configured by memory-mapped registers (default starting address: `0xFEE00000`).

#### 3.1.1. Local APIC ID
Each APIC has APIC ID assigned. It can be used as a CPU ID. The APIC ID is unique for all CPUs installed in the system. It can be read from APIC ID register (offset: 0x20). On xAPIC up to 256 CPUs are supported.

#### 3.1.2. Spurious interrupt vector
TBD

#### 3.1.3. How does fixed interrupt handling work?
> **MORE**: Intel's Manual, volume 3, chapter 10.8.4 Interrupt Acceptance for Fixed Interrupts.

The LAPIC IRR register (256 bits) contains the active IRQ that have been accepted, but not yet dispatched to the processor for processing. When the LAPIC accepts an IRQ, it sets the bit in the IRR that corresponds the vector of the accepted IRQ. When the processor core is ready to handle the next IRQ, the LAPIC clears the corresponding IRR bit that is set and sets the corresponding ISR bit. IRR and ISR registers are some kind of bitmaps. Each bit is an interrupt vector. When the Interrupt Service Routine issues a write to the EOI register the local APIC responds by clearing corresponding the ISR bit.

#### 3.1.4. Return from interrupt
> **MORE**: Intel's Manual, volume 3, chapter 10.8.5 Signaling Interrupt Servicing Completion

To signal interrupt handling completion to the LAPIC, the interrupt handler must include a write to the _end-of-interrupt_ (EOI) register. This write must occur at the end of the handler function. This action indicates that the handling of the current interrupt is complete and the LAPIC can issue the next interrupt from the ISR.

### 3.2. I/O APIC
> **MORE**: I/O APIC is very platform related and there is no latest official documentation of this piece of hardware.

IOAPIC is part of the chipset. It contains a redirection table, which is used to route the IRQs from peripherals (external hardware) to a specific LAPIC. It allows to translate an hardware IRQ number to specific interrupt vector (the mapping can be controlled by a software). Most often IOAPIC supports 24 separately programmable interrupt entries.

> **NOTE**: Formally (according to the Intel's Manual), the signal that is sent between IOAPIC and LAPIC is called an _Interrupt Message_.

#### 3.2.1. Configuration
IOAPIC is configured by memory-mapped registers (starting address: `0xFEC00000`). Due to space saving IOAPIC registers are accessed by writing selected register `offset` into _IOREGSEL_ register and then writing/reading register's data in _IOWIN_ register (where the selected register is placed).

There is one 64-bit register for each redirection entry. Data _IOWIN_ register is 32-bit long, it means that the 64-bit entry's register must be written in two rounds. Lower half must be written first. Writing higher half (offset + 1) actually applies the changes.

IOAPIC registers schema:

```text
0xfec0 xy00     IOREGSEL    I/O Register Select     RW
0xfec0 xy10     IOWIN       I/O Window              RW

----- Registers to be selected via IOREGSEL -----
0x00            IOAPICID    IOAPIC ID               RW
0x01            IOAPICVER   IOAPIC Version          R
0x02            IOAPICARB   IOAPIC Arbitration ID   R
0x10-3F         IOREDTBL    Redirection Table       RW
                            ^-- (24 entries)
```

> **REDIRECTION ENTRY**: The schema of a redirection entry register can be found in I/O APIC Specification, chapter 3.2.4 IOREDTBL[23:0].

#### 3.2.2. How does it work?
> **NOTE**: The number of the sent IRQ does not have to correspond to the entry number to which it will go (see: I/O APIC Specification, chapter 2.4 Interrupt Signals).

When the IOAPIC receives an **external interrupt** from a external device, it forwards the interrupt to the LAPIC. When an LAPIC is able to accept the interrupt, the LAPIC will signal an interrupt to the CPU and the CPU will interrupt through the corresponding interrupt vector that was programmed into the IOAPIC.

```text
External
interrupts             I/O APIC
              ,,,,,,,,,,,,,,,,,,,,,,,
IRQ 0 --------|entry 0 -> vector 156|  |Interrupt|
              |                     |  | Message |
IRQ 1 --------|entry 1 -> vector 87 |-------------> LAPIC --> CPU 
              |                     |                          |
IRQ 2 --------|entry 2 -> vector 97 |                          |
              ```````````````````````                       Execute
                                                           interrupt 
                                                            vector X
```

## 4. Additional resources

- [Dreamos82: Os-dev notes - APIC](https://dreamos82.github.io/Osdev-Notes/98_Drivers/APIC.html)
- [Kestrel Williams-King: OSDev notes 3: Hardware & Interrupts](https://web.archive.org/web/20220725202237/https://ethv.net/workshops/osdev/notes/notes-3.html)
- [Wesleyac: How to set up the APIC to get keyboard interrupts](https://blog.wesleyac.com/posts/ioapic-interrupts)
- [Kostr: External Interrupts in the x86 system. Part 1. Interrupt controller evolution](https://habr.com/en/articles/446312/)
- [Kostr: External Interrupts in the x86 system. Part 2. Linux kernel boot options](https://habr.com/en/articles/501660/)
- [Kostr: External Interrupts in the x86 system. Part 3. Interrupt routing setup in a chipset, with the example of coreboot](https://habr.com/en/articles/501912/)
