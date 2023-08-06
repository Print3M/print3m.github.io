---
title: ACPI - Advanced Configuration and Power Interface
---

- [1. RSDP - Root System Description Pointer](#1-rsdp---root-system-description-pointer)
- [2. SDT - System Description Tables](#2-sdt---system-description-tables)
  - [2.1. MADT - Multiple APIC Description Table](#21-madt---multiple-apic-description-table)

## 1. RSDP - Root System Description Pointer
> **More**: ACPI Specification, chapter 5.2.5.
RSDP is the first data structure that OS developer must touch to do anything more with ACPI.

```c Table 5.3: RSDP Structure
struct __attribute__ ((packed)); RSDP {
    char signature[8];
    u8 checksum;
    char oemid[6];
    u8 revision;
    u32 rsdt_addr;
};
```

It might be located anywhere in the MMIO memory. On older systems with BIOS, it had to be manually searched by scanning the entire memory and looking for certain `signature` string ("RSD PTR "). On new systems, you can pull the RSDP from the EFI Configuration Table (in the EFI System Table) using the GUID assigned to the ACPI. Reading the RSDP is therefore handled by the bootloader.

The RSDP structure can be aditionally verified with `signature` (should be "RSD PTR " - with space at the end!) and `checksum`.

There are two versions of ACPI: 1.0 and 2.0. The latter is backward compatible with version 1.0. It does not appear to have any significant new features. It is probably not even supported by Qemu and everything works.

## 2. SDT - System Description Tables
> **More**: ACPI Specification, chapter 5.1 and 5.2.

Architecture of SDTs:

```text
RSDP -> RSDT: SDT header + tables[1, 2, 3, ...]
                                  |  |  |
                                MADT |  |
              (SDT header + content) |  |
                                     |  |
                                   TPM2 |
                 (SDT header + content) |
                                        |
                                      HPET
                    (SDT header + content)
```

SDTs is standarized ACPI way of providing information about different devices or functions of hardware. It's collection of different tables. Every SDT starts with the same SDT header structure.

```c Table 5.4: SDT header
struct __attribute__((packed)) Header {
    char signature[4];
    u32 length;         // Length of the SDT in bytes (including header)
    u8 revision;
    u8 checksum;
    char oem_id[6];
    char oem_table_id[8];
    u32 oem_revision;
    u32 creator_id;
    u32 creator_revision;
};
```

The `signature` field is used to find the table you are looking for. There are dozens of different tables that contain all sorts of information. Here are some examples of signatures:

```text Table 5.5: SDT Header Signatures
"RSDT" - Root System Description Table
"APIC" - Multiple APIC Description Table (MADT)
"HPET" - High Precision Event Timer Table
"TPM2" - Trusted Platform Module 2 Table
"MPST" - Memory Power State Table 
```

> **Note**: Many of these tables are documented in the ACPI Specification but some of them (e.g. HPET) are maintained by third-party.

These tables contain specific information about different devices/functions, such as device's version, features and MMIO addresses for controlling specific device. One of them is RSDT. It's pointed by RSDP `rsdt_addr` field and it's important because it gives us list of pointers to all other tables. Actually, RSDT is just a normal SDT table, but it has more _internal_ meaning.

```c Table 5.7: RSDT
Header header;      // SDT header
u32 sdt_tables[];   // 32-bit pointers to other tables
```

### 2.1. MADT - Multiple APIC Description Table
> **More**: ACPI Specification, chapter 5.2.12.

It's one of the most important SDTs. It provides information necessary for operation on systems with APIC (Advanced Programmable Interrupt Controller).
