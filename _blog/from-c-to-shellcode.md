---
title: From C to shellcode (simple way)
---

TL;DR; [c-to-shellcode GitHub](https://github.com/Print3M/c-to-shellcode)

Shellcode (in terms of malware development) is a independent piece of machine code that can be injected anywhere and executed without worrying about dependencies, DLLs, stack layout, other kinds of adversity.

The most obvious way to create shellcode is to use Assembly language, which is very predictable and easy to use after compilation. Dependency-free Assembly guarantees the conditions provided for a valid shellcode. However, writing extensive code in Assembly can be quite complicated. Mankind noticed this problem long ago and created the C language in the 1970s. I write about the history of the C language here: [C standard vs implementation](https://print3m.github.io/blog/c-standard-vs-implementation).

C is much easier to use than Assembly but has drawbacks nonetheless. We do not have full control over the stack, the machine code produced is larger and less predictable. Compilers add a lot of their own functions and compile everything into a complex PE or ELF file structure.

So is it actualy possible to write code in C that could be used as a standalone shellcode? Yes, it can be done although it requires special steps.

## How to write a shellcode in C?

When writing shellcode in C, we need to be careful about a few things. First, after compilation, the only section we will have access to will be `.text` section. So we cannot use global constants or string literals directly in the code. They are placed in the `.rodata` or `.data` section.

**1.** We have to put all constants on the stack, string literals too. To get **stack-based strings**, we have to turn the string into an array of chars and put it in a local variable:

```c
// "calc.exe"
char path[] = {'c', 'a', 'l', 'c', '.', 'e', 'x', 'e', '\0'};
```

> **IMPORTANT**: Remember about the null-terminator character at the end of the array!

In the case of wide character strings (often used in WinAPI), the notation is as follows:

```c
// L"KERNEL32.DLL"
wchar_t dll_name[] = {
  L'K', L'E', L'R', L'N', L'E',  L'L', L'3', L'2', L'.', L'D', L'L',  L'L', L'\0',
};
```

Here's a convenient one-liner in Python for converting strings to stack-based strings:

```python
string = "example string"
output = "{" + ', '.join([f"L'{c}'" for c in string]) + ", L'\0'}"
```

**2.** We don't have access to any external libraries so no libc. Independent shellcode can't rely on dependencies it won't load itself. To interact with the operating system, you need to use the Windows API via indirect API calling (manually parsing kernel32.dll and using WinAPI functions).

**3.** All our local functions must be placed in a separate section by the compiler, so that we can move them to the end of the shellcode at the linking stage. I write more about linking below. To achieve this we will use a special directive of the GCC compiler:

```c
// Convenient macro
#define FUNC __attribute__((section(".func")))

// All functions must use FUNC macro to specify target section
FUNC int ThisIsExampleFunction(void) {
  return 1;
}
```

## Compilation

For compilation I use MinGW (`x86_64-w64-mingw32-gcc-win32`) which is a port of GCC for Windows. Trying to do the same from MSVC on Windows can lead to mental breakdown. MinGW implements all necessary GCC flags to generate shellcode:

```bash
x86_64-w64-mingw32-gcc-win32 -c payload.c -o bin/payload.o  -Os -fPIC -nostdlib -nostartfiles -ffreestanding -fno-asynchronous-unwind-tables -fno-ident -e start -s
```

- `-Os` - optimize generated machine code for size rather than speed;
- `-fPIC` - generate position-independent code (don't hardcode specific memory addresses);
- `-nostdlib` - don't link with libc;
- `-nostartfiles` - don't link with standard startup files, don't include standard initialization code that runs before the main function;
- `-ffreestanding` - generate code for a freestanding environment (no dependencies or runtime assumptions);
- `-fno-asynchronous-unwind-tables` - don't generate stack unwind tables (reduce binary size);
- `-fno-ident` - don't generate compiler identification string (reduce binary size);
- `-s` - strip all symbols and debugging information (reduce binary size);
- `-e start` - specify the entry point to the program (instead of default `main`);

Then we take the generated file and link it using a special linker script:

```bash
ld -T assets/linker.ld bin/payload.o -o bin/payload.bin
```

I will not describe here how the linker script works exactly. The most important information is that it generates a flat binary file with our entry point at the beginning of the shellcode, followed only by local functions. This way, by injecting the shellcode, we can start execution at the beginning of the buffer:

```ld
OUTPUT_FORMAT("binary");
BASE = 0x00;

SECTIONS
{
    . = BASE;
    .text : {
        . = BASE;
        *(.text)
        *(.func)
    }
}
```

![Linking process: from PE to flat binary](/imgs/from-c-to-shellcode/flat-binary-linking.png)

The `.text` and `.func` sections (where we keep our functions) have been merged into one continuous raw machine code in `payload.bin`. **This is our independent shellcode!** We can embed the binary file prepared this way in the shellcode loader and execute it.

![Raw binary independent shellcode](/imgs/from-c-to-shellcode/shellcode.png)

## Indirect API calling in C

Indirect API calling by manually parsing `kernel32.dll` library structures from process memory I described in detail in this blog post: [Shellcode x64: Find and execute WinAPI functions with Assembly](https://print3m.github.io/blog/x64-winapi-shellcoding). Now I'm just going to demonstrate how much faster and more convenient it is to get the same effect using C.

I implemented two functions from standard libc: `wcscmp` and `strcmp`. The function that retrieves the address of the PEB structure must have been implemented using GCC's disgusting inline assembly syntax, since we are using the GS segment register here:

```c
FUNC PPEB GetPEB(void) {
  uint64_t value = 0;

  // Inline assembly to read from the GS segment
  asm volatile("movq %%gs:%1, %0"
               : "=r"(value)            // output
               : "m"(*(uint64_t *)0x60) // input
               :                        // no clobbered registers
  );

  return (PPEB)value;
}
```

The following program run `calc.exe` without using any libraries directly (note the stack-based strings):

```c
typedef UINT(WINAPI *WinExecPtr)(LPCSTR lpCmdLine, UINT uCmdShow);

int start(void) {
  PPEB peb = GetPEB();

  wchar_t dll_name[] = {
      L'C', L':', L'\\', L'W', L'i', L'n', L'd', L'o', L'w',  L's', L'\\',
      L'S', L'y', L's',  L't', L'e', L'm', L'3', L'2', L'\\', L'K', L'E',
      L'R', L'N', L'E',  L'L', L'3', L'2', L'.', L'D', L'L',  L'L', L'\0',
  };

  // Get address of kernel32.dll
  PLDR_DATA_TABLE_ENTRY kernel32_ldr = GetDllLdr(peb->Ldr, dll_name);
  PIMAGE_DOS_HEADER kernel32 = (PIMAGE_DOS_HEADER)kernel32_ldr->DllBase;

  // Get address of PE headers
  PVOID pe_hdrs = (PVOID)((PVOID)kernel32 + kernel32->e_lfanew);

  // Get Export Address Table RVA
  DWORD eat_rva = *(PDWORD)(pe_hdrs + 0x88);

  // Get address of Export Address Table
  PIMAGE_EXPORT_DIRECTORY eat =
      (PIMAGE_EXPORT_DIRECTORY)((PVOID)kernel32 + eat_rva);

  // Get address of function names table
  PDWORD name_rva = (PDWORD)((PVOID)kernel32 + eat->AddressOfNames);

  // Get function name
  char func_name[] = {'W', 'i', 'n', 'E', 'x', 'e', 'c', '\0'};
  uint64_t i = 0;

  do {
    char *tmp = (char *)((PVOID)kernel32 + name_rva[i]);

    if (my_strcmp(tmp, func_name) == 0) {
      break;
    }
    i++;
  } while (true);

  // Get function ordinal
  PWORD ordinals = (PWORD)((PVOID)kernel32 + eat->AddressOfNameOrdinals);
  WORD ordinal = ordinals[i];

  // Get function pointer
  PDWORD func_rvas = (PDWORD)((PVOID)kernel32 + eat->AddressOfFunctions);
  DWORD func_rva = func_rvas[ordinal];
  WinExecPtr winExecPtr = (WinExecPtr)((PVOID)kernel32 + func_rva);

  // Run WinAPI function
  char path[] = {'c', 'a', 'l', 'c', '.', 'e', 'x', 'e', '\0'};
  ALIGN_STACK();
  winExecPtr(path, SW_SHOWNORMAL);

  return 0;
}
```

A more unusual thing in this program is the `ALIGN_STACK()` macro before calling the `WinExec` function. It's the requirement of WinAPI to align stack before calling. Since the compiler does not know that we are calling a WinAPI function (indirect API calling), we have to take care of stack alignment ourselves before each call. Not gonna lie, this mess is generated by AI. I'm disgusted by AT&T syntax with GCC inline Assembly.

```c
#define ALIGN_STACK()                                                          \
  __asm__ __volatile__(                                                        \
      "mov %%rsp, %%rax;" /* Move stack pointer to rax */                      \
      "and $0xF, %%rax;"  /* Check if aligned to 16 bytes */                   \
      "jz aligned;"       /* If aligned, jump to aligned If not aligned,       \
                             adjust the stack pointer */                       \
      "sub $8, %%rsp;"    /* Decrease stack pointer by 8 bytes */              \
      "xor %0, %0;"       /* Optionally zero out the allocated space */        \
      "aligned:"                                                               \
      :        /* No output operands */                                        \
      : "r"(0) /* Input operand (to zero out) */                               \
      : "%rax" /* Clobbered register */                                        \
  );
```

It is worth noting that in the code you can use types belonging to external header files:

```c
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <wchar.h>
#include <windows.h>
#include <winternl.h>

// Types from WinAPI
typedef UINT(WINAPI *WinExecPtr)(LPCSTR lpCmdLine, UINT uCmdShow);
```

Types are used only at the compilation stage and do not affect the “no dependency” principle, as long as you do not use a specific function. The types and macros themselves are harmless.

Full source code available at: [payload.c](https://github.com/Print3M/c-to-shellcode/blob/main/payload.c)

Here's the result:

![Screenshot: executing payload (calc.exe) on Windows](/imgs/from-c-to-shellcode/calc-exe.png)

## Assembly vs C shellcode

The entire C program executing `calc.exe` compiled into shellcode **takes 480 bytes**. A program doing the same thing written in pure Assembly **takes about 200 bytes**. And my Assembly isn't the most concise code in the world. That's still more than twice as many bytes. With larger programs this difference will probably increase, but **the benefits of using C (in my opinion) are more important than the bytes saved**.

Code written in C is just readable, easy to expand and maintain. In fact, it is rather obvious at first glance.

## Automation script

I wouldn't be myself if I didn't automate the entire process. A Python script that compiles C to shellcode and injects it right into the example loader can be found here: [https://github.com/Print3M/c-to-shellcode](c-to-shellcode.py)

The script generates the following files:

- `bin/payload.exe` - compiled C program (without shellcode conversion), so you can use libc and WinAPI functions directly, e.g. `printf()`. Great for debugging and fast development.
- `bin/loader.exe` - sample loader with compiled shellcode. It really injects shellcode into memory and executes it just like real malware.
- `bin/payload.bin` - raw shellcode binary file.

![Screenshot: "c-to-shellcode.py" output files](/imgs/from-c-to-shellcode/python-script.png)

The Python script allows for rapid prototyping and debugging. It returns all necessary file formats for effective malware development.

\~ Print3M
