---
title: C standard vs implementation - platonism and compilers
createdAt: "2024-09-01"
thumbnail: /imgs/c-standard-vs-implementation/thumbnail.webp
description: The C standard is not actually read by anyone, except perhaps compiler developers. I want to define what is part of the standard and what is an implementation.
---

![C Standard vs Implementation banner - Dennis Ritchie](/imgs/c-standard-vs-implementation/thumbnail.webp)

## 1. Introduction

Today we will delve into the fascinating world of the C language standard and its actual implementations in the form of compilers and the standard libraries. In the beginning there was chaos, from this chaos emerged order in the form of the C standard, the beautiful platonic idea, and then chaos emerged again, with the growth of compilers, and built-in functions, and directives, and custom keywords and...

It still surprises me that the C standard is not actually read by anyone, except perhaps compiler developers. I want to define once and for all what is part of the standard and what is an implementation.

## 2. Standarization of C Language

Let's start at the beginning. **The C language was developed in 1972 by Dennis Ritchie while working on the Unix operating system**. The preprocessor was introduced around 1973. In 1973 the Unix kernel was reimplemented in C. Unix was one of the first operating system kernels implemented in a language other than assembly. C was rapidly gaining popularity however it was not standardized.

### 2.1. K&R C (1972-1989)

The book _The C Programming Language_ from 1978, co-authored by Dennis Ritchie, served for many years as the de facto standard for the language. The version of C that it describes is commonly referred to as _K&R C_. As the famous book was released in 1978, it is now also referred to as _C78_.

_K&R C_ introduced several language features. They initiated the development of the standard library (`stdio.h` was probably the first "standarized" header).

The large number of custom extensions and lack of agreement on a standard library, together with the language popularity and the fact that not even the Unix compilers precisely implemented the K&R specification, led to the necessity of formal standardization.

### 2.2. ANSI C (1989)

One of the aims of the C standardization process was to produce a superset of _K&R C_, incorporating many of the subsequently introduced unofficial features.

In 1983, ANSI began work on standardization, basing the new C standard on the Unix implementation. In 1989, the C standard was ratified as ANSI X3.159-1989 "Programming Language C". It's called _ANSI C_, _Standard C_ or _C89_.

> The non-portable part of the Unix C library was handed off to the IEEE to become the basis for the C POSIX library in 1988.

After the ANSI standarization, any program written only in Standard C and without any hardware-dependent assumptions will run correctly on any platform with a conforming C implementation, within its resource limits.

### 2.3. ISO C (1990-now)

In 1990, the ANSI C standard (with formatting changes) was adopted by the ISO as ISO/IEC 9899:1990. It's sometimes called _C90_. Therefore, the terms _C89_ and _C90_ refer to the same programming language.

ANSI no longer develops the C standard independently. Since then, all official C language specifications have been issued by the ISO.

The latest C language standard is the so-called _C23_, or [ISO/IEC 9899:2024](https://www.open-std.org/jtc1/sc22/wg14/www/docs/n3220.pdf).

## 3. C Naming and Implementations

In theory, currently there is one C language specified by the ISO specification. It is an ideal model - the idea. This model is called _ANSI C_, _ISO C_, or _Standard C_.

However, the specification is developed and changed over the years. To distinguish between different versions of the C Standard, a two-digit number is used to denote the year of release of a particular specification. Formally, the ISO numbers should be used, but a set of informal names has been broadly adopted.

```text
 Informal |       Formal
          |
   C78    |  Before standarization
   C89    |  ANSI X3.159-1989
   C90    |  ISO/IEC 9899:1990
   C99    |  ISO/IEC 9899:1999
   C11    |  ISO/IEC 9899:2011
   C17    |  ISO/IEC 9899:2018
   C23    |  ISO/IEC 9899:2024
```

**However, the final shape of the language in which you write the program is enforced by the compiler and the libc that the compiler uses**. This is the actual implementation of the language specification and here the differences can be significant. What is defined in Standard C should remain unchanged in different implementations, otherwise standardization makes no sense. However, compilers and different libc implementations can add A LOT OF various things of their own, about which I write much more below.

Microsoft implementation of Standard C with custom features (MSVC compiler with CRT) is called _Visual C++_, _VC++_ (C is considered here as a subset of C++), _Microsoft C_, or just _MSVC_. **Using MSVC you are able to write portable C code because it still implements Standard C**. But you also have the option to use many MSVC-specific features, which are described on MSDN, and which are not available in other implementations, so the code may not be portable.  

GNU implementation of Standard C with custom features (GCC with glibc) is called _GNU C_.

In general, all feature layers added to Standard C should be a superset of Standard C. Compliance with the original ISO specification should always be maintained as much as possible. **The rest of the non-standard features are the domain compilers and the libc implementations**.

## 4. C Standard Library

C Standard library (often called _libc_) is the standard library for the C language specified in the ISO C standard. The ISO standard of the C language defines what functions, types and macros must be defined in standard header files. There are 31 standard header files.

All valid libc implementations must export all standardized functions. It is worth remembering that a given libc implementation can implement much more than the C Standard Library requires.

### 4.1. POSIX (Unix-like) systems

The C library is considered part of the operating system on Unix-like systems. The POSIX standard enforces the existence of a libc implementation on the system but header files (and compiler toolchain) may be absent so C development may not be possible. Unix-like systems typically have a C library in shared library form. **Because libc is part of the OS, compilers can assume it's always present and link to them dynamically by default**. GCC links glibc dynamically by default.  

_C POSIX Library_ is a specification of a C standard library for POSIX systems. POSIX Library includes additional functions and types (useful for developers working on POSIX systems) to those introduced in standard libc. **It's a superset of standard libc**. The POSIX standard adds new header files but also expands the standard ones. Classic example of POSIX libc extension are _POSIX Threads_ (`pthread.h`).

The most commons C POSIX Library implementations:

- GNU C Library (glibc) - used in Linux
- BSD libc - used in BSD-derived operating systems

### 4.2. Windows

On Windows, compiled applications written in C are either statically linked with a C library, or linked to a dynamic version of the library that is shipped with these applications, rather than relied upon to be present on the targeted systems.

The default Standard C Library implementation shipped with Microsoft's MSVC compiler is called _C Runtime Library_ (CRT). It implements all standard libc features and many more Microsoft-specific features. **The names of Microsoft-specific functions and global variables begin with a single underscore**. It's [documented on MSDN](https://learn.microsoft.com/en-us/cpp/c-runtime-library/c-run-time-library-reference) and it's considered as a standard libc on Windows.

On Windows 10 and later, CRT is distributed as _Universal CRT_ (UCRT) along with the operating system. Now it's more like glibc on Linux. New applications no longer need to install the specific CRT version they need to use using _Redistributable_ files. UCRT DLLs are updated via standard Windows Update mechanism. It exports all Standard C Library functions and Microsoft-specific features documented on MSDN. It's placed in `C:\Windows\system32\ucrtbase.dll` library.

There's also something called `vcruntime140.dll`. It exports MSVC intrinsics and startup / termination features. It's an MSVC thing and it's placed in IAT when you link CRT dynamically using MSVC. A lot of software assumes it's present in the system but it doesn't seem to be guaranteed by Microsoft's documentation. The fact is that it is shipped with the OS in `C:\Windows\system32\vcruntime140.dll` and the name of this file haven't changed for years. But still, it's probably not guaranteed so it might be necessary to use _Redistributables_ anyway.

MSVC specific DLLs still need to be guaranteed by your software using Redistributables. There is a full list of MSVC-related CRT libraries that might be required to ship with your software: [Determine which DLLs to redistribute](https://learn.microsoft.com/en-us/cpp/windows/determining-which-dlls-to-redistribute).

If you link your program from the command line without a compiler option that specifies a C runtime library, the linker will use the statically linked CRT libraries. Generally speaking, Microsoft recommends to use static linking for executables. [Overview of CRT linking options](https://learn.microsoft.com/en-us/cpp/c-runtime-library/crt-library-features?view=msvc-170).

Here's what executables look like with different linking options:

`cl.exe test.c` (static linking by default):

- IAT:
  - `kernel32.dll`
- Size: 83kB
- UCRT is statically linked
- Only `kernel32.dll` is loaded at run-time

`cl.exe test.c /MD` (dynamic loading):

- IAT:
  - `kernel32.dll`
  - `vcruntime140.dll`
  - UCRT proxy DLLs to `ucrtbase.dll`
- Size: 9kB
- UCRT is loaded dynamically
- `ucrtbase.dll` and `vcruntime140.dll` is loaded at run-time

## 5. Compiler (implementation specifics)

### 5.1. Compiler-specific keywords

Here's the full list of keywords specified by C23 Standard:

```text
alignas     for             true
alignof     goto            typedef
auto        if              typeof
bool        inline          typeof_unqual
break       int             union
case        long            unsigned
char        nullptr         void
const       register        volatile
constexpr   restrict        while
continue    return          _Atomic
default     short           _BitInt
do          signed          _Complex
double      sizeof          _Decimal128
else        static          _Decimal32
enum        static_assert   _Decimal64
extern      struct          _Generic
false       switch          _Imaginary
float       thread_local    _Noreturn
```

Some of the keywords have alternative spelling:

```text
alignas       ==  _Alignas
alignof       ==  _Alignof
bool          ==  _Bool
static_assert == _Static_assert
thread_local  == _Thread_local
```

> **NOTE**: The C23 Standard introduced new built-in keywords that were previously associated by default rather with C++, such as: `true`, `false`, `constexpr`, `nullptr`, `typeof`.

All working C compilers must support the above keywords. **However, compilers can implement their own custom keywords which are not part of the C Standard.** Most often, these are keywords that allow you to control how the compiler will implement a particular thing in a machine code (e.g. calling convention or inline assembly).

- [Microsoft-specific keywords used in MSVC compiler](https://learn.microsoft.com/en-us/cpp/c-language/c-keywords#microsoft-specific-c-keywords) (e.g. `__asm`, `__fastcall`, `__cdecl`).
- GCC-specific keywords (e.g. `__attribute__`, `asm`, `__asm__`) - I could not find one consistent list of GCC keywords. They are mixed with _built-in functions_ which are something else (read below).

### 5.2. Compiler built-in functions (intrinsics)

Many compilers (e.g. MSVC and GCC) provide built-in versions of many of the functions in the C standard library. The implementations of the functions are written directly into the compiled object file, and the program calls the "local" built-in versions instead of the functions in the C library shared object file.

These built-in features are called _intrinsic_. They reduce function-call overhead (inline function variants) and allow other forms of optimization (e.g. better CPU instructions usage), but may cause confusion when debugging and doing weird low-level things. The CPU instruction set has grown significantly over the past few decades and what used to require libc functions in the past, today can be done with one CPU instruction.

- [GCC built-in functions](https://gcc.gnu.org/onlinedocs/gcc-4.8.5/gcc/Other-Builtins.html#index-isblank-3194)
- [MSVC built-in functions](https://learn.microsoft.com/en-us/cpp/intrinsics/intrinsics-available-on-all-architectures)

### 5.3. Compiler-specific directives

The preprocessor is part of the C Standard. The standard specifies a set of mandatory directives (e.g. `#if`, `#include`, `#pragma`, `#embed`) and macros (e.g. `__LINE__`, `__FILE__`, `__DATE__`).

The `#pragma` directive is a compiler-specific preprocessor directive, which compiler vendors may use for their own purposes (this is how it is defined in the C standard). List of common pragmas:

- [MSVC pragmas](https://learn.microsoft.com/en-us/cpp/preprocessor/pragma-directives-and-the-pragma-keyword?view=msvc-170)
- [GCC pragmas](https://gcc.gnu.org/onlinedocs/cpp/Index-of-Directives.html)

However, compilers can also implement other directives that are completely their own custom things (see: GCC `#include_next` or `#ident`). However, this approach is not very common.

Some directives, although not part of the standard, have become so popular that all serious compilers support them. An example would be `#pragma once`.

### 5.4. Undefined behavior

_Undefined behavior_ is an action whose effects are not defined by the ISO C standard. Ideally, these types of actions should not be present in the code, and certainly no logic should be based on them. They are considered to be a programming mistake. Since their effect is not defined by the standard, it is mostly the responsibility of compilers and the effect can vary between vendors. **C23 standard defines 221 undefined behaviors.**

Examples of undefined behaviors (according to C23 standard):

- The value of the second operand of the `/` or `%` operator is zero (division by zero);
- The value of a pointer to an object whose lifetime has ended is used (use-after-free);
- Conversion to or from an integer type produces a value outside the range that can be represented (integer overflow);
- The value of the buffer allocated by the _malloc_ function is used;
- The `mode` argument in a call to the `fopen` function does not exactly match one of the specified strings;
- Copying or changing the bytes of or copying from a non-null pointer into a
`nullptr_t` object and then reading that object (null pointer dereference);
- When program execution reaches an `unreachable()` macro invocation;
- The character sequence in an `#include` preprocessing directive does not start with a letter;
- A function declared with a `_Noreturn` function specifier returns to its caller.

What might happen? Well, the C specification generally puts it this way: _Possible undefined behavior ranges from ignoring the situation completely with unpredictable results, to behaving during translation or program execution in a documented manner characteristic of the environment, to terminating a translation or execution_. Not very helpful, huh?

### 5.5. Unspecified behavior

_Unspecified behavior_ is an action for which the C standard does not impose implementation requirements. This is a normal part of the language, these are not programmer errors. However, basing a program's operation on this type of behavior can destroy portability, since they are defined by the implementation, not by the standard. **C23 standard defines 63 unspecified behaviors.**

Examples of unspecified behaviors (according to C23 standard):

- The manner and timing of static initialization;
- The termination status returned to the hosted environment if the return type of `main` is not compatible with `int`;
- The layout of storage for function parameters;
- The order in which the function designator, arguments, and subexpressions within the arguments are evaluated in a function call;
- The order and contiguity of storage allocated by successive calls to the `calloc`, `malloc`, `realloc`, and `aligned_alloc` functions;
- The order of two elements that compare as equal in an array sorted by the `qsort` function.

Probably the most representative example of an unspecified behavior is the order in which the arguments to a function are evaluated. Also, it is worth remembering that the arrangement of function parameters in memory is not defined by the C standard.

### 5.6. Implementation-defined behavior

_Implementation-defined behavior_: a conforming implementation of the C standard is required to document its choice of behavior in each of the 13 areas listed in this specification. These are things that must be explicitly defined by each implementation. **C23 standard defines 131 implementation-defined behaviors**.

Examples of implementation-defined behaviors (according to C23 standard):

- An alternative manner in which the main function may be defined;
- The manner of execution of the string by the system function;
- The number of bits in a byte;
- The accuracy of the floating-point operations and of the library functions in `<math.h>` and `<complex.h>` that return floating-point results;
- The result of converting a pointer to an integer or vice versa;
- The extent to which suggestions made by using the `register` storage-class specifier are effective;
- The extent to which suggestions made by using the `inline` function specifier are effective;
- The format of the diagnostic printed by the `assert` macro;
- The null pointer constant to which the macro `NULL` expands;
- Whether the `calloc`, `malloc`, `realloc`, and `aligned_alloc` functions return a null pointer or a pointer to an allocated object when the size requested is zero;
- The value of the result of the `sizeof` and `alignof` operators.

One of the most interesting things for me was that the number of bits in a byte is not specified by the C standard. Nowadays, we often forget that a byte formally is not 8 bits, but the smallest addressable unit of memory. Over the decades, byte sizes have varied.

It's also worth noting that the `register` and `inline` keywords don't force the implementation to do anything actual. The compiler can decide for itself what to do with this command.

## 6. Conclusion

In the above article, I tried to introduce the fascinating world of the C standard that virtually no one reads and its actual implementations that no one understand. While writing this article, I had to repeatedly check what the C specification actually says, because even compiler documentation is often not precise enough. Now you know what to watch out for!

\~ Print3M
