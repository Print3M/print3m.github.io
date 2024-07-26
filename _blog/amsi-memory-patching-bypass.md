---
title: PowerShell AMSI bypass by Memory Patching
createdAt: "2024-05-03"
---

**DISCLAIMER**: This is not a new AMSI bypass technique. As far as I know it was discovered by [Rasta Mouse in 2021](https://rastamouse.me/memory-patching-amsi-bypass/).

**TLDR**: [Repository with final PowerShell script](https://github.com/Print3M/amsi-memory-patching?tab=readme-ov-file)

## What is AMSI?

AMSI stands for _Antimalware Scan Interface_. It's an antivirus-agnostic security feature introduced in the Windows OS in 2015. Basically, many different security products can listen on scan requests triggered by AMSI functions (so-called _AMSI-aware antiviruses_).

The useful AMSI functions are exposed to the binaries using a built-in `amsi.dll` library (located in `C:\Windows\System32\amsi.dll` path). Any program can load this `amsi.dll` module and use, for example, the `AmsiScanString()` function, giving it a piece of code to be scanned as a parameter. According to the documentation, AMSI supports, among other things the scanning of:

- PowerShell scripts
- JScript
- VBScript

Code fragments written in the above languages can be scanned by some AMSI-aware antivirus software (Windows Defender by default) via AMSI functions. A result will be returned whether the given script is safe or not. Based on the returned result, the binary can decide whether to execute the given script or not.

## PowerShell with AMSI

In this blog post, I will focus on PowerShell. So how does it work with PowerShell? Well, `PowerShell.exe` uses `AmsiScanString()` or `AmsiScanBuffer()` (a lower level function) on any PS script or line given to it before the actual execution. If the response from AMSI indicated _a malicious piece of code_ the script is blocked (no execution) and the red text is displayed.

![PowerShell Screenshot - AMSI triggered, script is blocked](/imgs/amsi-memory-patching-bypass/16.png)

**Very important**: All PS scripts (`*.ps1` files) and PS commands are executed in the current `PowerShell.exe` process. Basically, one console window = one `PowerShell.exe` process = one `amsi.dll` loaded in memory. No child process is created for each script and each command separately. This means that if we deactivate AMSI for the current `PowerShell.exe` process, we can execute all subsequent PowerShell scripts and not worry about anything.

## The Idea of Memory Patching

All code executed by PowerShell.exe is located in its virtual address space. All loaded external modules in the form of DLLs are also located in memory (we'll see that later). Memory patching is the process of modifying data or program code directly in its virtual memory. Unlike binary patching which is the modification of an executable file, before it is loaded into memory.

Using memory patching, we can overwrite the machine code of functions executed by the program so that, for example, they always return the value we want. And that's the point. We want to override the functions exported by `amsi.dll` so that they always return a response that the scanned code is safe. This ensures that `PowerShell.exe` will never know that the code is malicious and will not block its execution. Let's do it.

## Reverse Engineering of amsi.dll

`amsi.dll` is always present in the `PowerShell.exe` process. This module is always loaded automatically at the start of the process. We can see that `amsi.dll` is loaded into memory using `Process Hacker` tool.

![Process Hacker Screenshot - location of amsi.dll in memory](/imgs/amsi-memory-patching-bypass/1.png)

DLLs are loaded at the high addresses of the memory address space. The `amsi.dll` is loaded at address `0x7ffc0e8b0000`. This is how the memory map looks like: 5 regions different regions. The most interesting one is the `RX` (read-execute) region where the code of AMSI functions is actually placed.

![Process Hacker Screenshot - PowerShell.exe process memory map](/imgs/amsi-memory-patching-bypass/3.png)

`amsi.dll` is located (as every other built-in DLL) in `C:\Windows\System32\amsi.dll` path. Let's load the module to Ghidra and do a little bit of reverse engineering.

![File Explorer Screenshot - location of amsi.dll](/imgs/amsi-memory-patching-bypass/4.png)

We can set the base address for memory layout to exactly the same value as it's set in `PowerShell.exe` process. Just for fun.

![Ghidra Screenshot - amsi.dll loaded](/imgs/amsi-memory-patching-bypass/5.png)

This is how the decompiled `AmsiScanString()` function looks like with a little bit of rather terrible reverse engineering:

![Ghidra Screenshot - AmsiScanString function decompiled](/imgs/amsi-memory-patching-bypass/6.png)

And the Assembly listing of `AmsiScanString()` function:

![Ghidra Screenshot - AmsiScanString function Assembly listing](/imgs/amsi-memory-patching-bypass/7.png)

From this Assembly listing we can figure out that this function simply returns exactly what actually `AmsiScanBuffer()` returns. Thanks to reverse engineering, we know that it's probably better option to patch `AmsiScanBuffer()` function directly. There might possibility that some `PowerShell.exe` features use that function instead of `AmsciScanString()`. Here's how the `AmsciScanBuffer()` function looks like:

![Ghidra Screenshot - AmsiScanBuffer function decompiled](/imgs/amsi-memory-patching-bypass/13.png)

## Memory patching of AMSI function

The `AmsiScanBuffer()` returns `AMSI_RESULT` number. This is the value that determines what is the result of scan. Here are the possible result values (from [Microsoft documentation](https://learn.microsoft.com/en-us/windows/win32/api/amsi/ne-amsi-amsi_result)):

![AMSI_RESULT Enum](/imgs/amsi-memory-patching-bypass/8.png)

We can inject our patch at the very beginning of the function. Essentially, we need to write `0` to EAX register and return from the function. EAX register contains the returned value. Two instructions, 3 bytes in total. According to the Microsoft documentation: _The antimalware provider may return a result between 1 and 32767, inclusive, as an estimated risk level. The larger the result, the riskier it is to continue with the content_. I assume that returned `0` means `AMSI_RESULT_CLEAN` so this is the value we want to return in order to disable AMSI detection capabilities.

So here's how the Assembly PoC can look like:

```nasm
XOR EAX, EAX
RET
```

And the corresponding array of opcodes:

```powershell
{ 0x31, 0xC0, 0xC3 } 
```

Yeah, that's it.

I've implemented a very basic Proof of Concept script. Of course we need to write it in PowerShell to execute it in the same `PowerShell.exe` process we want to patch. This script is actually a PowerShell code that executes C# methods imported from built-in `kernel32.dll` written in C. I also use built-in .NET method [Marshal.Copy](https://learn.microsoft.com/pl-pl/dotnet/api/system.runtime.interopservices.marshal.copy?view=net-8.0) to write bytes into memory. The following WinAPI functions are used:

- `LoadLibrary` - to get the address of `amsi.dll`.
- `GetProcAddress` - to get the address of `AmsiScanBuffer` function.
- `VirtualProtect` - to change permissions to the memory region of AMSI functions code (allow write operation).

Unfortunately our PoC script gets detected by AMSI (the AMSI we want to bypass hehe).

![AMSI Bypass PowerShell Script (Proof of Concept) detected](/imgs/amsi-memory-patching-bypass/10.png)

We can use [AmsiTrigger](https://github.com/RythmStick/AMSITrigger) tool to gather information which part of the bypass script is actually detected by AMSI. **NOTE**: This script often gives strange and not-quite-correct results, and it's a good idea to run it again after each change until everything goes through.

![AmsiTrigger script executed](/imgs/amsi-memory-patching-bypass/11.png)

Now we can obfuscate these indicators using [PowerShell Obfuscation Bible](https://github.com/t3l3machus/PowerShell-Obfuscation-Bible). Of course there is tons of automatic obfuscators out there but I want to do this manually for fun. After some **_very sophisticated obfuscation_** the final PoC looks like this:

![Obfuscated AMSI Bypass PowerShell Script (PoC)](/imgs/amsi-memory-patching-bypass/12.png)

What I did was basically:

- const strings reversing
- suspicious variables renaming

And finally. Ladies and gentlemen, we got him. In the left window AMSI is active and it detects `AMSI Test Sample` (this is the command that works like like EICAR file for AV so basically just testing AMSI presence). In the right window AMSI is bypassed using our PoC script – `AMSI Test Sample` is interpreted as a standard PowerShell command (which obviously doesn't exist) and it doesn't trigger any detection error. IT WORKS!

![Comparision of two PowerShell windows - AMSI disabled and enabled](/imgs/amsi-memory-patching-bypass/14.png)

Just to be 100% that our bypass works as inteded let's try to import very malicious [Invoke-Mimikatz.ps1](https://github.com/samratashok/nishang/blob/master/Gather/Invoke-Mimikatz.ps1) and dump some credentials. Normally, this particular script without any obfuscation is 100% always detected.

![Proof that AMSI is disabled successfully - Invoke-Mimikatz script execution](/imgs/amsi-memory-patching-bypass/15.png)

No errors whatsoever. Credentials dumped. AMSI bypassed successfully. Mission completed.

\~ Print3M

## References

- [RastaMouse, _Memory Patching AMSI Bypass_](https://rastamouse.me/memory-patching-amsi-bypass/)
- [Rx0red, _From AMSI to Reflection 0x0](https://rxored.github.io/post/csharploader/bypassing-amsi-with-csharp/)
- [Sam Rothlisberger, _AMSI Bypass Memory Patch Technique in 2024_](https://medium.com/@sam.rothlisberger/amsi-bypass-memory-patch-technique-in-2024-f5560022752b)
