# WerWolf: Dumping LSASS Without Touching LSASS - Weaponizing Silent Process Exit and WER for Credential Theft

## TL;DR

Every EDR on the market monitors LSASS. They hook `OpenProcess`, flag `MiniDumpWriteDump`, alert on `PssCaptureSnapshot`, and panic when someone reads LSASS memory. But deep inside `ntdll.dll` lives an undocumented function that nobody in the offensive security community has weaponized: **`RtlReportSilentProcessExit`**.

This function is part of the Windows **Silent Process Exit** monitoring infrastructure. When called, it signals the Windows Error Reporting service to create a full dump of a target process - using WER's own trusted, EDR-whitelisted handle. We never open LSASS. We never read its memory. We never call `MiniDumpWriteDump`. We just ask WER to do what it was designed to do.

This article walks through how I discovered this technique, the research process behind it, and the custom Python COFF loader I built to execute it entirely in-memory.

---

## How I Found It: The Research Story

I'll be honest - I didn't start out looking for `RtlReportSilentProcessExit`. Nobody does. You don't Google "undocumented NTDLL functions that dump LSASS" and get a clean answer. The discovery came from weeks of frustration and a very specific question I couldn't let go of.

### The Starting Point

I was deep into LSASS credential dumping research. I had already built several variants - the classic `PssCaptureSnapshot` + `MiniDumpWriteDump` approach, handle duplication via `NtQuerySystemInformation`, even a manual minidump writer that constructs the file format from scratch without ever loading `dbghelp.dll`. Each one was an incremental improvement, each one evaded *some* EDRs, and each one eventually got caught.

The pattern was always the same: no matter how creative the approach, at some point **my process** had to read LSASS memory. Whether through a direct handle, a cloned snapshot, or a stolen handle from a donor process - eventually, there was a `NtReadVirtualMemory` call with my PID as the source. And that's where EDRs were converging their detection.

I kept asking myself one question: **Is there a way to make Windows dump LSASS for me, without my process ever reading its memory?**

### Going Down the WER Rabbit Hole

I started looking at Windows services that legitimately interact with process memory. The obvious candidate was **Windows Error Reporting (WER)**. WerFault.exe is a signed Microsoft binary that reads process memory every time an application crashes. EDRs can't block it without breaking Windows itself.

My first approach was the `WerReportCreate` / `WerReportAddDump` API path. It works - you can create a WER report and attach a process dump to it. But there's a catch: `WerReportAddDump` still requires your process to hold a handle to the target with `PROCESS_VM_READ`. You're delegating the *writing* to WER, but the handle requirement means EDRs can still flag the handle creation. It was better, but not the breakthrough I was looking for.

### The Breakthrough: Reading NTDLL Exports

One night I was going through NTDLL exports in IDA, not looking for anything specific - just scrolling through the Rtl* function family, reading function names, seeing if anything jumped out. I had been doing this for a while, building a mental catalog of undocumented functions and what they might do.

And then I saw it: **`RtlReportSilentProcessExit`**.

The name immediately caught my attention. "Silent Process Exit" - I vaguely remembered reading about this feature in a Windows Internals chapter. It's a diagnostic mechanism: when a process terminates silently (without a visible crash dialog), Windows can be configured to automatically collect a dump. The configuration lives in the registry under `Image File Execution Options` and `SilentProcessExit`.

I started reverse-engineering the function. The disassembly revealed something beautiful: `RtlReportSilentProcessExit` doesn't dump the process itself. It sends an **ALPC message** to the WER service, passing along the process handle. The WER service then spawns WerFault.exe, which opens its **own** handle to the target process and creates the dump.

My process doesn't read LSASS memory. WerFault does. And WerFault is trusted.

### The "Wait, Really?" Moment

I immediately went to check what handle permissions `RtlReportSilentProcessExit` actually needs. I was expecting it to require `PROCESS_VM_READ` or `PROCESS_QUERY_INFORMATION` at minimum. But when I tested it - it worked with just **`PROCESS_QUERY_LIMITED_INFORMATION`**. That's the weakest possible process handle. Dozens of legitimate processes hold this level of access to LSASS at any given time.

I searched everywhere - GitHub, conference talks, blog posts, Twitter, exploit-db, the Cobalt Strike community. Nothing. Nobody had weaponized this function for credential dumping. It had been sitting in `ntdll.dll` since Windows 7, exported by name, callable from userland, and completely overlooked.

### From Discovery to Weapon

Once I confirmed the core technique worked, I built it into a BOF (Beacon Object File) so it could be loaded and executed entirely in-memory. No executable on disk. The full chain became:

1. Write registry keys to enable Silent Process Exit monitoring for LSASS
2. Open LSASS with `PROCESS_QUERY_LIMITED_INFORMATION` (barely a handle)
3. Call `RtlReportSilentProcessExit` - one function call
4. WER does the rest - WerFault reads LSASS, writes the dump
5. Clean up the registry keys
6. Parse the dump offline with pypykatz

I tested it against multiple enterprise EDR products. None of them flagged it.

---

## The Problem with Traditional LSASS Dumping

If you've done any red teaming in the last five years, you know the drill. You get SYSTEM, you try to dump LSASS, and your agent dies. Here's why:

### What EDRs Watch For

| Technique | Detection |
|---|---|
| `OpenProcess(lsass.exe)` | Kernel callback on process handle creation |
| `MiniDumpWriteDump()` | Hook on dbghelp.dll export |
| `PssCaptureSnapshot()` | Hook on kernel32 snapshot API |
| `NtReadVirtualMemory(lsass)` | Syscall-level monitoring on LSASS PID |
| Procdump, comsvcs.dll | Signature-based + behavioral |

The security industry has hardened every path from your process to LSASS. Direct access is a dead end.

So the question becomes: **what if we never touch LSASS at all?**

---

## The Undocumented Goldmine: `RtlReportSilentProcessExit`

Deep in `ntdll.dll`, there's an undocumented function:

```c
NTSTATUS RtlReportSilentProcessExit(HANDLE ProcessHandle, NTSTATUS ExitStatus);
```

This function is part of Windows' **Silent Process Exit** monitoring, a feature introduced in Windows 7. Here's what Microsoft designed it for: when a process exits "silently" (terminates without user-visible indicators), the OS can be configured to automatically collect a dump for post-mortem debugging.

The mechanism works through the **Windows Error Reporting (WER) service**. When `RtlReportSilentProcessExit` is called:

1. NTDLL sends a message to the **WER service** via an ALPC port
2. The WER service (`WerSvc`) spawns **`WerFault.exe`**
3. WerFault opens a handle to the target process - **using its own privileges**
4. WerFault creates a full memory dump of the target process
5. The dump is written to the configured output directory

### Why This Is Game-Changing

The critical insight: **WerFault.exe is a signed Microsoft binary that EDRs explicitly whitelist**. Security products *cannot* block WerFault from reading process memory without breaking Windows crash reporting. And the dump operation happens inside WerFault's process context, not ours.

Previous WER-based research has focused on `WerReportCreate`/`WerReportAddDump` - those are user-mode APIs that still require *your* process to hold a readable handle to the target. `RtlReportSilentProcessExit` is fundamentally different: it delegates the *entire* operation to the WER service. Your process doesn't need a readable handle to LSASS memory. It just sends a notification.

**Nobody in the public offensive security space has weaponized `RtlReportSilentProcessExit` for credential dumping before.** The function exists in every version of Windows since 7, hiding in plain sight.

---

## The Full Attack Chain

### Step 0: Enable Silent Process Exit Monitoring

Silent Process Exit monitoring is disabled by default. To enable it for LSASS, we write two registry keys:

```
HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\lsass.exe
    GlobalFlag = 0x200  (FLG_MONITOR_SILENT_PROCESS_EXIT)

HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SilentProcessExit\lsass.exe
    ReportingMode  = 0x2  (LOCAL_DUMP)
    LocalDumpFolder = C:\Windows\Temp
    DumpType = 0x2  (MiniDumpWithFullMemory)
```

These are standard Windows diagnostic settings. They configure what happens when the Silent Process Exit mechanism triggers - in this case, "write a full memory dump to `C:\Windows\Temp`."

### Step 1: No EXE, No Problem - In-Memory BOF Loading

Before the WER technique fires, we need to solve another problem: getting our code onto the target without dropping an executable.

I built a custom **COFF (Common Object File Format) loader in Python**. COFF is the intermediate format compilers produce before linking - the `.o` file from `gcc -c`. The loader takes these raw object files and does what the Windows PE loader does, but entirely in userspace:

```
┌──────────────┐     ┌──────────────┐     ┌──────────────┐
│   BOF.c      │ --> │  Compiler    │ --> │   BOF.o      │
│   (source)   │     │  (MinGW)     │     │   (COFF)     │
└──────────────┘     └──────────────┘     └──────┬───────┘
                                                  │
                                                  ▼
                                        ┌──────────────────┐
                                        │  Python COFF     │
                                        │  Loader          │
                                        │                  │
                                        │  1. VirtualAlloc │
                                        │  2. Map sections │
                                        │  3. Resolve DLLs │
                                        │  4. Relocate     │
                                        │  5. Execute go() │
                                        └──────────────────┘
```

The loader handles section mapping, AMD64 relocations (REL32, ADDR64, ADDR32NB, SECREL), DLL import resolution via the `MODULE$FUNCTION` naming convention, and provides a `BeaconOutput` callback - the same BOF standard Cobalt Strike popularized, but as a standalone Python tool.

### Step 2: Privilege Escalation - The Quiet Way

We need SeDebugPrivilege. Most tools use the noisy three-call chain (`OpenProcessToken` -> `LookupPrivilegeValue` -> `AdjustTokenPrivileges`). We use a single undocumented NTDLL call:

```c
NTDLL$RtlAdjustPrivilege(SE_DEBUG_PRIVILEGE, TRUE, FALSE, &wasEnabled);
```

One call, one syscall, minimal EDR telemetry.

### Step 3: Find LSASS

Standard process enumeration via `CreateToolhelp32Snapshot` to locate `lsass.exe` PID. Nothing fancy here - this is the least detectable part.

### Step 4: Configure Silent Process Exit (Registry)

```c
// Enable FLG_MONITOR_SILENT_PROCESS_EXIT for lsass.exe
ADVAPI32$RegSetValueExA(hKey,
    "GlobalFlag", 0, REG_DWORD, &flagValue, sizeof(DWORD));

// Configure: full memory dump to C:\Windows\Temp
ADVAPI32$RegSetValueExA(hSilentKey,
    "ReportingMode", 0, REG_DWORD, &localDump, sizeof(DWORD));
ADVAPI32$RegSetValueExA(hSilentKey,
    "DumpType", 0, REG_DWORD, &fullMemory, sizeof(DWORD));
ADVAPI32$RegSetValueExA(hSilentKey,
    "LocalDumpFolder", 0, REG_SZ, dumpPath, ...);
```

We're writing to `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options` and `SilentProcessExit` - legitimate Windows diagnostic configuration keys.

### Step 5: The Kill Shot - `RtlReportSilentProcessExit`

```c
// Open LSASS with minimal permissions (no VM_READ needed!)
HANDLE hLsass = NtOpenProcess(lsassPid, PROCESS_QUERY_LIMITED_INFORMATION, ...);

// Trigger the silent exit report - WER does the rest
NTDLL$RtlReportSilentProcessExit(hLsass, 0);
```

That's it. That's the entire dump trigger.

We open LSASS with **`PROCESS_QUERY_LIMITED_INFORMATION`** - the weakest possible process handle. We don't need `VM_READ`. We don't need `QUERY_INFORMATION`. We just need enough of a handle to identify the process to the WER service.

When `RtlReportSilentProcessExit` executes:

1. NTDLL sends an ALPC message to the WER service
2. WER spawns `WerFault.exe` with the target PID
3. **WerFault opens its OWN handle** to LSASS with full read access
4. WerFault reads LSASS memory and writes a complete minidump
5. The dump lands in `C:\Windows\Temp` (or wherever we configured)

**Our process never reads a single byte from LSASS.**

### Step 6: Cleanup and Parse

```c
// Clean up the registry breadcrumbs
ADVAPI32$RegDeleteKeyA(hIFEO, "lsass.exe\\SilentProcessExit");
ADVAPI32$RegDeleteValueA(hKey, "GlobalFlag");
```

Then parse the dump offline:

```bash
pypykatz lsa minidump C:\Windows\Temp\lsass.exe_*.dmp
```

---

## Why This Evades Modern EDR

Let's map this against every major detection strategy:

### 1. Process Handle Monitoring
EDRs flag when a process opens a handle to LSASS with `PROCESS_VM_READ`. **We only request `PROCESS_QUERY_LIMITED_INFORMATION`** - the least suspicious handle type. Dozens of legitimate processes request this level of access to LSASS constantly.

### 2. API Hooking on dbghelp.dll
`MiniDumpWriteDump` is one of the most hooked APIs in endpoint security. **We never load dbghelp.dll.** WerFault uses its own internal dumping mechanism.

### 3. Direct Syscall Monitoring
Some EDRs monitor `NtReadVirtualMemory` syscalls targeting the LSASS PID. **All memory reads come from WerFault.exe** - a signed Microsoft binary with legitimate reasons to read LSASS.

### 4. Call Stack Analysis
Advanced EDRs check the call stack when LSASS memory is read. If the read originates from an unexpected module, it's flagged. Here, the call stack is: `WerFault.exe -> wer.dll -> ntdll.dll -> NtReadVirtualMemory`. **A perfectly legitimate, signed call chain.**

### 5. Behavioral Analytics
EDR behavioral rules look for patterns like:
```
Process A opens LSASS -> Process A reads LSASS -> Process A writes a large file
```
Our pattern is:
```
Process A writes registry keys -> Process A calls RtlReportSilentProcessExit
-> [context switch] -> WerFault reads LSASS -> WerFault writes dump file
```
**The behavioral chain is broken across process boundaries.** The sensitive operations (reading LSASS, writing the dump) happen in WerFault's context.

### 6. Known Tool Signatures
No signature exists for this technique because **it hasn't been publicly weaponized before**. The function call is a legitimate Windows API, the registry keys are legitimate diagnostic settings, and the dump is created by a legitimate Windows service.

---

## The COFF Loader Deep Dive

For the technically curious, here's how the in-memory loader works:

### Memory Layout

```
VirtualAlloc'd Block (one contiguous RWX region):
+-------------------------+  base
|  .text section          |  Machine code (4KB aligned)
+-------------------------+
|  .data section          |  Global variables
+-------------------------+
|  .rdata section         |  String constants
+-------------------------+
|  Import Function Table  |  8-byte pointer slots
|  [0] -> kernel32!Func1  |
|  [1] -> ntdll!Func2     |
|  [2] -> BeaconOutput cb |
+-------------------------+
|  Internal Stubs         |  ___chkstk_ms -> RET
+-------------------------+
```

Everything goes in one block because AMD64 `CALL` instructions use 32-bit signed displacements (REL32 relocations). Scattered allocations can exceed the +/- 2GB range.

### The MODULE$FUNCTION Convention

```c
// BOF declaration
DECLSPEC_IMPORT NTSTATUS NTAPI NTDLL$RtlReportSilentProcessExit(HANDLE, NTSTATUS);
```

The compiler generates an indirect call through `__imp_NTDLL$RtlReportSilentProcessExit`. The loader:

1. Strips `__imp_` -> `NTDLL$RtlReportSilentProcessExit`
2. Splits on `$` -> module=`NTDLL`, function=`RtlReportSilentProcessExit`
3. `LoadLibraryA("NTDLL.dll")` -> handle
4. `GetProcAddress(handle, "RtlReportSilentProcessExit")` -> address
5. Writes address into an 8-byte import table slot

The BOF code does `call qword ptr [slot]` - identical to normal PE import mechanics.

---

## Detection Guidance (For the Blue Team)

Since the goal of publishing this research is to improve defensive capabilities, here's how to detect this technique:

### Registry Monitoring (Highest Signal)
1. **Watch `Image File Execution Options\lsass.exe`** - the `GlobalFlag` value being set to `0x200` (`FLG_MONITOR_SILENT_PROCESS_EXIT`) is a strong indicator
2. **Watch `SilentProcessExit\lsass.exe`** - this key being created at all is suspicious; legitimate use for LSASS is extremely rare

### Process Monitoring
3. **Correlate `WerFault.exe` spawns with LSASS** - WerFault launching with LSASS as the target process, when LSASS hasn't actually crashed, is anomalous
4. **Monitor `RtlReportSilentProcessExit` calls** - ETW tracing on this function, especially targeting LSASS, is a high-fidelity signal

### File System
5. **Watch WER output directories** - unexpected `.dmp` files targeting LSASS in `C:\Windows\Temp`, `%LOCALAPPDATA%\CrashDumps`, or configured `LocalDumpFolder` paths

### COFF Loader Artifacts
6. **`VirtualAlloc` + `PAGE_EXECUTE_READWRITE`** from Python or scripting engines, followed by `LoadLibrary`/`GetProcAddress` patterns

---

## Usage

```bash
# Just run it (requires admin on Windows)
python main.py

# Verbose logging (see full COFF parsing + loader internals)
python main.py -v
```

That's it. WerWolf automatically loads the BOF and executes. No arguments needed.

---

## MITRE ATT&CK Mapping

| Technique | ID | Usage |
|---|---|---|
| OS Credential Dumping: LSASS Memory | T1003.001 | Extracts credentials from LSASS via WER dump |
| Modify Registry | T1112 | Enables Silent Process Exit monitoring for LSASS |
| Signed Binary Proxy Execution | T1218 | WerFault.exe performs the memory read and dump |
| Abuse Elevation Control Mechanism | T1548 | Leverages WER service's trusted privileges |
| Process Injection | T1055 | In-memory COFF/BOF loading - no disk artifacts |

---

## Conclusion

The security industry has spent years building increasingly sophisticated detections around direct LSASS access. But `RtlReportSilentProcessExit` represents a fundamental blind spot: it delegates the entire dump operation to the Windows Error Reporting service - a trusted, signed, EDR-whitelisted component that has *legitimate reasons* to read any process's memory.

By combining this undocumented NTDLL function with in-memory COFF loading, we achieve a credential dumping technique that:

- **Never opens a readable handle to LSASS** - only `PROCESS_QUERY_LIMITED_INFORMATION`
- **Never calls `MiniDumpWriteDump`** - WER uses its own internal mechanism
- **Never reads LSASS memory directly** - WerFault does it under its own context
- **Never drops an executable to disk** - the BOF runs in-memory via COFF loading
- **Breaks the behavioral detection chain** - sensitive operations happen in WerFault's context, not ours

The function has been in `ntdll.dll` since Windows 7. It's been there for over 15 years, waiting.

---

*This tool is intended for authorized security testing, red team engagements, and security research only. Always obtain written authorization before testing on systems you don't own.*
