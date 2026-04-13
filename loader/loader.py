"""
COFF In-Memory Loader
======================
Loads parsed COFF objects into executable memory on Windows and runs them.

Loading Pipeline:
  1. Allocate a contiguous RWX memory block (VirtualAlloc)
  2. Map each section into the block with 4KB alignment
  3. Build a function-pointer table for external imports
  4. Resolve symbols: MODULE$FUNCTION -> LoadLibrary + GetProcAddress
  5. Apply relocations: patch code to point at resolved addresses
  6. Locate entry point ("go") and call it
"""

import ctypes
import struct
import logging
from typing import Dict, Optional

from .parser import (
    CoffParser, SectionHeader, Symbol, Relocation,
    IMAGE_SYM_UNDEFINED, IMAGE_SYM_CLASS_EXTERNAL,
    IMAGE_REL_AMD64_ABSOLUTE, IMAGE_REL_AMD64_ADDR64,
    IMAGE_REL_AMD64_ADDR32, IMAGE_REL_AMD64_ADDR32NB,
    IMAGE_REL_AMD64_REL32, IMAGE_REL_AMD64_REL32_1,
    IMAGE_REL_AMD64_REL32_2, IMAGE_REL_AMD64_REL32_3,
    IMAGE_REL_AMD64_REL32_4, IMAGE_REL_AMD64_REL32_5,
    IMAGE_REL_AMD64_SECTION, IMAGE_REL_AMD64_SECREL,
    IMAGE_SCN_CNT_CODE, IMAGE_SCN_CNT_UNINITIALIZED_DATA,
    RELOC_TYPE_NAMES,
)

logger = logging.getLogger(__name__)

# ── Windows Memory Constants ──
MEM_COMMIT             = 0x00001000
MEM_RESERVE            = 0x00002000
MEM_RELEASE            = 0x00008000
PAGE_EXECUTE_READWRITE = 0x40
PAGE_READWRITE         = 0x04
PAGE_EXECUTE_READ      = 0x20

SECTION_ALIGNMENT = 0x1000  # 4 KB


class CoffLoader:
    """
    Loads a COFF object file into memory and executes its entry point.

    The loader mimics what the Windows PE loader does, but for raw COFF objects:
      - Sections are mapped into executable memory
      - External symbols (DLL imports) are resolved via LoadLibrary/GetProcAddress
      - Internal beacon functions are provided as callbacks
      - Relocations patch the loaded code so addresses are correct
    """

    def __init__(self):
        # Windows API handles
        self.kernel32 = ctypes.windll.kernel32
        self._setup_winapi()

        # Memory tracking
        self._allocated_blocks = []      # [(address, size), ...]
        self._section_bases: Dict[int, int] = {}  # section_index -> base_address
        self._func_table_base = 0
        self._func_table_cursor = 0

        # Beacon API
        self._callbacks = []             # prevent garbage collection
        self.output_lines = []
        self._beacon_functions = {}
        self._setup_beacon_api()

    # ──────────────────────────────────────
    #  Windows API Setup
    # ──────────────────────────────────────

    def _setup_winapi(self):
        k32 = self.kernel32

        self._VirtualAlloc = k32.VirtualAlloc
        self._VirtualAlloc.restype = ctypes.c_void_p
        self._VirtualAlloc.argtypes = [
            ctypes.c_void_p, ctypes.c_size_t, ctypes.c_uint32, ctypes.c_uint32
        ]

        self._VirtualFree = k32.VirtualFree
        self._VirtualFree.restype = ctypes.c_bool
        self._VirtualFree.argtypes = [
            ctypes.c_void_p, ctypes.c_size_t, ctypes.c_uint32
        ]

        self._LoadLibraryA = k32.LoadLibraryA
        self._LoadLibraryA.restype = ctypes.c_void_p
        self._LoadLibraryA.argtypes = [ctypes.c_char_p]

        self._GetProcAddress = k32.GetProcAddress
        self._GetProcAddress.restype = ctypes.c_void_p
        self._GetProcAddress.argtypes = [ctypes.c_void_p, ctypes.c_char_p]

    # ──────────────────────────────────────
    #  Beacon API (internal functions for BOFs)
    # ──────────────────────────────────────

    def _setup_beacon_api(self):
        """
        Create native callback functions that BOFs can call.

        BOFs reference these as __imp_BeaconOutput etc.
        We allocate ctypes callbacks (function pointers callable from native code)
        and register them for symbol resolution.
        """

        # void BeaconOutput(int type, char* data, int len)
        BEACON_OUTPUT_T = ctypes.CFUNCTYPE(
            None, ctypes.c_int, ctypes.c_void_p, ctypes.c_int
        )

        def _beacon_output(callback_type, data_ptr, length):
            if data_ptr and length > 0:
                raw = ctypes.string_at(data_ptr, length)
                text = raw.decode("utf-8", errors="replace")
                self.output_lines.append(text)
                print(text, end="")

        cb = BEACON_OUTPUT_T(_beacon_output)
        self._callbacks.append(cb)  # prevent GC
        addr = ctypes.cast(cb, ctypes.c_void_p).value

        self._beacon_functions["BeaconOutput"] = addr
        logger.debug(f"Beacon API: BeaconOutput @ 0x{addr:016X}")

        # Internal stubs (___chkstk_ms etc.) will be placed inside the
        # contiguous block during _map_sections to stay within REL32 range.
        self._internal_stubs = {}

    # ──────────────────────────────────────
    #  Public Interface
    # ──────────────────────────────────────

    def load_and_execute(
        self,
        coff_data: bytes,
        entry_name: str = "go",
        args: bytes = b"",
    ) -> str:
        """
        Full pipeline: parse -> load -> relocate -> execute.

        Returns the collected output from the BOF.
        """
        try:
            # 1. Parse
            parser = CoffParser(coff_data)
            parser.parse()
            parser.dump()

            # 2. Map sections into memory
            self._map_sections(parser)

            # 3. Resolve all symbols to addresses
            sym_addrs = self._resolve_symbols(parser)

            # 4. Apply relocations (patch the code)
            self._apply_relocations(parser, sym_addrs)

            # 5. Find entry point
            entry = self._find_entry(parser, sym_addrs, entry_name)
            if entry is None:
                raise RuntimeError(
                    f"Entry point '{entry_name}' not found in symbol table"
                )

            logger.info(f"Entry point '{entry_name}' at 0x{entry:016X}")
            print(f"[*] Jumping to entry point '{entry_name}' @ 0x{entry:016X}\n")

            # 6. Execute: void go(char* args, int alen)
            GO_FUNC = ctypes.CFUNCTYPE(None, ctypes.c_char_p, ctypes.c_int)
            go = GO_FUNC(entry)

            self.output_lines.clear()
            go(args if args else None, len(args))

            return "".join(self.output_lines)

        except Exception:
            logger.exception("COFF load/execute failed")
            raise
        finally:
            self._cleanup()

    # ──────────────────────────────────────
    #  Step 2: Map Sections
    # ──────────────────────────────────────

    def _map_sections(self, parser: CoffParser):
        """
        Allocate one contiguous RWX block and lay out all sections + the
        function-pointer import table inside it.

        Why one block?  All sections and the import table must be within
        +-2 GB of each other so that REL32 relocations (32-bit signed
        displacement) don't overflow.
        """
        # Calculate total size
        total = 0
        offsets = []
        for section in parser.sections:
            aligned = self._align(section.effective_size)
            offsets.append(total)
            total += aligned

        # Reserve space for function-pointer slots (8 bytes each)
        extern_count = sum(
            1 for s in parser.symbols
            if s.is_undefined and s.is_external and s.name != "__aux__"
        )
        table_size = self._align((extern_count + 64) * 8)
        total += table_size

        # Reserve one page for internal stubs (___chkstk_ms, etc.)
        stub_page_size = SECTION_ALIGNMENT
        total += stub_page_size

        # Allocate
        base = self._VirtualAlloc(
            None, total, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE
        )
        if not base:
            raise MemoryError(f"VirtualAlloc failed for {total} bytes")

        self._allocated_blocks.append((base, total))
        ctypes.memset(base, 0, total)

        logger.info(
            f"Allocated {total:,} bytes at 0x{base:016X} "
            f"(sections + import table)"
        )

        # Copy section data
        for i, section in enumerate(parser.sections):
            addr = base + offsets[i]
            self._section_bases[i] = addr

            if section.data:
                ctypes.memmove(addr, section.data, len(section.data))

            logger.info(
                f"  Mapped [{i}] '{section.name}' "
                f"({section.effective_size} bytes) -> 0x{addr:016X}"
            )

        # Function table after sections
        self._func_table_base = base + total - table_size - stub_page_size
        self._func_table_cursor = 0

        # Stub area at the very end (inside the same contiguous block)
        stub_base = base + total - stub_page_size
        # ___chkstk_ms: MinGW emits calls to this for functions with >4KB
        # stack frames.  It probes guard pages to commit stack memory.
        # Python's thread stack is already committed, so a plain RET is safe.
        ctypes.c_char.from_address(stub_base).value = b"\xc3"  # RET
        self._internal_stubs = {
            "___chkstk_ms": stub_base,
            "__chkstk_ms": stub_base,
        }
        logger.info(f"  Stub ___chkstk_ms -> 0x{stub_base:016X} (inside block)")

    # ──────────────────────────────────────
    #  Step 3: Resolve Symbols
    # ──────────────────────────────────────

    def _resolve_symbols(self, parser: CoffParser) -> Dict[int, int]:
        """
        Build a mapping:  symbol_index -> resolved virtual address.

        For defined symbols:  section_base + symbol.value
        For external symbols: resolve via DLL or beacon API, then create
                              an 8-byte pointer slot (for __imp_ indirection).
        """
        addresses: Dict[int, int] = {}
        dll_cache: Dict[str, int] = {}

        for i, sym in enumerate(parser.symbols):
            if sym.name == "__aux__":
                continue

            # ── Defined symbol (lives in a section) ──
            if sym.section_number > 0:
                sec_idx = sym.section_number - 1
                if sec_idx in self._section_bases:
                    addresses[i] = self._section_bases[sec_idx] + sym.value
                continue

            # ── Undefined external (needs resolution) ──
            if sym.section_number != IMAGE_SYM_UNDEFINED:
                continue
            if not sym.is_external:
                continue

            name = sym.name
            is_imp = name.startswith("__imp_")
            actual = name[6:] if is_imp else name

            # Try beacon internals first
            if actual in self._beacon_functions:
                func_addr = self._beacon_functions[actual]
                addresses[i] = (
                    self._write_ptr_slot(func_addr) if is_imp else func_addr
                )
                logger.info(f"  Resolved [beacon] {actual} -> 0x{func_addr:016X}")
                continue

            # MODULE$FUNCTION -> LoadLibrary(MODULE) + GetProcAddress(FUNCTION)
            if "$" in actual:
                mod_name, func_name = actual.split("$", 1)
                func_addr = self._resolve_dll_func(mod_name, func_name, dll_cache)
                addresses[i] = (
                    self._write_ptr_slot(func_addr) if is_imp else func_addr
                )
                logger.info(
                    f"  Resolved {mod_name}!{func_name} -> 0x{func_addr:016X}"
                )
                continue

            # Check internal stubs (___chkstk_ms, etc.)
            if actual in self._internal_stubs:
                stub_addr = self._internal_stubs[actual]
                addresses[i] = (
                    self._write_ptr_slot(stub_addr) if is_imp else stub_addr
                )
                logger.info(f"  Resolved [stub] {actual} -> 0x{stub_addr:016X}")
                continue

            # Unknown  - could be a CRT symbol or linker-generated
            logger.warning(f"  Unresolved symbol: '{name}' (index {i})")

        return addresses

    def _resolve_dll_func(
        self, module: str, function: str, cache: Dict[str, int]
    ) -> int:
        """Load a DLL and get a function address."""
        dll_name = module if module.lower().endswith(".dll") else module + ".dll"

        if dll_name not in cache:
            handle = self._LoadLibraryA(dll_name.encode("ascii"))
            if not handle:
                raise RuntimeError(f"LoadLibrary failed: {dll_name}")
            cache[dll_name] = handle
            logger.debug(f"  Loaded {dll_name} @ 0x{handle:016X}")

        handle = cache[dll_name]
        addr = self._GetProcAddress(handle, function.encode("ascii"))
        if not addr:
            raise RuntimeError(f"GetProcAddress failed: {dll_name}!{function}")
        return addr

    def _write_ptr_slot(self, func_addr: int) -> int:
        """
        Allocate an 8-byte slot in the import table and write the function
        pointer into it.  Returns the address of the slot itself.

        This is how __imp_ symbols work:
          code does:  call qword ptr [slot]
          slot holds: actual function address (64-bit)
        """
        slot = self._func_table_base + self._func_table_cursor
        ctypes.c_uint64.from_address(slot).value = func_addr
        self._func_table_cursor += 8
        return slot

    # ──────────────────────────────────────
    #  Step 4: Apply Relocations
    # ──────────────────────────────────────

    def _apply_relocations(self, parser: CoffParser, sym_addrs: Dict[int, int]):
        """
        Walk every relocation in every section and patch the loaded code.

        Each relocation says: "at offset X in this section, there's a
        reference to symbol Y that needs to be fixed up with type Z."
        """
        for sec_idx, section in enumerate(parser.sections):
            if sec_idx not in self._section_bases:
                continue

            sec_base = self._section_bases[sec_idx]

            for reloc in section.relocations:
                sym_idx = reloc.symbol_table_index
                if sym_idx not in sym_addrs:
                    sym = parser.symbols[sym_idx]
                    logger.warning(
                        f"  Skipping reloc -> unresolved '{sym.name}' "
                        f"(type={reloc.type_name})"
                    )
                    continue

                target = sym_addrs[sym_idx]
                patch_addr = sec_base + reloc.virtual_address

                self._patch(reloc.type_, patch_addr, target, sec_idx)

    def _patch(self, rtype: int, addr: int, target: int, sec_idx: int):
        """Apply a single relocation at `addr`, pointing to `target`."""

        if rtype == IMAGE_REL_AMD64_ABSOLUTE:
            return  # no-op padding

        # For reading/writing the patch site
        buf8 = (ctypes.c_char * 8).from_address(addr)

        if rtype == IMAGE_REL_AMD64_ADDR64:
            # 64-bit absolute address (+ addend already in place)
            existing = struct.unpack_from("<Q", buf8, 0)[0]
            struct.pack_into("<Q", buf8, 0, target + existing)

        elif rtype == IMAGE_REL_AMD64_ADDR32:
            existing = struct.unpack_from("<I", buf8, 0)[0]
            struct.pack_into("<I", buf8, 0, (target + existing) & 0xFFFFFFFF)

        elif rtype == IMAGE_REL_AMD64_ADDR32NB:
            # 32-bit relative to image base (used in .pdata/.xdata)
            existing = struct.unpack_from("<I", buf8, 0)[0]
            struct.pack_into("<I", buf8, 0, (target + existing) & 0xFFFFFFFF)

        elif rtype in (
            IMAGE_REL_AMD64_REL32,
            IMAGE_REL_AMD64_REL32_1,
            IMAGE_REL_AMD64_REL32_2,
            IMAGE_REL_AMD64_REL32_3,
            IMAGE_REL_AMD64_REL32_4,
            IMAGE_REL_AMD64_REL32_5,
        ):
            # 32-bit RIP-relative displacement
            # Formula: displacement = target - (patch_site + 4 + extra)
            # The _1.._5 variants account for instruction bytes after the disp
            extra = rtype - IMAGE_REL_AMD64_REL32
            existing = struct.unpack_from("<i", buf8, 0)[0]
            disp = (target - (addr + 4 + extra)) + existing

            # Verify 32-bit signed range
            if disp > 0x7FFFFFFF or disp < -0x80000000:
                raise OverflowError(
                    f"REL32 relocation overflow: displacement=0x{disp:X} "
                    f"(target=0x{target:X}, addr=0x{addr:X})"
                )

            struct.pack_into("<i", buf8, 0, disp & 0xFFFFFFFF)

        elif rtype == IMAGE_REL_AMD64_SECTION:
            # 16-bit section index (1-based)
            struct.pack_into("<H", buf8, 0, sec_idx + 1)

        elif rtype == IMAGE_REL_AMD64_SECREL:
            # 32-bit offset relative to section start
            sec_base = self._section_bases.get(sec_idx, 0)
            existing = struct.unpack_from("<I", buf8, 0)[0]
            struct.pack_into("<I", buf8, 0, (target - sec_base + existing) & 0xFFFFFFFF)

        else:
            logger.warning(f"  Unhandled relocation type: 0x{rtype:04X}")

    # ──────────────────────────────────────
    #  Step 5: Find Entry Point
    # ──────────────────────────────────────

    def _find_entry(
        self, parser: CoffParser, sym_addrs: Dict[int, int], name: str
    ) -> Optional[int]:
        """Search for the entry point by name (tries both 'go' and '_go')."""
        candidates = [name, f"_{name}"]
        for i, sym in enumerate(parser.symbols):
            if sym.name in candidates and i in sym_addrs:
                return sym_addrs[i]
        return None

    # ──────────────────────────────────────
    #  Helpers
    # ──────────────────────────────────────

    @staticmethod
    def _align(size: int, alignment: int = SECTION_ALIGNMENT) -> int:
        return (size + alignment - 1) & ~(alignment - 1)

    def _cleanup(self):
        for addr, size in self._allocated_blocks:
            self._VirtualFree(addr, 0, MEM_RELEASE)
        self._allocated_blocks.clear()
        self._section_bases.clear()
        self._func_table_cursor = 0
