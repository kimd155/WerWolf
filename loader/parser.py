"""
COFF (Common Object File Format) Parser
========================================
Parses COFF object files (.obj / .o) produced by MSVC or MinGW compilers.

COFF Structure:
  [FILE HEADER]        - 20 bytes: machine type, section/symbol counts
  [SECTION HEADERS]    - 40 bytes each: name, size, characteristics
  [SECTION DATA]       - raw bytes: machine code (.text) and data (.data, .rdata)
  [RELOCATIONS]        - 10 bytes each: fixups needed for position-independent loading
  [SYMBOL TABLE]       - 18 bytes each: function/variable names and locations
  [STRING TABLE]       - variable: long symbol names (>8 chars)
"""

import struct
import logging
from dataclasses import dataclass, field
from typing import List, Optional

logger = logging.getLogger(__name__)

# ── Machine Types ──
IMAGE_FILE_MACHINE_AMD64 = 0x8664
IMAGE_FILE_MACHINE_I386  = 0x14C

# ── Section Characteristics ──
IMAGE_SCN_CNT_CODE               = 0x00000020
IMAGE_SCN_CNT_INITIALIZED_DATA   = 0x00000040
IMAGE_SCN_CNT_UNINITIALIZED_DATA = 0x00000080
IMAGE_SCN_LNK_NRELOC_OVFL        = 0x01000000
IMAGE_SCN_MEM_EXECUTE            = 0x20000000
IMAGE_SCN_MEM_READ               = 0x40000000
IMAGE_SCN_MEM_WRITE              = 0x80000000

# ── Symbol Storage Classes ──
IMAGE_SYM_CLASS_EXTERNAL = 2
IMAGE_SYM_CLASS_STATIC   = 3
IMAGE_SYM_CLASS_LABEL    = 6
IMAGE_SYM_CLASS_SECTION  = 104

# ── Symbol Section Numbers ──
IMAGE_SYM_UNDEFINED = 0
IMAGE_SYM_ABSOLUTE  = -1
IMAGE_SYM_DEBUG     = -2

# ── AMD64 Relocation Types ──
IMAGE_REL_AMD64_ABSOLUTE = 0x0000
IMAGE_REL_AMD64_ADDR64   = 0x0001
IMAGE_REL_AMD64_ADDR32   = 0x0002
IMAGE_REL_AMD64_ADDR32NB = 0x0003
IMAGE_REL_AMD64_REL32    = 0x0004
IMAGE_REL_AMD64_REL32_1  = 0x0005
IMAGE_REL_AMD64_REL32_2  = 0x0006
IMAGE_REL_AMD64_REL32_3  = 0x0007
IMAGE_REL_AMD64_REL32_4  = 0x0008
IMAGE_REL_AMD64_REL32_5  = 0x0009
IMAGE_REL_AMD64_SECTION  = 0x000A
IMAGE_REL_AMD64_SECREL   = 0x000B

RELOC_TYPE_NAMES = {
    IMAGE_REL_AMD64_ABSOLUTE: "ABSOLUTE",
    IMAGE_REL_AMD64_ADDR64:   "ADDR64",
    IMAGE_REL_AMD64_ADDR32:   "ADDR32",
    IMAGE_REL_AMD64_ADDR32NB: "ADDR32NB",
    IMAGE_REL_AMD64_REL32:    "REL32",
    IMAGE_REL_AMD64_REL32_1:  "REL32_1",
    IMAGE_REL_AMD64_REL32_2:  "REL32_2",
    IMAGE_REL_AMD64_REL32_3:  "REL32_3",
    IMAGE_REL_AMD64_REL32_4:  "REL32_4",
    IMAGE_REL_AMD64_REL32_5:  "REL32_5",
    IMAGE_REL_AMD64_SECTION:  "SECTION",
    IMAGE_REL_AMD64_SECREL:   "SECREL",
}


@dataclass
class CoffHeader:
    machine: int
    number_of_sections: int
    time_date_stamp: int
    pointer_to_symbol_table: int
    number_of_symbols: int
    size_of_optional_header: int
    characteristics: int

    def __str__(self):
        return (
            f"Machine: 0x{self.machine:04X} | "
            f"Sections: {self.number_of_sections} | "
            f"Symbols: {self.number_of_symbols} | "
            f"OptHdr: {self.size_of_optional_header}"
        )


@dataclass
class SectionHeader:
    name: str
    virtual_size: int
    virtual_address: int
    size_of_raw_data: int
    pointer_to_raw_data: int
    pointer_to_relocations: int
    pointer_to_line_numbers: int
    number_of_relocations: int
    number_of_line_numbers: int
    characteristics: int
    data: bytes = b""
    relocations: list = field(default_factory=list)

    @property
    def is_code(self) -> bool:
        return bool(self.characteristics & IMAGE_SCN_CNT_CODE)

    @property
    def is_data(self) -> bool:
        return bool(self.characteristics & IMAGE_SCN_CNT_INITIALIZED_DATA)

    @property
    def is_bss(self) -> bool:
        return bool(self.characteristics & IMAGE_SCN_CNT_UNINITIALIZED_DATA)

    @property
    def is_executable(self) -> bool:
        return bool(self.characteristics & IMAGE_SCN_MEM_EXECUTE)

    @property
    def effective_size(self) -> int:
        return max(self.size_of_raw_data, self.virtual_size, 1)

    def __str__(self):
        flags = []
        if self.is_code: flags.append("CODE")
        if self.is_data: flags.append("DATA")
        if self.is_bss: flags.append("BSS")
        if self.is_executable: flags.append("EXEC")
        return (
            f"{self.name:<8s} | size={self.effective_size:<6d} | "
            f"relocs={self.number_of_relocations:<3d} | "
            f"flags=[{', '.join(flags)}]"
        )


@dataclass
class Symbol:
    name: str
    value: int
    section_number: int  # 1-based, 0=undefined, -1=absolute, -2=debug
    type_: int
    storage_class: int
    number_of_aux_symbols: int

    @property
    def is_external(self) -> bool:
        return self.storage_class == IMAGE_SYM_CLASS_EXTERNAL

    @property
    def is_undefined(self) -> bool:
        return self.section_number == IMAGE_SYM_UNDEFINED

    @property
    def is_function(self) -> bool:
        return (self.type_ >> 4) == 2  # IMAGE_SYM_DTYPE_FUNCTION

    def __str__(self):
        sec = {0: "UNDEF", -1: "ABS", -2: "DEBUG"}.get(
            self.section_number, f"sec[{self.section_number}]"
        )
        cls = {2: "EXTERN", 3: "STATIC", 6: "LABEL", 104: "SECTION"}.get(
            self.storage_class, f"class({self.storage_class})"
        )
        return f"{self.name:<40s} | {sec:<10s} | val=0x{self.value:08X} | {cls}"


@dataclass
class Relocation:
    virtual_address: int
    symbol_table_index: int
    type_: int

    @property
    def type_name(self) -> str:
        return RELOC_TYPE_NAMES.get(self.type_, f"UNKNOWN(0x{self.type_:04X})")

    def __str__(self):
        return (
            f"offset=0x{self.virtual_address:08X} | "
            f"sym_idx={self.symbol_table_index:<4d} | "
            f"type={self.type_name}"
        )


class CoffParser:
    """
    Parses a raw COFF object file into structured data.

    Usage:
        parser = CoffParser(raw_bytes)
        parser.parse()
        # Access: parser.header, parser.sections, parser.symbols
    """

    def __init__(self, data: bytes):
        self.data = data
        self.header: Optional[CoffHeader] = None
        self.sections: List[SectionHeader] = []
        self.symbols: List[Symbol] = []
        self.string_table: bytes = b""

    def parse(self) -> "CoffParser":
        self._parse_header()
        self._parse_string_table()   # Must come before sections (long names)
        self._parse_sections()
        self._parse_symbols()
        self._parse_relocations()
        return self

    # ── Header (20 bytes) ──

    def _parse_header(self):
        if len(self.data) < 20:
            raise ValueError("File too small to be a valid COFF object")

        fields = struct.unpack_from("<HHIIIHH", self.data, 0)
        self.header = CoffHeader(*fields)

        if self.header.machine != IMAGE_FILE_MACHINE_AMD64:
            raise ValueError(
                f"Unsupported machine type: 0x{self.header.machine:04X} "
                f"(expected x64 / 0x8664)"
            )

        if self.header.size_of_optional_header != 0:
            raise ValueError(
                "File has an optional header  - this looks like a PE executable, not a COFF object"
            )

        logger.info(f"COFF Header: {self.header}")

    # ── Section Headers (40 bytes each) ──

    def _parse_sections(self):
        offset = 20 + self.header.size_of_optional_header

        for i in range(self.header.number_of_sections):
            fields = struct.unpack_from("<8sIIIIIIHHI", self.data, offset)
            name_raw = fields[0]

            # Section names > 8 chars use /N format (offset into string table)
            if name_raw.startswith(b"/"):
                try:
                    str_offset = int(name_raw[1:].rstrip(b"\x00"))
                    name = self._read_string_at(str_offset)
                except (ValueError, IndexError):
                    name = name_raw.rstrip(b"\x00").decode("ascii", errors="replace")
            else:
                name = name_raw.rstrip(b"\x00").decode("ascii", errors="replace")

            section = SectionHeader(
                name=name,
                virtual_size=fields[1],
                virtual_address=fields[2],
                size_of_raw_data=fields[3],
                pointer_to_raw_data=fields[4],
                pointer_to_relocations=fields[5],
                pointer_to_line_numbers=fields[6],
                number_of_relocations=fields[7],
                number_of_line_numbers=fields[8],
                characteristics=fields[9],
            )

            # Read raw section data
            if section.size_of_raw_data > 0 and section.pointer_to_raw_data > 0:
                start = section.pointer_to_raw_data
                end = start + section.size_of_raw_data
                section.data = self.data[start:end]

            self.sections.append(section)
            logger.info(f"  Section [{i}]: {section}")

            offset += 40

    # ── String Table ──

    def _parse_string_table(self):
        """String table sits immediately after the symbol table."""
        if self.header.number_of_symbols == 0:
            return

        str_table_offset = (
            self.header.pointer_to_symbol_table
            + self.header.number_of_symbols * 18
        )

        if str_table_offset + 4 > len(self.data):
            return

        str_table_size = struct.unpack_from("<I", self.data, str_table_offset)[0]
        if str_table_size > 4:
            self.string_table = self.data[
                str_table_offset : str_table_offset + str_table_size
            ]

    def _read_string_at(self, offset: int) -> str:
        """Read a null-terminated string from the string table."""
        if offset >= len(self.string_table):
            return f"<invalid_offset_{offset}>"
        end = self.string_table.index(b"\x00", offset)
        return self.string_table[offset:end].decode("ascii", errors="replace")

    # ── Symbol Table (18 bytes each) ──

    def _parse_symbols(self):
        offset = self.header.pointer_to_symbol_table

        i = 0
        while i < self.header.number_of_symbols:
            fields = struct.unpack_from("<8sIhHBB", self.data, offset)
            name_raw = fields[0]

            # Name: either inline (8 bytes) or string-table offset
            if name_raw[:4] == b"\x00\x00\x00\x00":
                str_offset = struct.unpack_from("<I", name_raw, 4)[0]
                name = self._read_string_at(str_offset)
            else:
                name = name_raw.rstrip(b"\x00").decode("ascii", errors="replace")

            symbol = Symbol(
                name=name,
                value=fields[1],
                section_number=fields[2],
                type_=fields[3],
                storage_class=fields[4],
                number_of_aux_symbols=fields[5],
            )
            self.symbols.append(symbol)
            logger.debug(f"  Symbol [{i}]: {symbol}")

            # Skip auxiliary symbol records
            aux = symbol.number_of_aux_symbols
            offset += 18
            i += 1

            for _ in range(aux):
                self.symbols.append(
                    Symbol("__aux__", 0, 0, 0, 0, 0)
                )
                offset += 18
                i += 1

    # ── Relocations (10 bytes each) ──

    def _parse_relocations(self):
        for section in self.sections:
            if section.number_of_relocations == 0:
                continue

            offset = section.pointer_to_relocations
            for _ in range(section.number_of_relocations):
                fields = struct.unpack_from("<IIH", self.data, offset)
                reloc = Relocation(
                    virtual_address=fields[0],
                    symbol_table_index=fields[1],
                    type_=fields[2],
                )
                section.relocations.append(reloc)
                offset += 10

            logger.debug(
                f"  Section '{section.name}': {len(section.relocations)} relocations"
            )

    # ── Pretty Print ──

    def dump(self):
        """Print a human-readable summary of the COFF file."""
        print(f"\n{'='*60}")
        print(f"  COFF Object File Summary")
        print(f"{'='*60}")
        print(f"\n  {self.header}\n")

        print(f"  Sections:")
        print(f"  {'-'*56}")
        for i, s in enumerate(self.sections):
            print(f"    [{i}] {s}")

        print(f"\n  Symbols (external/defined):")
        print(f"  {'-'*56}")
        for i, s in enumerate(self.symbols):
            if s.name == "__aux__":
                continue
            if s.is_external or s.section_number > 0:
                marker = "  >>  " if s.is_undefined and s.is_external else "      "
                print(f"  {marker}[{i}] {s}")

        print(f"\n  Relocations:")
        print(f"  {'-'*56}")
        for sec in self.sections:
            if sec.relocations:
                print(f"    Section '{sec.name}':")
                for r in sec.relocations:
                    sym_name = self.symbols[r.symbol_table_index].name
                    print(f"      {r} -> {sym_name}")

        print(f"\n{'='*60}\n")
