"""NSO parsing, LZ4 decompression and the dynamic tables needed to name addresses."""

from __future__ import annotations

import struct
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Tuple

import lz4.block

HEADER_SIZE = 0x100
BASE = 0x7100000000

DT_NULL, DT_PLTRELSZ, DT_STRTAB, DT_SYMTAB, DT_RELA, DT_RELASZ, DT_JMPREL = 0, 2, 5, 6, 7, 8, 23
R_AARCH64_ABS64 = 257
R_AARCH64_GLOB_DAT = 1025
R_AARCH64_JUMP_SLOT = 1026
R_AARCH64_RELATIVE = 1027


@dataclass
class Segment:
    file_offset: int
    mem_offset: int
    mem_size: int
    extra: int  # module name offset/size for text/rodata, bss size for data
    file_size: int


@dataclass
class NsoHeader:
    raw: bytes
    flags: int
    segments: List[Segment]

    @staticmethod
    def parse(data: bytes) -> "NsoHeader":
        if data[:4] != b"NSO0":
            raise ValueError("not an NSO file")
        flags = struct.unpack_from("<I", data, 0x0C)[0]
        file_sizes = struct.unpack_from("<3I", data, 0x60)
        segments = []
        for i in range(3):
            fo, mo, ms, extra = struct.unpack_from("<4I", data, 0x10 + i * 0x10)
            segments.append(Segment(fo, mo, ms, extra, file_sizes[i]))
        return NsoHeader(bytes(data[:HEADER_SIZE]), flags, segments)


def decompress(data: bytes) -> bytes:
    """Return an uncompressed NSO laid out exactly like `nx2elf --export-uncompressed`.

    The upstream downgrade patches and hashes are defined on that layout.
    """
    hdr = NsoHeader.parse(data)
    data_seg = hdr.segments[2]
    image = bytearray(data_seg.mem_offset + data_seg.mem_size)
    for i, seg in enumerate(hdr.segments):
        src = data[seg.file_offset : seg.file_offset + seg.file_size]
        if hdr.flags & (1 << i):
            out = lz4.block.decompress(src, uncompressed_size=seg.mem_size)
        else:
            out = src
        if len(out) != seg.mem_size:
            raise ValueError(f"segment {i}: expected {seg.mem_size:#x} bytes, got {len(out):#x}")
        image[seg.mem_offset : seg.mem_offset + seg.mem_size] = out

    header = bytearray(hdr.raw)
    struct.pack_into("<I", header, 0x0C, hdr.flags & 0xF8)
    for i, seg in enumerate(hdr.segments):
        struct.pack_into("<I", header, 0x10 + i * 0x10, seg.mem_offset + HEADER_SIZE)
        struct.pack_into("<I", header, 0x60 + i * 4, seg.mem_size)
    struct.pack_into("<I", header, 0x1C, 0x100)  # text "bss_align" as written by nx2elf
    struct.pack_into("<I", header, 0x2C, 0)  # rodata "bss_align"
    return bytes(header) + bytes(image)


@dataclass
class Image:
    """Flat memory image of the main module, addressed with absolute (0x71...) addresses."""

    data: bytes
    text: Tuple[int, int]
    rodata: Tuple[int, int]
    data_seg: Tuple[int, int]
    got: Dict[int, str] = field(default_factory=dict)  # slot address -> symbol name
    got_addr: Dict[int, int] = field(default_factory=dict)  # slot address -> target address
    plt: Dict[int, str] = field(default_factory=dict)  # stub address -> symbol name
    exports: Dict[int, str] = field(default_factory=dict)  # defined dynsym address -> name
    got_range: Tuple[int, int] = (0, 0)

    @staticmethod
    def load(path: Path) -> "Image":
        raw = path.read_bytes()
        hdr = NsoHeader.parse(raw)
        if hdr.flags & 7:
            raw = decompress(raw)
            hdr = NsoHeader.parse(raw)
        data_seg = hdr.segments[2]
        mem = bytearray(data_seg.mem_offset + data_seg.mem_size + data_seg.extra)
        for seg in hdr.segments:
            mem[seg.mem_offset : seg.mem_offset + seg.mem_size] = raw[
                seg.file_offset : seg.file_offset + seg.mem_size
            ]
        ranges = [(BASE + s.mem_offset, BASE + s.mem_offset + s.mem_size) for s in hdr.segments]
        img = Image(bytes(mem), ranges[0], ranges[1], ranges[2])
        img._parse_dynamic()
        return img

    def read(self, addr: int, size: int) -> bytes:
        off = addr - BASE
        return self.data[off : off + size]

    def u32(self, addr: int) -> int:
        return struct.unpack_from("<I", self.data, addr - BASE)[0]

    def in_text(self, addr: int) -> bool:
        return self.text[0] <= addr < self.text[1]

    def c_string(self, addr: int, limit: int = 512) -> Optional[str]:
        """Return a printable NUL-terminated string at addr (rodata only), else None."""
        if not (self.rodata[0] <= addr < self.rodata[1]):
            return None
        off = addr - BASE
        end = self.data.find(b"\0", off, off + limit)
        if end < 0:
            return None
        chunk = self.data[off:end]
        try:
            text = chunk.decode("utf-8")
        except UnicodeDecodeError:
            return None
        if any(ord(c) < 0x20 and c not in "\t\n\r" for c in text):
            return None
        return text

    def _parse_dynamic(self) -> None:
        mod_off = struct.unpack_from("<I", self.data, 4)[0]
        if self.data[mod_off : mod_off + 4] != b"MOD0":
            return
        dyn_off = mod_off + struct.unpack_from("<i", self.data, mod_off + 4)[0]
        dyn: Dict[int, int] = {}
        pos = dyn_off
        while True:
            tag, val = struct.unpack_from("<QQ", self.data, pos)
            pos += 16
            if tag == DT_NULL:
                break
            dyn.setdefault(tag, val)

        symtab, strtab = dyn.get(DT_SYMTAB), dyn.get(DT_STRTAB)

        def sym_name(index: int) -> str:
            if symtab is None or strtab is None:
                return ""
            st_name = struct.unpack_from("<I", self.data, symtab + index * 24)[0]
            end = self.data.index(b"\0", strtab + st_name)
            return self.data[strtab + st_name : end].decode("utf-8", "replace")

        def relocs(start: Optional[int], size: Optional[int]):
            if not start or not size:
                return
            for p in range(start, start + size, 24):
                yield struct.unpack_from("<QQq", self.data, p)

        if symtab is not None and strtab is not None and strtab > symtab:
            for i in range(1, (strtab - symtab) // 24):
                st_name, _info, _other, shndx, value, _size = struct.unpack_from(
                    "<IBBHQQ", self.data, symtab + i * 24)
                if shndx != 0 and value:
                    name = sym_name(i)
                    if name:
                        self.exports.setdefault(BASE + value, name)

        jump_slot_end = 0
        glob_dat_end = 0
        for table in ((dyn.get(DT_RELA), dyn.get(DT_RELASZ)), (dyn.get(DT_JMPREL), dyn.get(DT_PLTRELSZ))):
            for r_offset, r_info, r_addend in relocs(*table):
                rtype, rsym = r_info & 0xFFFFFFFF, r_info >> 32
                slot = BASE + r_offset
                if rtype == R_AARCH64_JUMP_SLOT:
                    jump_slot_end = max(jump_slot_end, slot + 8)
                elif rtype == R_AARCH64_GLOB_DAT:
                    glob_dat_end = max(glob_dat_end, slot + 8)
                if rtype == R_AARCH64_RELATIVE:
                    self.got_addr[slot] = BASE + r_addend
                elif rtype in (R_AARCH64_GLOB_DAT, R_AARCH64_JUMP_SLOT, R_AARCH64_ABS64) and rsym:
                    name = sym_name(rsym)
                    if name:
                        self.got[slot] = name

        # Like nx2elf: .got starts at the slot holding the _DYNAMIC offset after .got.plt
        # and ends after the last GLOB_DAT slot.
        got_start = 0
        if jump_slot_end:
            needle = struct.pack("<Q", dyn_off)
            pos = self.data.find(needle, jump_slot_end - BASE)
            if pos >= 0 and pos % 8 == 0:
                got_start = BASE + pos
        if got_start and glob_dat_end > got_start:
            # Slots after the last GLOB_DAT that are still relocated belong to .got as well
            # (symbols bound at link time become RELATIVE).
            end = glob_dat_end
            while end in self.got or end in self.got_addr:
                end += 8
            self.got_range = (got_start, end)
        else:
            self.got_range = (self.data_seg[0], self.data_seg[1])

    def plt_target(self, addr: int) -> Optional[str]:
        """Decode `adrp x16; ldr x17,[x16,#o]; add x16,x16,#o; br x17` and name the slot."""
        if addr in self.plt:
            return self.plt[addr]
        if not self.in_text(addr):
            return None
        w0, w1, w2, w3 = struct.unpack_from("<4I", self.data, addr - BASE)
        if (w0 & 0x9F00001F) != 0x90000010 or (w1 & 0xFFC003FF) != 0xF9400211 or w3 != 0xD61F0220:
            return None
        immlo, immhi = (w0 >> 29) & 3, (w0 >> 5) & 0x7FFFF
        imm = (immhi << 2) | immlo
        if imm & (1 << 20):
            imm -= 1 << 21
        page = (addr & ~0xFFF) + (imm << 12)
        slot = page + ((w1 >> 10) & 0xFFF) * 8
        name = self.got.get(slot)
        if name:
            self.plt[addr] = name
        return name
