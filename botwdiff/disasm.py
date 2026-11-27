"""Disassemble functions from the original image and from decomp objects into a common
symbolic form, so that instructions which differ only by link-time addresses compare equal.

Each instruction is rendered as `mnemonic operands`, where operands that the linker would
fill in (branch targets, ADRP pages, :lo12: offsets, GOT slots, literal pools) are replaced
with a descriptor of what they refer to: a symbol name, a string literal, a constant value
or, when nothing better is known, a raw address.
"""

from __future__ import annotations

import re
import struct
from dataclasses import dataclass
from typing import Callable, Dict, List, Optional, Tuple

import capstone
from capstone import arm64 as A

_ARCH = getattr(capstone, "CS_ARCH_ARM64", None) or getattr(capstone, "CS_ARCH_AARCH64")
_MD = capstone.Cs(_ARCH, capstone.CS_MODE_ARM)
_MD.detail = True

_OP_IMM = A.ARM64_OP_IMM
_OP_MEM = A.ARM64_OP_MEM
_OP_REG = A.ARM64_OP_REG
_BRANCH_GROUPS = (capstone.CS_GRP_JUMP, capstone.CS_GRP_CALL)
_LITERAL_LOADS = {"ldr", "ldrsw", "prfm"}
_MEM_RE = re.compile(r"\[(\w+)(?:, #[^\]]+)?\]")
_REG_RE = re.compile(r"\b([xwbhsdqv])([0-9]|[12][0-9]|30)\b")

# Relocation kinds shared by both sides.
BRANCH, PAGE, GOT_PAGE, LO12, GOT_LO12, ADR, LITERAL = (
    "branch", "page", "gotpage", "lo12", "gotlo12", "adr", "literal")
_SUFFIX = {PAGE: "@PAGE", GOT_PAGE: "@GOTPAGE", LO12: "@PAGEOFF", GOT_LO12: "@GOTPAGEOFF"}

UNRESOLVED_PREFIXES = ("0x", "<")
_PLACEHOLDER = "\x00"


@dataclass
class Ref:
    kind: str
    desc: str

    @property
    def unresolved(self) -> bool:
        return self.desc.startswith(UNRESOLVED_PREFIXES)

    @property
    def is_literal(self) -> bool:
        """String or constant value rather than a symbol."""
        return self.desc.startswith(('"', "="))


@dataclass
class Insn:
    offset: int
    word: int
    mnemonic: str
    op_str: str
    ref: Optional[Ref] = None

    @property
    def text(self) -> str:
        return f"{self.mnemonic} {render_operands(self)}".rstrip()

    @property
    def reg_normalized(self) -> str:
        return _REG_RE.sub(lambda m: m.group(1) + "?", self.text)

    @property
    def shape(self) -> str:
        """Text with the referenced symbol replaced by a placeholder."""
        if self.ref is None:
            return self.text
        return f"{self.mnemonic} {render_operands(self, _PLACEHOLDER)}".rstrip()

    @property
    def shape_normalized(self) -> str:
        return _REG_RE.sub(lambda m: m.group(1) + "?", self.shape)


def render_operands(insn: Insn, desc: Optional[str] = None) -> str:
    ref = insn.ref
    ops = insn.op_str
    if ref is None:
        return ops
    if desc is None:
        desc = ref.desc
    if ref.kind in (PAGE, GOT_PAGE):
        return f"{ops.split(',', 1)[0]}, {desc}{_SUFFIX[ref.kind]}"
    if ref.kind in (LO12, GOT_LO12):
        sym = desc + _SUFFIX[ref.kind]
        if "[" in ops:
            return _MEM_RE.sub(lambda m: f"[{m.group(1)}, {sym}]", ops, count=1)
        return _replace_last(ops, sym)
    return _replace_last(ops, desc)


def _replace_last(ops: str, value: str) -> str:
    head, sep, _ = ops.rpartition(", ")
    return f"{head}{sep}{value}" if sep else value


def width_of(insn: "capstone.CsInsn") -> int:
    """Access width of a load/store from its first register operand."""
    if not insn.operands or insn.operands[0].type != _OP_REG:
        return 8
    name = insn.reg_name(insn.operands[0].reg)
    return {"b": 1, "h": 2, "w": 4, "s": 4, "x": 8, "d": 8, "q": 16}.get(name[:1], 8)


def is_fp_load(insn: "capstone.CsInsn") -> bool:
    if not insn.mnemonic.startswith("ld") or not insn.operands or insn.operands[0].type != _OP_REG:
        return False
    return insn.reg_name(insn.operands[0].reg)[:1] in "bhsdq"


def _decode(code: bytes, address: int):
    out = []
    pos = 0
    while pos < len(code):
        got = False
        for ins in _MD.disasm(code[pos:], address + pos):
            out.append(ins)
            pos += 4
            got = True
        if pos < len(code):  # undecodable word: emit as data and resume
            word = struct.unpack_from("<I", code, pos)[0]
            out.append(word)
            pos += 4
        elif not got:
            break
    return out


def _branch_target(ins) -> Optional[int]:
    if not any(ins.group(g) for g in _BRANCH_GROUPS):
        return None
    if ins.operands and ins.operands[-1].type == _OP_IMM:
        return ins.operands[-1].imm
    return None


def _lo12_base(ins) -> Optional[Tuple[int, int]]:
    """(base register, immediate) if ins could consume an ADRP page."""
    ops = ins.operands
    if ins.mnemonic == "add" and len(ops) == 3 and ops[1].type == _OP_REG and ops[2].type == _OP_IMM \
            and ops[2].shift.type == 0:
        return ops[1].reg, ops[2].imm
    for op in ops:
        if op.type == _OP_MEM and op.mem.index == 0 and not ins.writeback:
            return op.mem.base, op.mem.disp
    return None


def _make(ins, base: int) -> Insn:
    if isinstance(ins, int):
        return Insn(0, ins, ".word", f"{ins:#010x}")
    word = struct.unpack("<I", ins.bytes)[0]
    return Insn(ins.address - base, word, ins.mnemonic, ins.op_str)


def local_label(offset: int) -> str:
    return f".L{offset:x}"


# --------------------------------------------------------------------------- original


class OriginalResolver:
    """Names addresses in the original image."""

    def __init__(self, image, names: Dict[int, str], got_range: Tuple[int, int]):
        self.image = image
        self.names = names
        self.got_range = got_range

    def name(self, addr: int) -> Optional[str]:
        name = self.names.get(addr)
        if name:
            return name
        plt = self.image.plt_target(addr)
        if plt:
            return plt
        return None

    def got_target(self, slot: int) -> Optional[str]:
        lo, hi = self.got_range
        if not (lo <= slot < hi):
            return None
        if slot in self.image.got:
            return self.image.got[slot]
        target = self.image.got_addr.get(slot)
        if target is None:
            return None
        return self.describe(target, 8, False)

    def describe(self, addr: int, width: int, fp: bool) -> str:
        name = self.name(addr)
        if name:
            return name
        s = self.image.c_string(addr)
        if s is not None and s:
            return _quote(s)
        if fp and self.image.rodata[0] <= addr < self.image.rodata[1]:
            return "=" + _value(self.image.read(addr, width))
        return f"{addr:#x}"


def disasm_original(image, resolver: OriginalResolver, start: int, size: int) -> List[Insn]:
    code = image.read(start, size)
    raw = _decode(code, start)
    out: List[Insn] = []
    pages: Dict[int, Tuple[int, int]] = {}  # reg -> (page, index of adrp)
    for ins in raw:
        insn = _make(ins, start)
        out.append(insn)
        if isinstance(ins, int):
            insn.offset = (len(out) - 1) * 4
            continue
        target = _branch_target(ins)
        if target is not None:
            if start <= target < start + size:
                insn.ref = Ref(BRANCH, local_label(target - start))
            else:
                insn.ref = Ref(BRANCH, resolver.name(target) or f"{target:#x}")
        elif ins.mnemonic == "adrp":
            pages[ins.operands[0].reg] = (ins.operands[1].imm, len(out) - 1)
            insn.ref = Ref(PAGE, f"{ins.operands[1].imm:#x}")
            continue
        elif ins.mnemonic == "adr":
            insn.ref = Ref(ADR, resolver.describe(ins.operands[1].imm, 8, False))
        elif ins.mnemonic in _LITERAL_LOADS and len(ins.operands) == 2 and ins.operands[1].type == _OP_IMM:
            addr = ins.operands[1].imm
            insn.ref = Ref(LITERAL, "=" + _value(image.read(addr, width_of(ins))))
        else:
            base = _lo12_base(ins)
            if base is not None and base[0] in pages:
                page, adrp_index = pages[base[0]]
                addr = page + base[1]
                got = None
                if ins.mnemonic == "ldr" and width_of(ins) == 8 and not is_fp_load(ins):
                    got = resolver.got_target(addr)
                if got is not None:
                    insn.ref = Ref(GOT_LO12, got)
                    page_ref = Ref(GOT_PAGE, got)
                else:
                    desc = resolver.describe(addr, width_of(ins), is_fp_load(ins))
                    insn.ref = Ref(LO12, desc)
                    page_ref = Ref(PAGE, desc)
                adrp = out[adrp_index]
                if adrp.ref is not None and adrp.ref.desc.startswith("0x"):
                    adrp.ref = page_ref
        _, written = ins.regs_access()
        for reg in written:
            pages.pop(reg, None)
    return out


# --------------------------------------------------------------------------- object


@dataclass
class ObjReloc:
    type: int
    symbol: str
    addend: int


# AArch64 ELF relocation types
R_CALL26, R_JUMP26 = 283, 282
R_CONDBR19, R_TSTBR14 = 280, 279
R_ADR_PREL_LO21, R_ADR_PREL_PG_HI21, R_ADR_PREL_PG_HI21_NC = 274, 275, 276
R_ADD_ABS_LO12_NC = 277
R_LDST_LO12 = {278, 284, 285, 286, 299}
R_LD_PREL_LO19 = 273
R_ADR_GOT_PAGE, R_LD64_GOT_LO12_NC = 311, 312


def disasm_object(code: bytes, relocs: Dict[int, ObjReloc], describe: Callable[[ObjReloc, int, bool], str],
                  local_name: Callable[[int], Optional[str]], func_offset: int,
                  func_name: str = "") -> List[Insn]:
    """`code` is the function body, `relocs` are keyed by offset from the function start.
    `local_name(section_offset)` names symbols in the same section for unrelocated branches."""
    raw = _decode(code, 0)
    out: List[Insn] = []
    pending: Dict[int, int] = {}  # reg -> index of adrp waiting for its pair's descriptor
    for ins in raw:
        insn = _make(ins, 0)
        out.append(insn)
        if isinstance(ins, int):
            insn.offset = (len(out) - 1) * 4
            continue
        rel = relocs.get(insn.offset)
        if rel is None:
            target = _branch_target(ins)
            if target is not None:
                if 0 <= target < len(code):
                    insn.ref = Ref(BRANCH, local_label(target))
                else:
                    name = local_name(func_offset + target)
                    insn.ref = Ref(BRANCH, name or f"<{func_offset + target:#x}>")
        elif rel.type in (R_CALL26, R_JUMP26, R_CONDBR19, R_TSTBR14):
            if rel.symbol == func_name and rel.addend == 0:
                insn.ref = Ref(BRANCH, local_label(0))
            else:
                insn.ref = Ref(BRANCH, describe(rel, 8, False))
        elif rel.type in (R_ADR_PREL_PG_HI21, R_ADR_PREL_PG_HI21_NC):
            insn.ref = Ref(PAGE, describe(rel, 8, False))
            pending[ins.operands[0].reg] = len(out) - 1
            continue
        elif rel.type == R_ADR_GOT_PAGE:
            insn.ref = Ref(GOT_PAGE, describe(rel, 8, False))
            pending[ins.operands[0].reg] = len(out) - 1
            continue
        elif rel.type == R_LD64_GOT_LO12_NC:
            insn.ref = Ref(GOT_LO12, describe(rel, 8, False))
        elif rel.type == R_ADD_ABS_LO12_NC or rel.type in R_LDST_LO12:
            desc = describe(rel, width_of(ins), is_fp_load(ins))
            insn.ref = Ref(LO12, desc)
            base = _lo12_base(ins)
            if base is not None and base[0] in pending:
                adrp = out[pending.pop(base[0])]
                if adrp.ref is not None and adrp.ref.kind == PAGE:
                    adrp.ref = Ref(PAGE, desc)
        elif rel.type == R_ADR_PREL_LO21:
            insn.ref = Ref(ADR, describe(rel, 8, False))
        elif rel.type == R_LD_PREL_LO19:
            insn.ref = Ref(LITERAL, "=" + describe(rel, width_of(ins), True).lstrip("="))
        else:
            insn.ref = Ref(BRANCH if _branch_target(ins) is not None else ADR, describe(rel, 8, False))
        _, written = ins.regs_access()
        for reg in written:
            pending.pop(reg, None)
    return out


def _quote(s: str, limit: int = 60) -> str:
    text = s if len(s) <= limit else s[:limit] + "..."
    return '"' + text.encode("unicode_escape").decode("ascii").replace('"', '\\"') + '"'


def _value(data: bytes) -> str:
    if len(data) in (4, 8):
        return f"{int.from_bytes(data, 'little'):#x}"
    return "0x" + data[::-1].hex()


quote_string = _quote
format_value = _value
