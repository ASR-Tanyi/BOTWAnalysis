"""Check that the instructions shown for the original come from the NSO unchanged.

Three independent checks:
1. The prepared NSO still has the v1.5.0 hash.
2. Each instruction word is re-read from the NSO file at its file offset, without the image
   loader, and compared with the word that was disassembled.
3. The words are assembled back into an object with `.inst` directives by Clang 4.0.1, then
   disassembled by LLVM's llvm-objdump. LLVM and capstone must agree on the mnemonic and the
   registers of every instruction.
"""

from __future__ import annotations

import re
import struct
import subprocess
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Tuple

from . import nso, paths, prepare
from .target import Function, Target

_OBJDUMP_LINE = re.compile(r"^\s*([0-9a-f]+):\s+((?:[0-9a-f]{2} ){4})\s*(\S+)\s*(.*)$")
_REG = re.compile(r"\b(?:[xwbhsdqv](?:[12]?[0-9]|3[01])|sp|wsp|xzr|wzr)\b")
_COMMENT = re.compile(r"\s*(//|;).*$")


@dataclass
class FunctionReport:
    fn: Function
    file_offset: int
    words: int
    byte_mismatches: List[Tuple[int, int, int]] = field(default_factory=list)  # (offset, file, decoded)
    llvm_mismatches: List[Tuple[int, str, str]] = field(default_factory=list)  # (offset, capstone, llvm)

    @property
    def ok(self) -> bool:
        return not self.byte_mismatches and not self.llvm_mismatches


def _file_offset(header: nso.NsoHeader, addr: int) -> int:
    rva = addr - nso.BASE
    for seg in header.segments:
        if seg.mem_offset <= rva < seg.mem_offset + seg.mem_size:
            return seg.file_offset + rva - seg.mem_offset
    raise ValueError(f"{addr:#x} is outside the NSO segments")


def _llvm_disasm(words: List[int]) -> Dict[int, Tuple[str, str]]:
    """Disassemble raw words with Clang 4.0.1's integrated assembler + llvm-objdump."""
    clang = paths.CLANG_DIR / "bin" / "clang"
    objdump = paths.CLANG_DIR / "bin" / "llvm-objdump"
    if not clang.exists() or not objdump.exists():
        raise SystemExit(f"clang 4.0.1 not found at {paths.CLANG_DIR}; run `setup` first")
    with tempfile.TemporaryDirectory() as tmp:
        src = Path(tmp) / "words.s"
        obj = Path(tmp) / "words.o"
        lines = ["\t.text"] + [f"\t.inst {w:#010x}" for w in words]
        src.write_text("\n".join(lines) + "\n")
        subprocess.check_call([str(clang), "--target=aarch64-linux-elf", "-c", "-x", "assembler",
                               str(src), "-o", str(obj)])
        out = subprocess.check_output([str(objdump), "-d", str(obj)], text=True)
    result: Dict[int, Tuple[str, str]] = {}
    for line in out.splitlines():
        m = _OBJDUMP_LINE.match(line)
        if m:
            result[int(m.group(1), 16)] = (m.group(3), _COMMENT.sub("", m.group(4)).strip())
    return result


def _regs(ops: str) -> List[str]:
    return _REG.findall(ops.lower())


def _agree(cs_mnem: str, cs_ops: str, llvm_mnem: str, llvm_ops: str) -> bool:
    """Same instruction, allowing the alias spellings that differ between LLVM 4 and capstone 5."""
    if cs_mnem == ".word":
        return llvm_mnem == "<unknown>"
    if cs_mnem == llvm_mnem:
        return _regs(cs_ops) == _regs(llvm_ops)
    # mov wN, #imm  ==  orr wN, wzr, #imm   (bitmask-immediate move)
    if cs_mnem == "mov" and llvm_mnem == "orr":
        return _regs(cs_ops) == [r for r in _regs(llvm_ops) if r not in ("wzr", "xzr")]
    # mov vD.T[i], vN.T[j]  ==  ins vD.T[i], vN.T[j]
    if cs_mnem == "mov" and llvm_mnem == "ins":
        return _regs(cs_ops) == _regs(llvm_ops)
    return False


def verify(target: Target, functions: List[Function], llvm: bool = True) -> List[FunctionReport]:
    raw = paths.TARGET_NSO.read_bytes()
    header = nso.NsoHeader.parse(raw)
    if header.flags & 7:
        raise SystemExit(f"{paths.TARGET_NSO} is compressed; expected the uncompressed v1.5.0 NSO")

    reports: List[FunctionReport] = []
    all_words: List[int] = []
    starts: List[int] = []
    decoded = []
    for fn in functions:
        off = _file_offset(header, fn.addr)
        insns = target.disasm(fn)
        rep = FunctionReport(fn, off, len(insns))
        for insn in insns:
            file_word = struct.unpack_from("<I", raw, off + insn.offset)[0]
            if file_word != insn.word:
                rep.byte_mismatches.append((insn.offset, file_word, insn.word))
        reports.append(rep)
        starts.append(len(all_words) * 4)
        all_words.extend(i.word for i in insns)
        decoded.append(insns)

    if llvm and all_words:
        llvm_out: Dict[int, Tuple[str, str]] = {}
        batch = 1 << 16
        for i in range(0, len(all_words), batch):
            for off, val in _llvm_disasm(all_words[i : i + batch]).items():
                llvm_out[i * 4 + off] = val
        for rep, base, insns in zip(reports, starts, decoded):
            for insn in insns:
                got = llvm_out.get(base + insn.offset)
                if got is None:
                    if insn.mnemonic != ".word":
                        rep.llvm_mismatches.append((insn.offset, f"{insn.mnemonic} {insn.op_str}", "<missing>"))
                    continue
                mnem, ops = got
                if not _agree(insn.mnemonic, insn.op_str, mnem, ops):
                    rep.llvm_mismatches.append((insn.offset, f"{insn.mnemonic} {insn.op_str}", f"{mnem} {ops}"))
    return reports


def check_hash() -> bool:
    return prepare.sha256(paths.TARGET_NSO.read_bytes()) == prepare.UNCOMPRESSED_V150
