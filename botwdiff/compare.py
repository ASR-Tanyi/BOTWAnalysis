"""Align two instruction lists and classify each row."""

from __future__ import annotations

import difflib
import re
from dataclasses import dataclass, field
from typing import Dict, List, Optional

from .disasm import Insn

MATCH = "match"
RELOC = "reloc"  # same instruction, a link-time reference could not be named on one side
DATA = "data"  # same instruction, the referenced string/constant differs
SYMBOL = "symbol"  # same instruction, refers to a different symbol
REGSWAP = "regswap"  # same instruction modulo register allocation
DIFF = "diff"
LEFT_ONLY = "left"  # only in the original
RIGHT_ONLY = "right"  # only in the decomp

ROW_KINDS = (MATCH, RELOC, DATA, SYMBOL, REGSWAP, DIFF, LEFT_ONLY, RIGHT_ONLY)

# Complete/base object constructor and destructor variants are emitted as aliases.
_STRUCTOR_RE = re.compile(r"([CD])[12](?=E|I|v)")


def canonical(desc: str) -> str:
    return _STRUCTOR_RE.sub(r"\1x", desc)


# Placeholder names that IDA-derived function lists use for unnamed functions.
_PLACEHOLDER_RE = re.compile(r"^(nullsub|sub|j|loc|off|unk|unknown|fn|FUN)_[0-9A-Fa-f_]+$")


def _demangled_base(name: str) -> str:
    from .target import demangle

    text = demangle(canonical(name)) if name.startswith("_Z") else name
    return text.split("(", 1)[0].strip()


def ref_relation(a: str, b: str) -> str:
    """How the original descriptor `a` relates to decomp descriptor `b`:
    'same', 'unknown' (cannot tell) or 'different'."""
    if a == b or canonical(a) == canonical(b):
        return "same"
    if _PLACEHOLDER_RE.match(a):
        return "unknown"
    # Function lists name not-yet-decompiled functions with demangled names.
    if "::" in a and not a.startswith(("_Z", '"', "=")) and b.startswith("_Z"):
        return "same" if _demangled_base(a) == _demangled_base(b) else "different"
    return "different"


@dataclass
class Row:
    kind: str
    left: Optional[Insn]
    right: Optional[Insn]


@dataclass
class Result:
    rows: List[Row]
    left_size: int
    right_size: int
    counts: dict = field(default_factory=dict)

    @property
    def verdict(self) -> str:
        c = self.counts
        bad = c.get(DIFF, 0) + c.get(LEFT_ONLY, 0) + c.get(RIGHT_ONLY, 0) + c.get(SYMBOL, 0)
        if bad:
            return "mismatch"
        if c.get(REGSWAP, 0):
            return "regswap"
        if c.get(DATA, 0):
            return "data"  # code matches, a string or constant differs
        if c.get(RELOC, 0):
            return "match?"  # equal except references that could not be named
        return "match"

    @property
    def score(self) -> int:
        """Lower is better: weighted count of differing rows."""
        c = self.counts
        return (c.get(DIFF, 0) * 2 + c.get(LEFT_ONLY, 0) * 2 + c.get(RIGHT_ONLY, 0) * 2
                + c.get(SYMBOL, 0) + c.get(REGSWAP, 0) + c.get(DATA, 0))


def classify(a: Insn, b: Insn) -> str:
    if a.mnemonic != b.mnemonic:
        return DIFF
    if a.text == b.text:
        return MATCH
    if a.ref is not None and b.ref is not None and a.ref.kind == b.ref.kind:
        relation = ref_relation(a.ref.desc, b.ref.desc)
        if relation == "same":
            ref_kind = MATCH
        elif relation == "unknown" or a.ref.unresolved or b.ref.unresolved:
            ref_kind = RELOC
        elif a.ref.is_literal and b.ref.is_literal:
            ref_kind = DATA
        else:
            ref_kind = SYMBOL
        if a.shape == b.shape:
            return ref_kind
        if a.shape_normalized == b.shape_normalized:
            return REGSWAP if ref_kind in (MATCH, RELOC) else ref_kind
        return DIFF
    if a.reg_normalized == b.reg_normalized:
        return REGSWAP
    return DIFF


def _check_reloc_consistency(rows: List[Row]) -> None:
    """An unnamed address must correspond to one decomp symbol throughout the function
    (and vice versa); otherwise the rows really refer to different things."""
    fwd: Dict[str, set] = {}
    back: Dict[str, set] = {}
    for r in rows:
        if r.kind == RELOC:
            a, b = r.left.ref.desc, canonical(r.right.ref.desc)
            fwd.setdefault(a, set()).add(b)
            back.setdefault(b, set()).add(a)
    for r in rows:
        if r.kind == RELOC:
            a, b = r.left.ref.desc, canonical(r.right.ref.desc)
            if len(fwd[a]) > 1 or len(back[b]) > 1:
                r.kind = SYMBOL


def compare(left: List[Insn], right: List[Insn]) -> Result:
    keys_a = [i.mnemonic for i in left]
    keys_b = [i.mnemonic for i in right]
    rows: List[Row] = []
    sm = difflib.SequenceMatcher(None, keys_a, keys_b, autojunk=False)
    for tag, i1, i2, j1, j2 in sm.get_opcodes():
        if tag == "equal" or tag == "replace":
            n = min(i2 - i1, j2 - j1)
            for k in range(n):
                a, b = left[i1 + k], right[j1 + k]
                rows.append(Row(classify(a, b), a, b))
            for k in range(i1 + n, i2):
                rows.append(Row(LEFT_ONLY, left[k], None))
            for k in range(j1 + n, j2):
                rows.append(Row(RIGHT_ONLY, None, right[k]))
        elif tag == "delete":
            rows.extend(Row(LEFT_ONLY, left[k], None) for k in range(i1, i2))
        elif tag == "insert":
            rows.extend(Row(RIGHT_ONLY, None, right[k]) for k in range(j1, j2))
    _check_reloc_consistency(rows)
    counts: dict = {}
    for r in rows:
        counts[r.kind] = counts.get(r.kind, 0) + 1
    return Result(rows, len(left) * 4, len(right) * 4, counts)
