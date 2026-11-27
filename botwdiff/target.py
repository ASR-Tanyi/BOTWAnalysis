"""The original executable plus the decomp's function list and data symbol names."""

from __future__ import annotations

import csv
from dataclasses import dataclass
from functools import lru_cache
from typing import Dict, List, Optional

import cxxfilt

from . import disasm, nso, paths

QUALITY = {
    "O": "matching",
    "m": "minor mismatch",
    "M": "major mismatch",
    "W": "wip",
    "U": "not decompiled",
    "L": "library",
}


@dataclass
class Function:
    addr: int
    quality: str
    size: int
    name: str

    @property
    def display(self) -> str:
        return self.name or f"sub_{self.addr:x}"


@lru_cache(maxsize=None)
def demangle(name: str) -> str:
    try:
        return cxxfilt.demangle(name)
    except cxxfilt.InvalidName:
        return name


def load_functions() -> List[Function]:
    out = []
    with open(paths.functions_csv(), newline="") as f:
        for row in csv.reader(f):
            if not row or row[0] == "Address":
                continue
            out.append(Function(int(row[0], 16), row[1], int(row[2]), row[3] if len(row) > 3 else ""))
    return out


def load_data_symbols() -> Dict[int, str]:
    out = {}
    path = paths.data_symbols_csv()
    if path.is_file():
        with open(path, newline="") as f:
            for row in csv.reader(f):
                if len(row) >= 2 and row[0].startswith("0x"):
                    out[int(row[0], 16)] = row[1]
    return out


class Target:
    def __init__(self) -> None:
        if not paths.TARGET_NSO.is_file():
            raise SystemExit(f"{paths.TARGET_NSO} missing; run `setup` first")
        self.image = nso.Image.load(paths.TARGET_NSO)
        self.functions = load_functions()
        names: Dict[int, str] = dict(self.image.exports)
        names.update(load_data_symbols())
        for fn in self.functions:
            if fn.name:
                names[fn.addr] = fn.name
        self.names = names
        self.resolver = disasm.OriginalResolver(self.image, names, self.image.got_range)
        self.by_addr = {fn.addr: fn for fn in self.functions}
        self.by_name = {fn.name: fn for fn in self.functions if fn.name}

    def disasm(self, fn: Function) -> List[disasm.Insn]:
        return disasm.disasm_original(self.image, self.resolver, fn.addr, fn.size)

    def lookup(self, query: str) -> List[Function]:
        """Mangled name, address (0x71... or offset), exact demangled name, or substring."""
        q = query.strip()
        if q in self.by_name:
            return [self.by_name[q]]
        try:
            value = int(q, 16) if q.lower().startswith("0x") else None
        except ValueError:
            value = None
        if value is not None:
            if value < nso.BASE:
                value += nso.BASE
            if value in self.by_addr:
                return [self.by_addr[value]]
            containing = [fn for fn in self.functions if fn.addr <= value < fn.addr + fn.size]
            return containing
        exact = [fn for fn in self.functions if fn.name and demangle(fn.name) == q]
        if exact:
            return exact
        low = q.lower()
        return [fn for fn in self.functions
                if fn.name and (low in fn.name.lower() or low in demangle(fn.name).lower())]
