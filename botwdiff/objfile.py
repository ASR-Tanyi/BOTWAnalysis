"""Read functions and relocations from decomp object files and keep a symbol -> object index."""

from __future__ import annotations

import json
import os
from concurrent.futures import ProcessPoolExecutor
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from elftools.elf.constants import SH_FLAGS
from elftools.elf.elffile import ELFFile
from elftools.elf.relocation import RelocationSection

from . import build, disasm, paths

INDEX_VERSION = 1


def _scan(path: str) -> Tuple[str, float, Dict[str, List[int]]]:
    funcs: Dict[str, List[int]] = {}
    try:
        mtime = os.path.getmtime(path)
        with open(path, "rb") as f:
            elf = ELFFile(f)
            symtab = elf.get_section_by_name(".symtab")
            if symtab is None:
                return path, mtime, funcs
            for sym in symtab.iter_symbols():
                if sym["st_info"]["type"] != "STT_FUNC" or sym["st_size"] == 0:
                    continue
                shndx = sym["st_shndx"]
                if not isinstance(shndx, int):
                    continue
                weak = 1 if sym["st_info"]["bind"] == "STB_WEAK" else 0
                funcs[sym.name] = [shndx, sym["st_value"], sym["st_size"], weak]
    except (OSError, ValueError) as e:
        print(f"warning: cannot read {path}: {e}")
        mtime = 0.0
    return path, mtime, funcs


class ObjectIndex:
    def __init__(self, data: dict):
        self.objects: Dict[str, dict] = data.get("objects", {})
        self.sources: Dict[str, str] = data.get("sources", {})
        self._by_name: Optional[Dict[str, Tuple[str, List[int]]]] = None

    @staticmethod
    def load_or_update(build_dir: Path = paths.DECOMP_BUILD, index_path: Path = paths.OBJ_INDEX,
                       verbose: bool = True) -> "ObjectIndex":
        data = {}
        if index_path.is_file():
            data = json.loads(index_path.read_text())
            if data.get("version") != INDEX_VERSION:
                data = {}
        objects = data.get("objects", {})
        db = json.loads((build_dir / "compile_commands.json").read_text())
        sources = {}
        for entry in db:
            out = entry.get("output")
            if out:
                sources[str(Path(build_dir, out))] = entry["file"]
        stale = []
        for obj in sources:
            if not os.path.isfile(obj):
                objects.pop(obj, None)
                continue
            cached = objects.get(obj)
            if cached is None or cached["mtime"] != os.path.getmtime(obj):
                stale.append(obj)
        if stale:
            if verbose:
                print(f"indexing {len(stale)} object(s)")
            with ProcessPoolExecutor() as pool:
                for path, mtime, funcs in pool.map(_scan, stale, chunksize=32):
                    objects[path] = {"mtime": mtime, "funcs": funcs}
            index_path.parent.mkdir(parents=True, exist_ok=True)
            index_path.write_text(json.dumps({"version": INDEX_VERSION, "objects": objects, "sources": sources}))
        return ObjectIndex({"objects": objects, "sources": sources})

    def by_name(self) -> Dict[str, Tuple[str, List[int]]]:
        if self._by_name is None:
            table: Dict[str, Tuple[str, List[int]]] = {}
            for obj, info in self.objects.items():
                for name, entry in info["funcs"].items():
                    prev = table.get(name)
                    if prev is None or (prev[1][3] and not entry[3]):
                        table[name] = (obj, entry)
            self._by_name = table
        return self._by_name

    def find(self, name: str) -> Optional[Tuple[str, List[int]]]:
        return self.by_name().get(name)

    def ninja_target(self, obj: str, build_dir: Path = paths.DECOMP_BUILD) -> str:
        return str(Path(obj).relative_to(build_dir))


@dataclass
class ObjFunction:
    name: str
    obj: str
    code: bytes
    insns: List[disasm.Insn]


class ObjectFile:
    """Parsed object with lazy per-section relocation tables."""

    def __init__(self, path: str):
        self.path = path
        self._f = open(path, "rb")
        self.elf = ELFFile(self._f)
        self.symtab = self.elf.get_section_by_name(".symtab")
        self._symbols = list(self.symtab.iter_symbols())
        self._relocs: Dict[int, Dict[int, disasm.ObjReloc]] = {}
        self._rela_for: Dict[int, RelocationSection] = {}
        for sec in self.elf.iter_sections():
            if isinstance(sec, RelocationSection):
                self._rela_for[sec["sh_info"]] = sec
        self._section_syms: Dict[int, Dict[int, str]] = {}
        for sym in self._symbols:
            shndx = sym["st_shndx"]
            if isinstance(shndx, int) and sym["st_info"]["type"] == "STT_FUNC":
                self._section_syms.setdefault(shndx, {})[sym["st_value"]] = sym.name

    def close(self) -> None:
        self._f.close()

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()

    def relocs(self, shndx: int) -> Dict[int, disasm.ObjReloc]:
        if shndx not in self._relocs:
            table: Dict[int, disasm.ObjReloc] = {}
            rela = self._rela_for.get(shndx)
            if rela is not None:
                for r in rela.iter_relocations():
                    sym = self._symbols[r["r_info_sym"]]
                    if sym["st_info"]["type"] == "STT_SECTION":
                        name = "\0sec:" + str(sym["st_shndx"])
                    elif sym.name.startswith(".L") and isinstance(sym["st_shndx"], int):
                        name = "\0sec:" + str(sym["st_shndx"])
                        r_addend = r["r_addend"] + sym["st_value"]
                        table[r["r_offset"]] = disasm.ObjReloc(r["r_info_type"], name, r_addend)
                        continue
                    else:
                        name = sym.name
                    table[r["r_offset"]] = disasm.ObjReloc(r["r_info_type"], name, r["r_addend"])
            self._relocs[shndx] = table
        return self._relocs[shndx]

    def describe(self, rel: disasm.ObjReloc, width: int, fp: bool) -> str:
        if not rel.symbol.startswith("\0sec:"):
            return rel.symbol + (f"+{rel.addend:#x}" if rel.addend else "")
        shndx = int(rel.symbol[5:])
        sec = self.elf.get_section(shndx)
        flags = sec["sh_flags"]
        if sec["sh_type"] != "SHT_NOBITS":
            data = sec.data()
            if flags & SH_FLAGS.SHF_STRINGS:
                end = data.find(b"\0", rel.addend)
                try:
                    return disasm.quote_string(data[rel.addend : end if end >= 0 else None].decode("utf-8"))
                except UnicodeDecodeError:
                    pass
            if fp and not flags & SH_FLAGS.SHF_WRITE and not flags & SH_FLAGS.SHF_EXECINSTR:
                return "=" + disasm.format_value(data[rel.addend : rel.addend + width])
        # A section-relative reference to a function in this object.
        name = self._section_syms.get(shndx, {}).get(rel.addend)
        if name:
            return name
        return f"<{sec.name}+{rel.addend:#x}>"

    def function(self, name: str, shndx: int, value: int, size: int) -> ObjFunction:
        sec = self.elf.get_section(shndx)
        code = sec.data()[value : value + size]
        all_rel = self.relocs(shndx)
        rel = {off - value: r for off, r in all_rel.items() if value <= off < value + size}
        syms = self._section_syms.get(shndx, {})
        insns = disasm.disasm_object(code, rel, self.describe, syms.get, value, name)
        return ObjFunction(name, self.path, code, insns)


def rebuild_object(index: ObjectIndex, obj: str) -> None:
    build.build_objects([index.ninja_target(obj)], keep_going=False)
