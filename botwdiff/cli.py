"""Command line interface: python -m botwdiff <command>."""

from __future__ import annotations

import argparse
import html
import json
import os
import sys
from collections import Counter, defaultdict
from concurrent.futures import ProcessPoolExecutor
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from . import build, compare, objfile, paths, prepare, render
from .target import QUALITY, Function, Target, demangle


def cmd_setup(args) -> int:
    prepare.prepare_target(Path(args.nso) if args.nso else paths.ORIGINAL_NSO)
    build.setup_clang()
    build.configure()
    print(f"wrote {build.write_scratch_compdb()}")
    if args.build:
        return cmd_build(argparse.Namespace(jobs=args.jobs, targets=[]))
    return 0


def cmd_build(args) -> int:
    rc = build.build_objects(args.targets or None, jobs=args.jobs)
    objfile.ObjectIndex.load_or_update()
    if rc:
        print("some objects failed to compile; functions in them cannot be compared", file=sys.stderr)
    return rc


def _pick(target: Target, query: str) -> Function:
    found = target.lookup(query)
    if not found:
        raise SystemExit(f"no function matches {query!r}")
    if len(found) > 1:
        print(f"{len(found)} functions match {query!r}:", file=sys.stderr)
        for fn in found[:40]:
            print(f"  {fn.addr:#x} {fn.quality} {demangle(fn.display)}", file=sys.stderr)
        if len(found) > 40:
            print("  ...", file=sys.stderr)
        raise SystemExit("be more specific (mangled name or address)")
    return found[0]


def _diff_one(target: Target, index: objfile.ObjectIndex, fn: Function, symbol: Optional[str] = None):
    left = target.disasm(fn)
    name = symbol or fn.name
    entry = index.find(name) if name else None
    if entry is None:
        return left, None, None
    obj, (shndx, value, size, _weak) = entry
    with objfile.ObjectFile(obj) as of:
        right = of.function(name, shndx, value, size)
    return left, right, compare.compare(left, right.insns)


def _diff_scratch(target: Target, fn: Function, obj: Path, symbol: Optional[str]):
    _path, _mtime, funcs = objfile._scan(str(obj))
    name = symbol or fn.name
    if name not in funcs:
        strong = [n for n, e in funcs.items() if not e[3]]
        if symbol is None and len(strong) == 1:
            name = strong[0]
        else:
            print(f"{obj} defines {len(funcs)} function(s):", file=sys.stderr)
            for n in sorted(funcs):
                print(f"  {n}  ({demangle(n)})", file=sys.stderr)
            raise SystemExit(f"{name or 'no CSV name'} is not defined there; pass --symbol")
    shndx, value, size, _weak = funcs[name]
    left = target.disasm(fn)
    with objfile.ObjectFile(str(obj)) as of:
        right = of.function(name, shndx, value, size)
    return left, right, compare.compare(left, right.insns)


def cmd_diff(args) -> int:
    target = Target()
    fn = _pick(target, args.function)
    if args.source:
        obj = build.compile_scratch(Path(args.source), args.like)
        left, right, result = _diff_scratch(target, fn, obj, args.symbol)
        index = None
    else:
        name = args.symbol or fn.name
        index = objfile.ObjectIndex.load_or_update(verbose=False)
        if not args.no_build and name:
            entry = index.find(name)
            if entry is not None:
                if build.build_objects([index.ninja_target(entry[0])], keep_going=False):
                    return 1
            else:
                build.build_objects()
            index = objfile.ObjectIndex.load_or_update(verbose=False)
        left, right, result = _diff_one(target, index, fn, args.symbol)

    title = demangle(fn.display) if not args.mangled else fn.display
    header_left = f"original {fn.addr:#x} ({fn.size:#x} bytes)"
    if right is None:
        print(f"{title}\n{fn.display} [{fn.quality}: {QUALITY.get(fn.quality, '?')}]")
        print("not found in decomp objects; showing original only\n")
        for insn in left:
            print(f"{fn.addr + insn.offset:x}: {insn.text}")
        return 2
    source = args.source or index.sources.get(right.obj, right.obj)
    header_right = f"decomp {Path(source).name}"
    meta = [fn.display, f"quality: {fn.quality} ({QUALITY.get(fn.quality, '?')})",
            f"source: {source}", f"object: {right.obj}"]
    if right.name != fn.name:
        meta.append(f"decomp symbol: {right.name}")

    if args.html:
        out = Path(args.html)
        out.write_text(render.html_page(result, title, header_left, header_right, meta,
                                        left_base=fn.addr, show_bytes=args.bytes))
        print(f"wrote {out}")
    if not args.html or args.print:
        color = sys.stdout.isatty() and not args.no_color and "NO_COLOR" not in os.environ
        print(title)
        for line in meta:
            print(line)
        print(render.LEGEND)
        print(render.terminal(result, header_left, header_right, left_base=fn.addr, width=args.width,
                              color=color, show_bytes=args.bytes, only_diffs=args.only_diffs))
        print(render.summary_line(result))
    return 0 if result.verdict in ("match", "match?") else 1


def cmd_list(args) -> int:
    target = Target()
    index = objfile.ObjectIndex.load_or_update(verbose=False) if (paths.DECOMP_BUILD / "compile_commands.json").is_file() else None
    found = target.lookup(args.query) if args.query else target.functions
    if args.quality:
        found = [fn for fn in found if fn.quality in args.quality]
    for fn in found[: args.limit]:
        built = "" if index is None else (" obj" if fn.name and index.find(fn.name) else "    ")
        print(f"{fn.addr:#x} {fn.quality} {fn.size:6d}{built} {demangle(fn.display)}")
    if len(found) > args.limit:
        print(f"... {len(found) - args.limit} more")
    return 0


# --------------------------------------------------------------------------- check

_WORKER_TARGET: Optional[Target] = None


def _worker_init() -> None:
    global _WORKER_TARGET
    _WORKER_TARGET = Target()


def _check_object(job: Tuple[str, List[Tuple[str, int, int, int, int]]]):
    obj, funcs = job
    target = _WORKER_TARGET
    out = []
    try:
        of = objfile.ObjectFile(obj)
    except Exception as e:  # unreadable object: report every function in it
        return [(addr, "error", 0, {}, str(e)) for _name, addr, *_ in funcs]
    with of:
        for name, addr, shndx, value, size in funcs:
            fn = target.by_addr[addr]
            try:
                right = of.function(name, shndx, value, size)
                result = compare.compare(target.disasm(fn), right.insns)
                out.append((addr, result.verdict, result.score, result.counts, ""))
            except Exception as e:
                out.append((addr, "error", 0, {}, f"{type(e).__name__}: {e}"))
    return out


def cmd_check(args) -> int:
    target = Target()
    index = objfile.ObjectIndex.load_or_update()
    qualities = set(args.quality)
    selected = [fn for fn in target.functions if fn.quality in qualities and fn.name]
    if args.filter:
        low = args.filter.lower()
        selected = [fn for fn in selected if low in fn.name.lower() or low in demangle(fn.name).lower()]
    jobs: Dict[str, list] = defaultdict(list)
    missing = []
    for fn in selected:
        entry = index.find(fn.name)
        if entry is None:
            missing.append(fn)
            continue
        obj, (shndx, value, size, _w) = entry
        jobs[obj].append((fn.name, fn.addr, shndx, value, size))

    results: Dict[int, tuple] = {}
    with ProcessPoolExecutor(max_workers=args.jobs, initializer=_worker_init) as pool:
        for chunk in pool.map(_check_object, jobs.items(), chunksize=4):
            for addr, verdict, score, counts, err in chunk:
                results[addr] = (verdict, score, counts, err)

    by_quality: Dict[str, Counter] = defaultdict(Counter)
    rows = []
    for fn in selected:
        if fn.addr in results:
            verdict, score, counts, err = results[fn.addr]
        else:
            verdict, score, counts, err = "missing", 0, {}, ""
        by_quality[fn.quality][verdict] += 1
        rows.append({"addr": f"{fn.addr:#x}", "quality": fn.quality, "size": fn.size, "name": fn.name,
                     "verdict": verdict, "score": score, "counts": counts, "error": err})

    verdicts = ["match", "match?", "data", "regswap", "mismatch", "missing", "error"]
    print(f"{'quality':<20}" + "".join(f"{v:>9}" for v in verdicts))
    for q in sorted(by_quality):
        label = f"{q} {QUALITY.get(q, '')}"
        print(f"{label:<20}" + "".join(f"{by_quality[q][v]:>9}" for v in verdicts))

    # Functions marked matching in the CSV that do not match are the interesting ones.
    suspicious = [r for r in rows if r["quality"] == "O" and r["verdict"] in ("mismatch", "regswap", "error")]
    improved = [r for r in rows if r["quality"] != "O" and r["verdict"] == "match"]
    if suspicious:
        print(f"\nmarked O but not matching ({len(suspicious)}):")
        for r in sorted(suspicious, key=lambda r: -r["score"])[: args.show]:
            print(f"  {r['addr']} {r['verdict']:<9} score={r['score']:<4} {demangle(r['name'])}")
    if improved:
        print(f"\nmatching but not marked O ({len(improved)}):")
        for r in improved[: args.show]:
            print(f"  {r['addr']} {r['quality']} {demangle(r['name'])}")

    if args.json:
        Path(args.json).write_text(json.dumps(rows, indent=1))
        print(f"\nwrote {args.json}")
    if args.html_dir:
        _write_report(Path(args.html_dir), target, index, rows, args.html_limit)
    return 0


def _write_report(out: Path, target: Target, index: objfile.ObjectIndex, rows: List[dict], limit: int) -> None:
    out.mkdir(parents=True, exist_ok=True)
    order = {"error": 0, "mismatch": 1, "regswap": 2, "data": 3, "match?": 4, "missing": 5, "match": 6}
    rows = sorted(rows, key=lambda r: (order.get(r["verdict"], 9), r["quality"] != "O", -r["score"]))
    lines = ["<!doctype html><html><head><meta charset='utf-8'><title>botw diff report</title>",
             "<style>body{font:13px ui-monospace,Menlo,monospace;margin:16px}td{padding:1px 8px}"
             "tr:nth-child(even){background:rgba(127,127,127,.08)}</style></head><body>",
             "<table><tr><th>address</th><th>csv</th><th>verdict</th><th>score</th><th>function</th></tr>"]
    written = 0
    for r in rows:
        name = html.escape(demangle(r["name"]))
        link = name
        if r["verdict"] in ("mismatch", "regswap", "data", "match?") and written < limit:
            fn = target.by_addr[int(r["addr"], 16)]
            left, right, result = _diff_one(target, index, fn)
            if result is not None:
                page = f"{fn.addr:x}.html"
                source = index.sources.get(right.obj, right.obj)
                (out / page).write_text(render.html_page(
                    result, demangle(fn.name), f"original {fn.addr:#x}", f"decomp {Path(source).name}",
                    [fn.name, f"quality: {fn.quality}", f"source: {source}"], left_base=fn.addr))
                link = f"<a href='{page}'>{name}</a>"
                written += 1
        lines.append(f"<tr><td>{r['addr']}</td><td>{r['quality']}</td><td>{r['verdict']}</td>"
                     f"<td>{r['score']}</td><td>{link}</td></tr>")
    lines.append("</table></body></html>")
    (out / "index.html").write_text("\n".join(lines))
    print(f"wrote {out / 'index.html'} ({written} diff pages)")


# --------------------------------------------------------------------------- verify


def cmd_verify(args) -> int:
    from . import verify

    target = Target()
    ok_hash = verify.check_hash()
    print(f"{paths.TARGET_NSO}: sha256 {'matches' if ok_hash else 'DOES NOT match'} v1.5.0")
    if args.functions:
        fns = [_pick(target, q) for q in args.functions]
    else:
        fns = [fn for fn in target.functions if fn.quality in args.quality]
        if args.limit:
            fns = fns[: args.limit]
    reports = verify.verify(target, fns, llvm=not args.no_llvm)
    words = sum(r.words for r in reports)
    bad_bytes = [r for r in reports if r.byte_mismatches]
    bad_llvm = [r for r in reports if r.llvm_mismatches]
    for r in reports if args.functions else []:
        fn = r.fn
        print(f"{fn.addr:#x} {demangle(fn.display)}")
        print(f"  file offset {r.file_offset:#x}, {r.words} words  "
              f"(xxd -s {r.file_offset:#x} -l {fn.size} {paths.TARGET_NSO})")
    for r in (bad_bytes + bad_llvm)[: args.show]:
        for off, fw, dw in r.byte_mismatches[:5]:
            print(f"  BYTES {r.fn.addr + off:#x}: file {fw:08x} decoded {dw:08x}")
        for off, cs, lv in r.llvm_mismatches[:5]:
            print(f"  LLVM  {r.fn.addr + off:#x}: capstone '{cs}' llvm '{lv}'")
    print(f"{len(reports)} function(s), {words} instruction words: "
          f"{len(bad_bytes)} with byte mismatches, "
          + ("LLVM check skipped" if args.no_llvm else f"{len(bad_llvm)} where LLVM disagrees with capstone"))
    return 0 if ok_hash and not bad_bytes and not bad_llvm else 1


def main(argv: Optional[List[str]] = None) -> int:
    p = argparse.ArgumentParser(prog="botwdiff", description=__doc__)
    sub = p.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("setup", help="prepare v1.5.0 target, download clang 4.0.1, configure the decomp build")
    s.add_argument("--nso", help=f"original main NSO (default: {paths.ORIGINAL_NSO})")
    s.add_argument("--build", action="store_true", help="also compile all objects")
    s.add_argument("-j", "--jobs", type=int)
    s.set_defaults(func=cmd_setup)

    s = sub.add_parser("build", help="compile decomp objects (no link) and refresh the symbol index")
    s.add_argument("targets", nargs="*", help="ninja object targets (default: all)")
    s.add_argument("-j", "--jobs", type=int)
    s.set_defaults(func=cmd_build)

    s = sub.add_parser("clangd", help="write compile_commands.json for scratch/ sources (clangd)")
    s.set_defaults(func=lambda args: print(f"wrote {build.write_scratch_compdb()}"))

    s = sub.add_parser("list", help="search functions in uking_functions.csv")
    s.add_argument("query", nargs="?")
    s.add_argument("-q", "--quality", help="filter by quality letters, e.g. OmM")
    s.add_argument("-n", "--limit", type=int, default=50)
    s.set_defaults(func=cmd_list)

    s = sub.add_parser("diff", help="side-by-side diff of one function")
    s.add_argument("function", help="mangled name, address (0x71... or offset), or (part of) demangled name")
    s.add_argument("--no-build", action="store_true", help="do not rebuild the object first")
    s.add_argument("--html", help="write an HTML page instead of printing")
    s.add_argument("--print", action="store_true", help="print even when --html is given")
    s.add_argument("-d", "--only-diffs", action="store_true", help="only show differing rows with context")
    s.add_argument("-b", "--bytes", action="store_true", help="show instruction words")
    s.add_argument("-w", "--width", type=int, help="total output width")
    s.add_argument("--mangled", action="store_true")
    s.add_argument("--no-color", action="store_true")
    s.add_argument("-s", "--symbol", help="decomp symbol to compare against (default: the CSV name)")
    s.add_argument("--source", help="compile this .cpp outside the decomp build and compare against it")
    s.add_argument("--like", help="with --source: reuse compile flags of the decomp source ending with this path")
    s.set_defaults(func=cmd_diff)

    s = sub.add_parser("verify", help="check decoded original instructions against the NSO bytes and LLVM")
    s.add_argument("functions", nargs="*", help="functions to verify (default: all with --quality)")
    s.add_argument("-q", "--quality", default="OmMWUL", help="CSV quality letters when no functions are given")
    s.add_argument("-n", "--limit", type=int, help="verify only the first N selected functions")
    s.add_argument("--no-llvm", action="store_true", help="only compare bytes, skip the LLVM disassembly check")
    s.add_argument("--show", type=int, default=20, help="how many failing functions to print")
    s.set_defaults(func=cmd_verify)

    s = sub.add_parser("check", help="compare many functions and summarize")
    s.add_argument("-q", "--quality", default="OmMW", help="CSV quality letters to check (default OmMW)")
    s.add_argument("-f", "--filter", help="substring of the (demangled) name")
    s.add_argument("-j", "--jobs", type=int)
    s.add_argument("--show", type=int, default=30, help="how many functions to list per section")
    s.add_argument("--json", help="write per-function results")
    s.add_argument("--html-dir", help="write an index and per-function diff pages")
    s.add_argument("--html-limit", type=int, default=500, help="max diff pages to write")
    s.set_defaults(func=cmd_check)

    args = p.parse_args(argv)
    return args.func(args) or 0
