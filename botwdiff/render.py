"""Side-by-side output for the terminal and as standalone HTML."""

from __future__ import annotations

import html
import shutil
from typing import List, Optional

from . import compare as C
from .disasm import Insn

_ANSI = {
    C.MATCH: "",
    C.RELOC: "\x1b[36m",
    C.DATA: "\x1b[34m",
    C.SYMBOL: "\x1b[35m",
    C.REGSWAP: "\x1b[33m",
    C.DIFF: "\x1b[31m",
    C.LEFT_ONLY: "\x1b[31m",
    C.RIGHT_ONLY: "\x1b[32m",
}
_MARK = {
    C.MATCH: " ", C.RELOC: "?", C.DATA: "d", C.SYMBOL: "s", C.REGSWAP: "r",
    C.DIFF: "|", C.LEFT_ONLY: "<", C.RIGHT_ONLY: ">",
}
_RESET = "\x1b[0m"
_DIM = "\x1b[2m"

LEGEND = ("' ' match   '?' same, reference unnamed on one side   'd' different string/constant   "
          "'s' different symbol   'r' register allocation   '|' different   '<' only original   '>' only decomp")


def _cell(insn: Optional[Insn], width: int, base: int, show_bytes: bool) -> str:
    if insn is None:
        return " " * width
    prefix = f"{base + insn.offset:x}: " if base else f"{insn.offset:5x}: "
    if show_bytes:
        prefix += f"{insn.word:08x} "
    text = prefix + insn.text
    if len(text) > width:
        text = text[: width - 1] + "~"
    return text.ljust(width)


def terminal(result: C.Result, header_left: str, header_right: str, *, left_base: int = 0,
             width: Optional[int] = None, color: bool = True, show_bytes: bool = False,
             only_diffs: bool = False, context: int = 3) -> str:
    total = width or shutil.get_terminal_size((200, 40)).columns
    col = max(30, (total - 3) // 2)
    lines = [f"{header_left[:col].ljust(col)} | {header_right[:col]}", "-" * min(total, col * 2 + 3)]
    rows = result.rows
    keep = [True] * len(rows)
    if only_diffs:
        bad = [i for i, r in enumerate(rows) if r.kind not in (C.MATCH, C.RELOC)]
        keep = [False] * len(rows)
        for i in bad:
            for k in range(max(0, i - context), min(len(rows), i + context + 1)):
                keep[k] = True
    skipped = False
    for i, row in enumerate(rows):
        if not keep[i]:
            if not skipped:
                lines.append((_DIM if color else "") + "   ..." + (_RESET if color else ""))
            skipped = True
            continue
        skipped = False
        left = _cell(row.left, col, left_base, show_bytes)
        right = _cell(row.right, col, 0, show_bytes)
        mark = _MARK[row.kind]
        if color and row.kind != C.MATCH:
            code = _ANSI[row.kind]
            lines.append(f"{code}{left}{_RESET} {code}{mark}{_RESET} {code}{right}{_RESET}")
        else:
            lines.append(f"{left} {mark} {right}".rstrip())
    return "\n".join(lines)


def summary_line(result: C.Result) -> str:
    c = result.counts
    parts = [f"{k}={c[k]}" for k in C.ROW_KINDS if c.get(k)]
    return (f"verdict: {result.verdict}  score: {result.score}  "
            f"size: {result.left_size:#x} vs {result.right_size:#x}  " + " ".join(parts))


_CSS = """
body{font:13px/1.35 ui-monospace,SFMono-Regular,Menlo,monospace;margin:16px;background:#fff;color:#111}
h1{font-size:15px;margin:0 0 4px}
.meta{color:#555;margin-bottom:10px;white-space:pre-wrap}
table{border-collapse:collapse;width:100%;table-layout:fixed}
td{padding:0 6px;white-space:pre;overflow:hidden;text-overflow:ellipsis;vertical-align:top}
td.off{color:#888;width:7em;text-align:right}
td.mk{width:1.2em;text-align:center;color:#555}
th{text-align:left;border-bottom:1px solid #ccc;padding:2px 6px}
tr.reloc td.i{background:#e6f7fb}
tr.data td.i{background:#e4e9fb}
tr.symbol td.i{background:#f6e8fb}
tr.regswap td.i{background:#fff6d6}
tr.diff td.i{background:#fde2e2}
tr.left td.l{background:#fde2e2}
tr.right td.r{background:#e2f6e2}
.legend span{padding:0 6px;margin-right:6px}
@media (prefers-color-scheme:dark){
 body{background:#111;color:#ddd} .meta{color:#999} th{border-color:#444}
 tr.reloc td.i{background:#0f3340} tr.data td.i{background:#1a2347} tr.symbol td.i{background:#35183f}
 tr.regswap td.i{background:#3d3300} tr.diff td.i,tr.left td.l{background:#4a1515}
 tr.right td.r{background:#123d12}}
"""


def _html_cells(insn: Optional[Insn], base: int, cls: str, show_bytes: bool) -> str:
    if insn is None:
        return f'<td class="off"></td><td class="i {cls}"></td>'
    off = f"{base + insn.offset:x}" if base else f"{insn.offset:x}"
    text = insn.text
    if show_bytes:
        text = f"{insn.word:08x}  {text}"
    return f'<td class="off">{off}</td><td class="i {cls}">{html.escape(text)}</td>'


def html_page(result: C.Result, title: str, header_left: str, header_right: str, meta: List[str],
              *, left_base: int = 0, show_bytes: bool = False) -> str:
    out = [
        "<!doctype html><html><head><meta charset='utf-8'>",
        f"<title>{html.escape(title)}</title><style>{_CSS}</style></head><body>",
        f"<h1>{html.escape(title)}</h1>",
        f"<div class='meta'>{html.escape(chr(10).join(meta))}\n{html.escape(summary_line(result))}</div>",
        "<div class='legend meta'>" + html.escape(LEGEND) + "</div>",
        "<table><colgroup><col style='width:7em'><col><col style='width:1.2em'>"
        "<col style='width:7em'><col></colgroup>",
        f"<tr><th></th><th>{html.escape(header_left)}</th><th></th><th></th>"
        f"<th>{html.escape(header_right)}</th></tr>",
    ]
    for row in result.rows:
        out.append(
            f"<tr class='{row.kind}'>"
            + _html_cells(row.left, left_base, "l", show_bytes)
            + f"<td class='mk'>{html.escape(_MARK[row.kind])}</td>"
            + _html_cells(row.right, 0, "r", show_bytes)
            + "</tr>")
    out.append("</table></body></html>")
    return "\n".join(out)
