"""Clang 4.0.1 download, CMake configuration and object-only Ninja builds of botw-code.

Objects are compared directly, so no linker (lld) is required.
"""

from __future__ import annotations

import json
import os
import platform
import shlex
import shutil
import subprocess
import tarfile
import tempfile
import urllib.request
from pathlib import Path
from typing import List, Optional

from . import paths

CLANG_BUILDS = {
    ("Darwin", "x86_64"): "clang+llvm-4.0.1-x86_64-apple-darwin",
    ("Darwin", "arm64"): "clang+llvm-4.0.1-x86_64-apple-darwin",  # runs under Rosetta 2
    ("Linux", "x86_64"): "clang+llvm-4.0.1-x86_64-linux-gnu-Fedora-25",
    ("Linux", "aarch64"): "clang+llvm-4.0.1-aarch64-linux-gnu",
}
CLANG_URL = "https://releases.llvm.org/4.0.1/{name}.tar.xz"


def setup_clang(dest: Path = paths.CLANG_DIR) -> Path:
    if (dest / "bin" / "clang++").exists():
        print(f"clang already set up: {dest}")
        return dest
    name = CLANG_BUILDS.get((platform.system(), platform.machine()))
    if name is None:
        raise SystemExit(f"no clang 4.0.1 build for {platform.system()} {platform.machine()}")
    url = CLANG_URL.format(name=name)
    dest.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(dir=dest.parent) as tmp:
        archive = Path(tmp) / "clang.tar.xz"
        print(f"downloading {url}")
        urllib.request.urlretrieve(url, archive)
        print("extracting clang")
        with tarfile.open(archive) as tar:
            top = {m.name.split("/", 1)[0] for m in tar.getmembers()}
            if len(top) != 1:
                raise SystemExit(f"unexpected archive layout: {sorted(top)}")
            members = [m for m in tar.getmembers() if "/bin/" in m.name or "/lib/clang/" in m.name
                       or "/include/c++/" in m.name or m.isdir()]
            kwargs = {"filter": "tar"} if hasattr(tarfile, "data_filter") else {}
            tar.extractall(tmp, members=members, **kwargs)
        Path(tmp, top.pop()).rename(dest)
    print(f"clang installed to {dest}")
    return dest


def _require(tool: str) -> str:
    path = shutil.which(tool)
    if path is None:
        raise SystemExit(f"{tool} not found in PATH")
    return path


def configure(build_dir: Path = paths.DECOMP_BUILD, clang: Path = paths.CLANG_DIR) -> None:
    if (build_dir / "build.ninja").is_file():
        print(f"build directory already configured: {build_dir}")
        return
    if not (clang / "bin" / "clang++").exists():
        raise SystemExit(f"clang 4.0.1 missing at {clang}; run `setup` first")
    toolchain = paths.DECOMP / "toolchain" / "ToolchainNX64.cmake"
    if not toolchain.is_file():
        raise SystemExit(f"{toolchain} missing (is botw-code checked out with submodules?)")
    cmd = [
        _require("cmake"), "-S", str(paths.DECOMP), "-B", str(build_dir), "-G", "Ninja",
        "-DCMAKE_BUILD_TYPE=RelWithDebInfo",
        f"-DCMAKE_TOOLCHAIN_FILE={toolchain}",
        # Only objects are built, so compiler checks must not try to link.
        "-DCMAKE_TRY_COMPILE_TARGET_TYPE=STATIC_LIBRARY",
        "-DCMAKE_EXPORT_COMPILE_COMMANDS=ON",
    ]
    if shutil.which("ccache"):
        cmd += ["-DCMAKE_C_COMPILER_LAUNCHER=ccache", "-DCMAKE_CXX_COMPILER_LAUNCHER=ccache"]
    env = dict(os.environ, UKING_CLANG=str(clang))
    _require("ninja")
    print(" ".join(cmd))
    subprocess.check_call(cmd, env=env)


def object_targets(build_dir: Path = paths.DECOMP_BUILD) -> List[str]:
    """All object outputs, as Ninja target paths relative to the build directory."""
    db = json.loads((build_dir / "compile_commands.json").read_text())
    outs = []
    for entry in db:
        out = entry.get("output")
        if out is None:
            continue
        p = Path(out)
        if p.is_absolute():
            p = p.relative_to(build_dir)
        outs.append(str(p))
    if outs:
        return outs
    text = subprocess.check_output([_require("ninja"), "-C", str(build_dir), "-t", "targets", "all"], text=True)
    return [line.split(":", 1)[0] for line in text.splitlines() if line.split(":", 1)[0].endswith(".o")]


def build_objects(targets: Optional[List[str]] = None, jobs: Optional[int] = None,
                  keep_going: bool = True, build_dir: Path = paths.DECOMP_BUILD) -> int:
    if not (build_dir / "build.ninja").is_file():
        raise SystemExit(f"{build_dir} is not configured; run `setup` first")
    targets = targets or object_targets(build_dir)
    cmd = [_require("ninja"), "-C", str(build_dir)]
    if jobs:
        cmd += ["-j", str(jobs)]
    if keep_going:
        cmd += ["-k", "0"]
    # Avoid exceeding the argument limit with thousands of targets.
    result = 0
    for i in range(0, len(targets), 1000):
        result = subprocess.call(cmd + targets[i : i + 1000]) or result
    return result


def compile_scratch(source: Path, like: Optional[str] = None, build_dir: Path = paths.DECOMP_BUILD) -> Path:
    """Compile a source file outside the decomp build with the flags of an existing decomp source.

    `like` selects the reference translation unit by path suffix (default: a source in the same
    directory as `source`, else any game source). Returns the object path.
    """
    source = source.resolve()
    db = json.loads((build_dir / "compile_commands.json").read_text())
    entry = None
    if like:
        cands = [e for e in db if e["file"].endswith(like)]
        if not cands:
            raise SystemExit(f"no decomp source ends with {like!r}")
        entry = cands[0]
    else:
        same_dir = [e for e in db if Path(e["file"]).parent == source.parent]
        game = [e for e in db if e["file"].startswith(str(paths.DECOMP / "src") + "/")]
        entry = (same_dir or game or db)[0]

    args = shlex.split(entry["command"])
    out = paths.WORK / "scratch" / (source.stem + ".o")
    out.parent.mkdir(parents=True, exist_ok=True)
    fixed: List[str] = []
    skip = False
    for i, arg in enumerate(args):
        if skip:
            skip = False
            continue
        if arg == "-o":
            fixed += ["-o", str(out)]
            skip = True
        elif arg == "-c":
            fixed += ["-c", str(source)]
            skip = True
        elif arg.startswith(("-MD", "-MT", "-MF")) or (i > 0 and args[i - 1] in ("-MT", "-MF")):
            continue
        else:
            fixed.append(arg)
    if shutil.which("ccache"):
        fixed.insert(0, shutil.which("ccache"))
    print(f"compiling {source} (flags of {Path(entry['file']).relative_to(paths.DECOMP)})")
    rc = subprocess.call(fixed, cwd=entry["directory"])
    if rc:
        raise SystemExit(rc)
    return out
