"""Turn the shipped NSO into the uncompressed v1.5.0 NSO that the decompilation targets."""

from __future__ import annotations

import hashlib
import shutil
import subprocess
import tempfile
import urllib.request
from pathlib import Path

from . import nso, paths

# Hashes from botw-code/tools/setup.py
UNCOMPRESSED_V150 = "d9fa308d0ee7c0ab081c66d987523385e1afe06f66731bbfa32628438521c106"
KNOWN = {
    "898dc199301f7c419be5144bb5cb27e2fc346e22b27345ba3fb40c0060c2baf8": ("1.5.0", True),
    UNCOMPRESSED_V150: ("1.5.0", False),
    "15cfca7b89348956f85d945fade2e215a6af5991ed1071e181f97ca72f7ae20b": ("1.6.0", True),
    "8a2fc8b1111a35a76fd2d53a8670599da4a7a9706a3d91215d30fd62149f00c1": ("1.6.0", False),
    "f6f0b20bb1f2b67d164c24871cd473147eef1d285f12e7bd492e3126c6022e27": ("1.9.0", True),
    "6a30c162a2e6f885e0b1c0a6673a84795549a5ccdec1de8d3a741168ac4cba86": ("1.9.0", False),
}
UNCOMPRESSED_BY_VERSION = {v: h for h, (v, c) in KNOWN.items() if not c}
PATCH_URL = "https://s.botw.link/v150_downgrade/{tag}_to_v150.patch"


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def prepare_target(original: Path, dest: Path = paths.TARGET_NSO) -> Path:
    if dest.is_file() and sha256(dest.read_bytes()) == UNCOMPRESSED_V150:
        print(f"target already prepared: {dest}")
        return dest
    if not original.is_file():
        raise SystemExit(f"NSO not found: {original}")

    data = original.read_bytes()
    digest = sha256(data)
    if digest not in KNOWN:
        raise SystemExit(f"unknown NSO {original} (sha256 {digest})")
    version, compressed = KNOWN[digest]
    print(f"found {'compressed' if compressed else 'uncompressed'} v{version} NSO")

    if compressed:
        data = nso.decompress(data)
        if sha256(data) != UNCOMPRESSED_BY_VERSION[version]:
            raise SystemExit("decompressed NSO does not match the expected hash")

    dest.parent.mkdir(parents=True, exist_ok=True)
    if version == "1.5.0":
        dest.write_bytes(data)
    else:
        if shutil.which("xdelta3") is None:
            raise SystemExit("xdelta3 is required to downgrade to v1.5.0 (brew install xdelta)")
        tag = "v" + version.replace(".", "")
        patch = dest.parent / f"{tag}_to_v150.patch"
        if not patch.is_file():
            url = PATCH_URL.format(tag=tag)
            print(f"downloading {url}")
            urllib.request.urlretrieve(url, patch)
        with tempfile.TemporaryDirectory() as tmp:
            src = Path(tmp) / f"{tag}.nso"
            src.write_bytes(data)
            print("applying xdelta3 downgrade patch")
            subprocess.check_call(["xdelta3", "-f", "-d", "-s", str(src), str(patch), str(dest)])

    if sha256(dest.read_bytes()) != UNCOMPRESSED_V150:
        dest.unlink()
        raise SystemExit("patched NSO does not match the v1.5.0 hash")
    print(f"wrote {dest}")
    return dest
