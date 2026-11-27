"""Default locations. Every path can be overridden with an environment variable."""

from __future__ import annotations

import os
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
NS = ROOT.parent


def _env_path(name: str, default: Path) -> Path:
    value = os.environ.get(name)
    return Path(value).expanduser().resolve() if value else default


# Compressed v1.9.0 main NSO extracted from the update NSP.
ORIGINAL_NSO = _env_path(
    "BOTW_NSO",
    NS / "botw" / "01007EF00011E000_build" / "mac15" / "extract" / "v1114112" / "ExeFS" / "main",
)
# Checkout of https://github.com/zeldaret/botw
DECOMP = _env_path("BOTW_DECOMP", NS / "botw-code")

WORK = _env_path("BOTW_ANALYSIS_WORK", ROOT / "build")
TARGET_DIR = WORK / "target"
TARGET_NSO = TARGET_DIR / "main.v150.nso"
DECOMP_BUILD = WORK / "decomp"
OBJ_INDEX = WORK / "objindex.json"

TOOLCHAIN = _env_path("BOTW_ANALYSIS_TOOLCHAIN", ROOT / "toolchain")
CLANG_DIR = _env_path("UKING_CLANG", TOOLCHAIN / "clang-4.0.1")


def functions_csv() -> Path:
    return DECOMP / "data" / "uking_functions.csv"


def data_symbols_csv() -> Path:
    return DECOMP / "data" / "data_symbols.csv"
