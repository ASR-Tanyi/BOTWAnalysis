"""Default locations. Every path can be overridden with an environment variable."""

from __future__ import annotations

import os
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
EXTERNAL = ROOT / "external"


def _env_path(name: str, default: Path) -> Path:
    value = os.environ.get(name)
    return Path(value).expanduser().resolve() if value else default


# main NSO from the game's ExeFS (1.5.0, 1.6.0 or 1.9.0), supplied by the user.
ORIGINAL_NSO = _env_path("BOTW_NSO", EXTERNAL / "ExeFS" / "main")
# Submodule checkout of https://github.com/zeldaret/botw
DECOMP = _env_path("BOTW_DECOMP", EXTERNAL / "botw")

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
