# botw-analysis

Side-by-side AArch64 comparison of functions in the *Breath of the Wild* executable against the
[zeldaret/botw](https://github.com/zeldaret/botw) decompilation in `../botw-code`.

The decompilation targets v1.5.0. `setup` decompresses the shipped v1.9.0 `main` NSO and applies the
project's published xdelta3 downgrade patch. It then checks the result against the v1.5.0 hash that
`botw-code/tools/setup.py` uses. The decompilation is compiled with Clang 4.0.1 through CMake,
Ninja and ccache. Only object files are built, because the comparison reads code and relocations
straight from each object, so no linker is needed.

## Requirements

- Python 3.9 or newer. The packages in [requirements.txt](requirements.txt) install with pip
- `cmake` 3.30 or newer, `ninja`, `ccache` (optional) and `xdelta3` on `PATH`
- `../botw-code` checked out with submodules (`git submodule update --init --recursive`)
- On Apple silicon, Rosetta 2. LLVM published Clang 4.0.1 for macOS as x86-64 only

## Setup

```sh
./botwdiff.sh setup --build
```

On first run, [botwdiff.sh](botwdiff.sh) creates `.venv` and installs the requirements. You can also
do this yourself with `python3 -m venv .venv && .venv/bin/pip install -r requirements.txt`, then run
`.venv/bin/python -m botwdiff ...`.

`setup` does the following:

1. Reads `../botw/01007EF00011E000_build/mac15/extract/v1114112/ExeFS/main`. Pass `--nso PATH` to
   use another 1.5.0, 1.6.0 or 1.9.0 NSO.
2. Writes `build/target/main.v150.nso`. The patch download is cached next to it.
3. Downloads Clang 4.0.1 into `toolchain/clang-4.0.1`.
4. Configures `build/decomp` with the decomp's `ToolchainNX64.cmake`.
5. With `--build`, compiles every object and indexes the function symbols.

After you edit decomp sources, run `./botwdiff.sh build`. `diff` rebuilds the one object it needs
automatically.

## Usage

```sh
# Find functions by mangled name, demangled substring or address
./botwdiff.sh list PauseMenuDataMgr::addToPouch
./botwdiff.sh list -q mM Actor          # filter by CSV quality letters
./botwdiff.sh list -a 0x7100c80000 -n 20   # 20 functions from an address (or offset 0xc80000)

# Side-by-side diff in the terminal. Rebuilds the object first unless --no-build is given
./botwdiff.sh diff 0x710096f268
./botwdiff.sh diff _ZN5uking2ai12AirOctaFlyUp11loadParams_Ev -d   # only differing rows + context
./botwdiff.sh diff "ActionEx::checkDerivedRuntimeTypeInfo" -b     # also show instruction words

# Standalone HTML page
./botwdiff.sh diff 0x710096f268 --html build/addToPouch.html

# Compare every decompiled function and summarize by CSV quality
./botwdiff.sh check
./botwdiff.sh check -q O --json build/check.json
./botwdiff.sh check -q mM --html-dir build/report     # index.html + one page per mismatch
```

A function can be named by its mangled name, an address (`0x71...` or an offset from the module
base), its exact demangled name or a substring. If several functions match, the command lists them
and asks you to be more specific.

`diff` exits with 0 for `match` and `match?`, 1 for any other verdict and 2 if the function was not
found in the compiled objects.

## Verify the original side against the NSO

```sh
./botwdiff.sh verify 0x710096f268          # one or more functions; prints file offset + xxd command
./botwdiff.sh verify                       # every function in uking_functions.csv
./botwdiff.sh verify -q O --no-llvm        # bytes only, O functions only
```

`verify` performs three independent checks:

1. `build/target/main.v150.nso` still has the v1.5.0 SHA-256 from `botw-code/tools/setup.py`.
2. Every instruction word shown on the left is read again from the NSO file at its file offset
   (`segment.file_offset + addr - 0x7100000000 - segment.mem_offset`), without the image loader,
   and compared with the decoded word. You can check any function by hand with the printed
   `xxd -s <offset> -l <size>` command.
3. All words are wrapped in `.inst` directives, assembled by Clang 4.0.1 and disassembled by its
   `llvm-objdump`. LLVM must agree with capstone on the mnemonic and registers of every
   instruction. Two LLVM 4 alias spellings count as equal: `orr wN, wzr, #imm` for `mov wN, #imm`,
   and `ins` for `mov v.T[i], v.T[j]`.

At `botw-code` `4b2694e2`, all 113,491 functions passed: 6,291,627 words, with no byte mismatches
and no LLVM disagreements. The full run takes about 100 seconds.

## Add a new function and compare it

Functions marked `U` in the CSV are not decompiled yet. `diff` still shows the original side for
them:

```sh
./botwdiff.sh list -q U PlacementActors::
./botwdiff.sh diff _ZN4ksys3map15PlacementActors14getStaticObj_0Ei
```

### Option A: scratch file, botw-code untouched

Write a `.cpp` file anywhere. [scratch/example_getStaticObj_0.cpp](scratch/example_getStaticObj_0.cpp)
is an example. Then compile it with the exact flags of an existing decomp source and compare:

```sh
./botwdiff.sh diff _ZN4ksys3map15PlacementActors14getStaticObj_0Ei \
    --source scratch/example_getStaticObj_0.cpp --like Map/mapPlacementActors.cpp
```

`--like` selects whose compile command to copy: include paths, defines, `-O3`, `-mcpu` and so on.
Without it, the tool uses a source from the same directory, or any game source. The object goes
to `build/scratch/`. If the CSV name differs from your function's mangled name, pass
`--symbol <mangled>`. If the file defines exactly one function, it is picked automatically.
The example above matches all 8 instructions.

For clangd, `setup`, `diff --source` and `./botwdiff.sh clangd` write `compile_commands.json`
in this directory with an entry per `scratch/**/*.cpp`, which `.clangd` points at. New files in
`scratch/` get their flags from neighbouring entries until it is regenerated.

### Option B: inside botw-code

1. Implement the function in the right source file in `../botw-code/src/...`. If the file is new,
   add it to that directory's `CMakeLists.txt` under `target_sources(uking PRIVATE ...)`.
2. Run `./botwdiff.sh diff <function>`. It rebuilds the function's object with Ninja and ccache,
   or the whole tree if the symbol is not indexed yet. CMake reconfigures itself when a
   `CMakeLists.txt` changed. Then iterate on the source until the verdict is `match`.
3. Update the function's row in `../botw-code/data/uking_functions.csv`: set the quality to `O`
   (or `m`/`M`/`W`) and the name to the mangled symbol. `diff` looks up the decomp side by that
   name. Until you update the row, pass `--symbol` to `diff`.
4. Run `./botwdiff.sh check` to make sure the other functions in the file still match.

## How the comparison works

The original instructions come from the v1.5.0 image. The function boundaries come from
`botw-code/data/uking_functions.csv`. Decomp instructions come from each function's section in its
object. Instructions that the linker fills in are rendered by what they reference, not by raw
encodings, so the two sides can be compared directly:

| Original side | Decomp side | Shown as |
| --- | --- | --- |
| `bl`/`b` target address, named via the function CSV, `data_symbols.csv`, dynsym or PLT stubs | `R_AARCH64_CALL26` / `JUMP26` symbol | `bl _ZN...` |
| `adrp` + `ldr` from a `.got` slot, named by its `GLOB_DAT`/`JUMP_SLOT` relocation | `ADR_GOT_PAGE` + `LD64_GOT_LO12_NC` | `sym@GOTPAGE`, `[xN, sym@GOTPAGEOFF]` |
| `adrp` + `add`/load/store pair | `ADR_PREL_PG_HI21` + `*_LO12` | `sym@PAGE`, `sym@PAGEOFF` |
| C string in `.rodata` | reference into a `SHF_STRINGS` section | `"text"` |
| Floating-point literal | reference into a read-only constant section | `=0x3f800000` |
| Branch inside the function | branch inside the function | `.L<offset>` |

Rows are aligned by mnemonic with `difflib`, then each row is classified:

| Mark | Kind | Meaning |
| :---: | --- | --- |
| ` ` | match | Identical after normalization. C1/C2 and D1/D2 structor aliases count as equal. So does a demangled CSV name that matches the decomp symbol |
| `?` | reloc | Same instruction, but the original reference has no known name, such as a guard variable or a local static. Within one function, each unnamed address must map to exactly one decomp symbol. If it does not, the row becomes `s` |
| `d` | data | Same code, different string or constant. This is usually a typo in a string literal |
| `s` | symbol | Same instruction referencing a different symbol |
| `r` | regswap | Same instruction modulo register allocation |
| `\|` | diff | Different instruction |
| `<` / `>` | left / right | Instruction exists only in the original or only in the decomp |

From those rows, each function gets one of these verdicts:

- `match`: every row matches.
- `match?`: matches apart from references that could not be named.
- `data`: the code matches but a literal differs.
- `regswap`: registers differ, otherwise the code is the same.
- `mismatch`: at least one row is `s`, `|`, `<` or `>`.

## Results

At `botw-code` commit `4b2694e2`, with every object built:

| CSV quality | match | match? | data | regswap | mismatch |
| --- | ---: | ---: | ---: | ---: | ---: |
| O matching | 18,991 | 13,470 | 14 | 0 | 63 |
| m minor mismatch | 0 | 1 | 0 | 10 | 164 |
| M major mismatch | 0 | 0 | 0 | 2 | 2,177 |
| W wip | 0 | 0 | 0 | 0 | 7,588 |

The 63 `O` functions this tool reports as mismatching mostly fall into three groups:

- Template instances that the original linker merged with identical code folding, so the CSV
  address holds a different instantiation. The `agl::utl::Parameter<T>::clone` family is one example.
- Callees that the CSV names with informal names such as `hkpMotion::ctor`.
- Real differences the project tolerates, such as `glslc*` function-pointer getters.

## Layout

| Path | Purpose |
| --- | --- |
| [botwdiff/prepare.py](botwdiff/prepare.py) | Hash check, LZ4 decompression, xdelta3 downgrade |
| [botwdiff/nso.py](botwdiff/nso.py) | NSO parsing, dynamic relocations, GOT/PLT naming |
| [botwdiff/build.py](botwdiff/build.py) | Clang 4.0.1 download, CMake configure, Ninja object builds |
| [botwdiff/objfile.py](botwdiff/objfile.py) | Object symbol index (`build/objindex.json`) and relocation reading |
| [botwdiff/disasm.py](botwdiff/disasm.py) | Capstone disassembly and symbolic operand rendering |
| [botwdiff/compare.py](botwdiff/compare.py) | Alignment and row classification |
| [botwdiff/render.py](botwdiff/render.py) | Terminal and HTML side-by-side output |
| [botwdiff/verify.py](botwdiff/verify.py) | NSO byte and LLVM cross-checks for the original side |
| [botwdiff/cli.py](botwdiff/cli.py) | `setup`, `build`, `list`, `diff`, `check` and `verify` commands |

These environment variables override the default paths: `BOTW_NSO`, `BOTW_DECOMP`,
`BOTW_ANALYSIS_WORK`, `BOTW_ANALYSIS_TOOLCHAIN` and `UKING_CLANG`.

Game files and derived binaries stay under `build/`, which is ignored by Git, so nothing from the
game is committed.
