# Renesas RL78 for IDA Pro (`rl78` Processor Module + `rl78emu` Debugger)

A unified toolkit for reverse engineering, emulating, and debugging **Renesas RL78** (`RL78-S1`, `RL78-S2`, `RL78-S3`, `RL78/G13`) firmware in **IDA Pro 9.5**:

1. **`module/rl78`** ([`module/rl78/README.md`](module/rl78/README.md)) — Drop-in replacement `rl78.dll` processor module overriding the bundled Hex-Rays `rl78.dll` (`%IDAUSR%\procs\rl78.dll`) with S3 extended math, far/near switch recovery, `HL` stack frames, CC-RL ABI, TIL support, and IDB merge handlers.
2. **`plugins/rl78emu`** ([`plugins/rl78emu/README.md`](plugins/rl78emu/README.md)) — Cycle-and-register-accurate RL78 emulator (`rl78emu.exe`), C++ unit tests (`rl78emu_tests.exe`), GDB RSP server, and native in-process IDA Pro 9.5 debugger plugin (`rl78dbg.dll`) supporting RL78/G13 peripherals, `FSL` flash self-programming (`PFCMD` / `FLPMC`), dual boot-cluster swapping, and `BRK1` (`0xFF`) resets.
3. **`loaders/ps4syscon.py`** — IDA Python loader for PS4/Vita Syscon `FUPD` update images.
4. **`tests/run_comprehensive_validation.py`** — Real-world headless IDA validation suite for the `rl78` processor module.

---

## Repository Layout

```text
.
├── CMakeLists.txt                  # Unified CMake entry point (standalone or inside ida-sdk)
├── README.md
├── .gitignore
├── module/
│   └── rl78/                       # Improved RL78 processor module (builds rl78.dll)
├── plugins/
│   └── rl78emu/                    # RL78 emulator core, CLI, tests, and rl78dbg.dll plugin
├── loaders/
│   └── ps4syscon.py                # FUPD loader script
└── tests/
    └── run_comprehensive_validation.py
```

---

## Building & Deploying

### Option 1: Integrated Inside `ida-sdk` (`Ninja`)
From the `ida-sdk` root directory:
```powershell
cmake -B src/build -S src -G "Ninja"
cmake --build src/build --target rl78 rl78dbg rl78emu rl78emu_tests
```

### Option 2: Standalone Repository Build (Visual Studio 2022)
From this repository's root (pass `-DIDASDK=<path/to/ida-sdk/src>` if building outside `ida-sdk/src/module`):
```powershell
cmake -S . -B build -G "Visual Studio 17 2022" -A x64
cmake --build build --config Release
ctest --test-dir build -C Release --output-on-failure
```

To build only the standalone emulator & C++ tests without an IDA SDK, configure with `-DRL78_BUILD_PROCMOD=OFF`.

### Post-Build User Deployment
Release/Ninja builds automatically deploy the IDA components into `%APPDATA%\Hex-Rays\IDA Pro\`:
- Processor module: `%APPDATA%\Hex-Rays\IDA Pro\procs\rl78.dll` (loaded ahead of `<IDA>\procs\rl78.dll`)
- Debugger plugin: `%APPDATA%\Hex-Rays\IDA Pro\plugins\rl78dbg.dll`

---

## Verification

- **C++ Emulator & Flash/Boot-Swap Tests**:
  ```powershell
  ctest --test-dir build -C Release --output-on-failure
  ```
- **Headless IDA Processor Validation** (on a scratch `.i64` copy):
  ```powershell
  idat.exe -A -S"tests/run_comprehensive_validation.py" path/to/copy.i64
  ```
- **Headless IDA Debugger Validation** (on a scratch `.i64` copy):
  ```powershell
  idat.exe -A -S"plugins/rl78emu/tests/ida_headless_test.py" path/to/copy.i64
  ```
