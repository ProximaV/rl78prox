# rl78emu & rl78dbg — Renesas RL78 Emulator and Native IDA Pro 9.5 Debugger

`rl78emu` is a cycle-and-register-accurate C++17 emulator for the **Renesas RL78** architecture (`RL78-S1`, `RL78-S2`, `RL78-S3` cores and `RL78/G13` peripheral suite) modeled after `k0emu`, together with **`rl78dbg.dll`**, a native in-process **IDA Pro 9.5** `debugger_t` plugin tailored for RL78 firmware databases (including the companion [`rl78` processor module](../../module/rl78/README.md)).

## Architecture Overview

- **20-bit Unified Bus (`Rl78Bus`)**: Full 1 MB (`0x00000..0xFFFFF`) address space with Code Flash (`0x00000..0xEFFFF`), 2nd SFR region (`0xF0000..0xF07FF`), Data Flash (`0xF1000..0xF2FFF` gated by `DFLCTL.DFLEN`), Mirror ROM (`PMC.MAA` switching between `0x0xxxx` and `0x1xxxx`), Internal High-Speed RAM, 4 memory-mapped register banks (`RB3..RB0` at `0xFFEE0..0xFFEFF`), and 1st SFRs (`0xFFF00..0xFFFFF`).
- **Hardware-Accurate RL78 CPU Core (`Rl78Cpu`)**:
  - Supports **RL78-S1**, **RL78-S2**, and **RL78-S3** core profiles.
  - 20-bit `PC`, even-aligned 16-bit `SP` (`0xFFFF8`), `PSW` (`0xFFFFA`, reset `0x06` with `ISP1:ISP0 = 11`), `CS` (`0xFFFFC`), `ES` (`0xFFFFD`, reset `0x0F`), `PMC` (`0xFFFFE`), `MEM` (`0xFFFFF`), and `MACR` (`0xFFFF0..0xFFFF3`).
  - Complete instruction decoder across Map 1 (`0x00..0xFF`), Map 2 (`0x61`), Map 3 (`0x71`), Map 4 (`0x31`), `ES:` prefix (`0x11`), conditional skip propagation (`SKC`, `SKNC`, `SKZ`, `SKNZ`, `SKH`, `SKNH` including skipped `ES:` prefixes), and RL78-S3 extended math (`MULHU`, `MULH`, `DIVHU`, `DIVWU`, `MACHU`, `MACH`).
  - Exact 4-byte stack frames (`CALL`, `CALLT`, `RET`, `BRK`, Interrupt, `RETI`, `RETB`) and 2-byte `[SP+1]` `PUSH/POP PSW` semantics.
- **RL78/G13 Peripheral Suite (`rl78_peripherals.cpp`)**:
  - `Rl78Intc`: 54 maskable interrupt sources (`IF0..IF3L`, `MK0..MK3L`, `PR00..PR03L`, `PR10..PR13L`) with 4-level programmable priority (`ISP1:ISP0`) and 1-instruction interrupt hold.
  - `Rl78Clock`: `CMC`, `CSC`, `OSTC`, `OSTS`, `CKC`, `CKS0/1`, `PER0`, `OSMC`, `DFLCTL`, `RESF`, `LVIM`, `LVIS`.
  - `Rl78Wdt`: `WDTE` (`0xAC` kick) and Option Byte `0x000C0` configuration.
  - `Rl78Ports`: `P0..P15`, `PM*`, `PU*`, `PIM*`, `POM*`, `PMC*`, `EGP0/1`, `EGN0/1`, `KRM` with external pin injection & `INTP0..11`.
  - `Rl78Tau`: `TAU0` and `TAU1` (8 x 16-bit channels each).
  - `Rl78RtcIt`: 12-bit Interval Timer (`ITMC`) and BCD Real-Time Clock (`SEC..RTCC1`).
  - `Rl78Adc`, `Rl78Sau` (`SAU0`/`SAU1` with TX/RX FIFOs & loopback), `Rl78Iica` (`IICA0`/`IICA1`), `Rl78MulDiv` (`MDUC`), and 4-channel `Rl78Dma`.
  - `Rl78FlashCtrl`: Flash self-programming controller with `BECTL` (`0xFFFBE`), `PFCMD` (`0xFFFC0`) 3-step protection FSM for `FLPMC` (`0xFFFC4`) and `FLRST` (`0xF00C0`), `0xF0800..0xF080F` FSL parameter mailbox, `0x0EFFC0..0x0EFFFF` FSL ROM stub (`0x0EFFD0` flash size descriptor, `0x0EFFF8` entry handling `0x00` Init, `0x03` Erase, `0x04`/`0x17` Write, `0x06` IVerify, `0x08` BlankCheck, `0x09` GetBootFlag, `0x0A` InvertBootFlag), `BRK1` (`0xFF`) internal software reset (`RESF.IAWRF=0x80`) to swapped reset vector `[0x00000]`, and dual 4 KB boot-cluster swapping (`0x0000..0x0FFF` <-> `0x1000..0x1FFF`).

## Build Targets (`CMakeLists.txt`)

| Target | Output | Purpose |
| :--- | :--- | :--- |
| `rl78emu_core` | `rl78emu_core.lib` | Core RL78 CPU, 20-bit bus, peripherals, disassembler, GDB RSP server |
| `rl78emu` | `rl78emu.exe` | Standalone headless emulator & GDB RSP server |
| `rl78emu_tests` | `rl78emu_tests.exe` | C++ unit and integration test suite (`ctest`) |
| `rl78dbg` | `rl78dbg.dll` | Native IDA Pro 9.5 debugger plugin (`debugger_t`, `HT_IDD`/`HT_IDP`/`HT_UI`, `rl78dbg_*` IDC) |

## Quick Build

```powershell
cmake -S . -B build -G "Visual Studio 17 2022" -A x64
cmake --build build --config Release
ctest --test-dir build -C Release --output-on-failure
```

## Standalone Usage

```powershell
rl78emu.exe --rom firmware.bin --max-steps 10000 --trace
rl78emu.exe --rom firmware.bin --gdb --gdb-port 23946
```

## Native IDA Pro 9.5 Usage & IDC Functions

Copy `rl78dbg.dll` to `%APPDATA%\Hex-Rays\IDA Pro\plugins\rl78dbg.dll`. Opening any `rl78prox` / `rl78` IDB automatically selects the **rl78emu** debugger backend (`Debugger -> Select debugger -> rl78emu`).

CLI commands are available via IDA's debugger CLI (`rl78emu>`) or `rl78dbg_exec("...")`:
`status`, `banks`, `intc`, `clock`, `timers`, `ports`, `sau`, `adc`, `dma`, `flash [status|swap|boot <0|1|main|updater|start0|start1>|flmd0 <0|1>|erase <blk>]`, `map`, `disasm`, `step`, `reset`, `irq`, `pin`, `adcch`, `uartrx`, `uarttx`, `maa`.

Exposed IDC helpers: `rl78dbg_start()`, `rl78dbg_stop()`, `rl78dbg_step(n)`, `rl78dbg_run_to(addr, max_steps)`, `rl78dbg_get_reg(name)`, `rl78dbg_set_reg(name, val)`, `rl78dbg_read_u8(addr)`, `rl78dbg_write_u8(addr, val)`, `rl78dbg_read_u16(addr)`, `rl78dbg_write_u16(addr, val)`, `rl78dbg_add_bpt(addr)`, `rl78dbg_del_bpt(addr)`, `rl78dbg_exec(cmd)`, `rl78dbg_boot_swap()`.
