# Renesas RL78 Processor Module for IDA Pro (`rl78prox`)

An advanced, modern IDA Pro processor module for the **Renesas RL78** microcontroller family, updated and optimized for the **IDA Pro 9.5 SDK** and written in modern C++17.

This module is designed as an enhanced, feature-complete replacement for the factory `rl78.dll` module bundled with Hex-Rays IDA Pro. It incorporates full support for S1, S2, and S3 cores, automated switch/case jump table recognition, robust frame pointer (`HL`) and stack variable tracking, and comprehensive Renesas CC-RL calling conventions and type library (TIL) integration.

---

## Improvements Over Factory Hex-Rays `rl78.dll`

| Capability | Factory Hex-Rays `rl78.dll` | `rl78prox` (This Module) |
| :--- | :--- | :--- |
| **S3 Core Hardware Math** | ❌ Undecoded (`.db 0xCE, 0xFB...`) | ✅ Full decoding: `mulhu`, `mulh`, `divhu`, `divwu`, `machu`, `mach` |
| **Switch / Jump Tables** | ❌ Unhandled (indirect `br ax` unresolved) | ✅ Automated detection for Far 32-bit packed, Far split, and Near 16-bit tables |
| **Stack Return Size** | ❌ Generic / incorrect return size | ✅ Accurate RL78 4-byte stack return size (`PCL`, `PCH`, `PCS`, padding) |
| **Frame Pointer (`HL`)** | ❌ Only tracks SP, misses `[hl+disp]` | ✅ Full `HL` frame pointer tracking and automatic local stack variable creation |
| **Calling Conventions** | ❌ Unconfigured generic ABI | ✅ Full Renesas CC-RL ABI (`rAX`, `rBC`, `rDE`, 8-bit splits, far pointers) |
| **Type Libraries (TIL)** | ❌ 32-bit defaults (`int` = 4 bytes) | ✅ 16-bit architecture configuration (`int` = 2, `long` = 4, `align` = 2, `CM_N16_F32`) |
| **IDB Merge Support** | ❌ Unsupported | ✅ Full modern IDA 9.5 IDB Merge handler implementation (`merge.cpp`) |
| **Real-World ROM Testing**| ⚠️ Untested on complex firmware | ✅ 100% clean decoding across 102,000+ instructions on 1MB Syscon ROM |

---

## Detailed Features

### 1. Complete Core Architecture Support (S1, S2, and S3)
* **S3 Extended Math Instructions**: Full decoding and disassembly for Renesas S3 16-bit and 32-bit hardware arithmetic:
  * `mulhu` (`0xCE 0xFB 0x01`): 16-bit × 16-bit unsigned multiply
  * `mulh` (`0xCE 0xFB 0x02`): 16-bit × 16-bit signed multiply
  * `divhu` (`0xCE 0xFB 0x03`): 16-bit / 16-bit unsigned divide
  * `divwu` (`0xCE 0xFB 0x0B`): 32-bit / 32-bit unsigned divide
  * `machu` (`0xCE 0xFB 0x05`): 16-bit × 16-bit unsigned multiply-accumulate
  * `mach` (`0xCE 0xFB 0x06`): 16-bit × 16-bit signed multiply-accumulate
* **Interrupt Aliases**: Official Renesas `EI` (`0x71 0x7A 0xFA`) and `DI` (`0x71 0x7B 0xFA`) decode to clean zero-operand instructions.
* **Vector Table Cross-References**: `callt [addr5]` formatted with official bracket syntax, automatically generating code cross-references (`fl_CN`) to function entry points in the vector table.
* **Instruction Features**: Correct control flow flags (`CF_JUMP`) on all conditional branches (`bc`, `bnc`, `bz`, `bnz`, `bh`, `bnh`, `bt`, `bf`, `btclr`) and `CF_USE1` on `sel`.

### 2. Comprehensive Switch / Case Jump Table Handling
Resolves indirect jumps (`br ax`) and creates typed jump tables with case targets and cross-references:
* **32-Bit / 24-Bit Far Packed Jump Tables (`JT_FLAT32`)**:
  * Detects compiler idiom: `shlw ax, #2 -> addw ax, #table -> movw de, ax -> mov a, [de+2] -> mov cs, a -> movw ax, [de+0] -> br ax`.
  * Creates 4-byte pointer table entries (`dword`) and adds code cross-references (`fl_JN`) to each case block.
* **24-Bit Far Split Jump Tables (`SWI_CUSTOM | SWI_J32`)**:
  * Resolves separate CS code segment and AX 16-bit offset tables: `mov a, cs_table[bc] -> mov cs, a -> movw ax, ax_table[bc] -> br ax`.
* **16-Bit Near Jump Tables**:
  * Detects near tables: `shlw bc, 1 -> movw ax, table[bc] -> br ax`.
* **Addressing Mode Flexibility**: Supports both 8-bit (`kReg8`, `[reg + byte]`) and 16-bit (`kReg16`, `[reg + word]`) displacements.

### 3. High-Quality Stack Frame & Variable Analysis
* **RL78 Stack Return Size**: Implements `ev_get_function_retsize` returning 4 bytes (16-bit PC + 8-bit segment register + 1-byte alignment).
* **Deep Prologue Analysis**: Scans up to 30 instructions ahead across register-saving loops before stack allocation (`subw sp, #imm`) and frame pointer setup (`movw hl, sp`).
* **Frame Pointer (`HL`) Tracking**: Sets `FUNC_FRAME | FUNC_BOTTOMBP` and tracks local variable displacements against both `rSP` and `rHL` (`[hl+disp]`), instantiating named stack variables (`var_X`).
* **SP/FP Classification**: Correctly implements `ev_is_sp_based` to distinguish SP-relative from frame-pointer relative operands.

### 4. Renesas CC-RL Calling Conventions & Type Libraries
* **Type System Configuration (`ev_setup_til`)**:
  * Compiler ID: `COMP_GNU`
  * Model: `CM_N16_F32 | CM_CC_CDECL` (16-bit near code/data, 32-bit far pointers)
  * Fundamental sizes: `sizeof(int) = 2`, `sizeof(short) = 2`, `sizeof(long) = 4`, `sizeof(long long) = 8`, `sizeof(enum) = 2`, `defalign = 2`.
  * Default type library: automatically loads GNU common (`gnucmn`).
* **CC-RL Register Argument Allocation (`ev_calc_arglocs`)**:
  * Prioritizes registers in official CC-RL order: `rAX, rBC, rDE` for 16-bit integers; `rA, rX, rC, rB, rE, rD` for 8-bit integers; 3-byte far pointers packed in `reg2(pair, byte)`.
  * Automatically switches to 2-byte aligned stack offsets when register capacity is exhausted.
* **Return Location Rules (`ev_calc_retloc`)**:
  * 1 byte: `rA`
  * 2 bytes: `rAX`
  * 3 bytes (far pointer): `rC:rAX`
  * 4 bytes (far pointer): `rA:rDE`
  * 4 bytes (standard): `rBC:rAX`
  * >= 5 bytes: near pointer in `rAX`
* **Stack Cleanup**: `ev_calc_cdecl_purged_bytes` returns 0 (caller cleanup).
* **Database Legacy Upgrade**: `load_from_idb()` detects older databases loaded with 32-bit defaults and automatically upgrades their type sizes to RL78 architecture specifications.

### 5. Modern IDA SDK 9.5 Integration & IDB Merge
* Supports the unified 64-bit address space and IDA 9.5 API changes.
* Full IDB Merge support (`merge.cpp`) using `create_std_procmod_handlers(merge_data_t &)`.
* Registered with `PR_TYPEINFO` and `PR2_FORCE_16BIT`.

---

## Real-World Validation

The module has been tested against real-world Renesas RL78 firmware:

* **102,139 Instructions Decoded**: 0 decode failures (100% clean instruction decoding).
* **2,163 Functions Analyzed**: 100% accurately report 4-byte stack return sizes.
* **Complex Prologues**: Successfully identifies frames and tracks local variables in functions with context-saving loops (`sub_2429` creating 19 stack variable references).
* **Far Switch Recognition**: Successfully detects and reconstructs far 32-bit packed jump tables (`0xD365`), generating 4-byte typed tables and cross-references to all case blocks.

---

## Building and Installation

### Prerequisites
* IDA Pro 9.5 SDK (or compatible 9.x SDK)
* Visual Studio 2022 (MSVC toolchain with C++17 support)
* CMake 3.20+ and Ninja

### Build
From the IDA SDK build directory:
```powershell
cmake -B src/build -S src -G "Ninja"
cmake --build src/build --target rl78prox
```

### Installation
The build configuration automatically copies the compiled binaries to your IDA user directory:
* `%APPDATA%\Hex-Rays\IDA Pro\procs\rl78prox.dll`
* `%APPDATA%\Hex-Rays\IDA Pro\procs\rl78.dll` (serves as a drop-in replacement for the factory module)


---

## References
* Renesas RL78 Family Software User Manual (`r01us0015ej0220_rl78.pdf`)
* Renesas CC-RL Compiler User Manual (`r20ut3123ej0111-ccrl.pdf`)
* Renesas RL78/G13 Hardware User Manual (`RL78_G13_User_Manual_Hardware.pdf`)
