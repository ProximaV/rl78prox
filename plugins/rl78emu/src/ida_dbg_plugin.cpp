#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <deque>
#include <string>
#include <thread>
#include <unordered_set>
#include <vector>

#include <ida.hpp>
#include <idp.hpp>
#include <dbg.hpp>
#include <idd.hpp>
#include <loader.hpp>
#include <bytes.hpp>
#include <segment.hpp>
#include <name.hpp>
#include <funcs.hpp>
#include <entry.hpp>
#include <expr.hpp>
#include <kernwin.hpp>
#include <ua.hpp>
#include <nalt.hpp>
#include <netnode.hpp>

#include "disasm.h"
#include "log.h"
#include "machine.h"
#include "module_path.h"

namespace {

constexpr pid_t kPid = 1;
constexpr thid_t kTid = 1;
constexpr uint32_t kDefaultCodeFlashEnd = 0x080000u;

const uchar kSoftBptBytes[1] = { 0xFFu };  // Non-intrusive virtual breakpoint (flash bytes remain untouched)

bool IsRl78Proc() {
    const char *proc0 = (PH.psnames != nullptr && PH.psnames[0] != nullptr) ? PH.psnames[0] : nullptr;
#ifdef PLFM_RL78
    if (PH.id == PLFM_RL78) {
        return true;
    }
#endif
    if (PH.id == 0x8078) {  // rl78prox custom processor module ID (0x8000 + 0x78)
        return true;
    }
    if (proc0 != nullptr &&
        (strieq(proc0, "rl78") || strieq(proc0, "rl78prox"))) {
        return true;
    }
    return false;
}

enum RegClassMask : uchar {
    RC_GENERAL = 1u << 0,
    RC_BANKS   = 1u << 1,
    RC_INTC    = 1u << 2,
    RC_SYS     = 1u << 3,
    RC_TIMERS  = 1u << 4,
};

const char *const kRegClasses[] = {
    "General registers",
    "Register banks",
    "Interrupt controller",
    "System & Clock",
    "Timers",
    nullptr
};

const char *const kPswBits[8] = {
    "PSW_CY", "PSW_ISP0", "PSW_ISP1", "PSW_RBS0", "PSW_AC", "PSW_RBS1", "PSW_Z", "PSW_IE"
};

const register_info_t kRegisters[] = {
    // General registers (RC_GENERAL)
    { "PC",     REGISTER_IP | REGISTER_ADDRESS, RC_GENERAL, dt_dword, nullptr, 0 },
    { "SP",     REGISTER_SP | REGISTER_ADDRESS, RC_GENERAL, dt_word,  nullptr, 0 },
    { "PSW",    0,                              RC_GENERAL, dt_byte,  kPswBits, 0xFFu },
    { "CS",     0,                              RC_GENERAL, dt_byte,  nullptr, 0 },
    { "ES",     0,                              RC_GENERAL, dt_byte,  nullptr, 0 },
    { "PMC",    0,                              RC_GENERAL, dt_byte,  nullptr, 0 },
    { "MEM",    0,                              RC_GENERAL, dt_byte,  nullptr, 0 },
    { "AX",     0,                              RC_GENERAL, dt_word,  nullptr, 0 },
    { "BC",     0,                              RC_GENERAL, dt_word,  nullptr, 0 },
    { "DE",     0,                              RC_GENERAL, dt_word,  nullptr, 0 },
    { "HL",     0,                              RC_GENERAL, dt_word,  nullptr, 0 },
    { "A",      0,                              RC_GENERAL, dt_byte,  nullptr, 0 },
    { "X",      0,                              RC_GENERAL, dt_byte,  nullptr, 0 },
    { "B",      0,                              RC_GENERAL, dt_byte,  nullptr, 0 },
    { "C",      0,                              RC_GENERAL, dt_byte,  nullptr, 0 },
    { "D",      0,                              RC_GENERAL, dt_byte,  nullptr, 0 },
    { "E",      0,                              RC_GENERAL, dt_byte,  nullptr, 0 },
    { "H",      0,                              RC_GENERAL, dt_byte,  nullptr, 0 },
    { "L",      0,                              RC_GENERAL, dt_byte,  nullptr, 0 },
    { "RB",     0,                              RC_GENERAL, dt_byte,  nullptr, 0 },
    { "CY",     0,                              RC_GENERAL, dt_byte,  nullptr, 0 },
    { "MACRL",  0,                              RC_GENERAL, dt_word,  nullptr, 0 },
    { "MACRH",  0,                              RC_GENERAL, dt_word,  nullptr, 0 },

    // Register banks (RC_BANKS)
    { "RB0_AX", 0,                              RC_BANKS,   dt_word,  nullptr, 0 },
    { "RB0_BC", 0,                              RC_BANKS,   dt_word,  nullptr, 0 },
    { "RB0_DE", 0,                              RC_BANKS,   dt_word,  nullptr, 0 },
    { "RB0_HL", 0,                              RC_BANKS,   dt_word,  nullptr, 0 },
    { "RB1_AX", 0,                              RC_BANKS,   dt_word,  nullptr, 0 },
    { "RB1_BC", 0,                              RC_BANKS,   dt_word,  nullptr, 0 },
    { "RB1_DE", 0,                              RC_BANKS,   dt_word,  nullptr, 0 },
    { "RB1_HL", 0,                              RC_BANKS,   dt_word,  nullptr, 0 },
    { "RB2_AX", 0,                              RC_BANKS,   dt_word,  nullptr, 0 },
    { "RB2_BC", 0,                              RC_BANKS,   dt_word,  nullptr, 0 },
    { "RB2_DE", 0,                              RC_BANKS,   dt_word,  nullptr, 0 },
    { "RB2_HL", 0,                              RC_BANKS,   dt_word,  nullptr, 0 },
    { "RB3_AX", 0,                              RC_BANKS,   dt_word,  nullptr, 0 },
    { "RB3_BC", 0,                              RC_BANKS,   dt_word,  nullptr, 0 },
    { "RB3_DE", 0,                              RC_BANKS,   dt_word,  nullptr, 0 },
    { "RB3_HL", 0,                              RC_BANKS,   dt_word,  nullptr, 0 },

    // Interrupt controller (RC_INTC)
    { "IF0L",   0,                              RC_INTC,    dt_byte,  nullptr, 0 },
    { "IF0H",   0,                              RC_INTC,    dt_byte,  nullptr, 0 },
    { "IF1L",   0,                              RC_INTC,    dt_byte,  nullptr, 0 },
    { "IF1H",   0,                              RC_INTC,    dt_byte,  nullptr, 0 },
    { "IF2L",   0,                              RC_INTC,    dt_byte,  nullptr, 0 },
    { "IF2H",   0,                              RC_INTC,    dt_byte,  nullptr, 0 },
    { "MK0L",   0,                              RC_INTC,    dt_byte,  nullptr, 0 },
    { "MK0H",   0,                              RC_INTC,    dt_byte,  nullptr, 0 },
    { "MK1L",   0,                              RC_INTC,    dt_byte,  nullptr, 0 },
    { "MK1H",   0,                              RC_INTC,    dt_byte,  nullptr, 0 },
    { "MK2L",   0,                              RC_INTC,    dt_byte,  nullptr, 0 },
    { "MK2H",   0,                              RC_INTC,    dt_byte,  nullptr, 0 },
    { "PR00L",  0,                              RC_INTC,    dt_byte,  nullptr, 0 },
    { "PR00H",  0,                              RC_INTC,    dt_byte,  nullptr, 0 },
    { "PR01L",  0,                              RC_INTC,    dt_byte,  nullptr, 0 },
    { "PR01H",  0,                              RC_INTC,    dt_byte,  nullptr, 0 },
    { "PR10L",  0,                              RC_INTC,    dt_byte,  nullptr, 0 },
    { "PR10H",  0,                              RC_INTC,    dt_byte,  nullptr, 0 },
    { "PR11L",  0,                              RC_INTC,    dt_byte,  nullptr, 0 },
    { "PR11H",  0,                              RC_INTC,    dt_byte,  nullptr, 0 },

    // System & Clock (RC_SYS)
    { "CMC",    0,                              RC_SYS,     dt_byte,  nullptr, 0 },
    { "CSC",    0,                              RC_SYS,     dt_byte,  nullptr, 0 },
    { "OSTC",   0,                              RC_SYS,     dt_byte,  nullptr, 0 },
    { "OSTS",   0,                              RC_SYS,     dt_byte,  nullptr, 0 },
    { "CKC",    0,                              RC_SYS,     dt_byte,  nullptr, 0 },
    { "PER0",   0,                              RC_SYS,     dt_byte,  nullptr, 0 },
    { "OSMC",   0,                              RC_SYS,     dt_byte,  nullptr, 0 },
    { "RESF",   0,                              RC_SYS,     dt_byte,  nullptr, 0 },
    { "LVIM",   0,                              RC_SYS,     dt_byte,  nullptr, 0 },
    { "LVIS",   0,                              RC_SYS,     dt_byte,  nullptr, 0 },
    { "WDTE",   0,                              RC_SYS,     dt_byte,  nullptr, 0 },
    { "DFLCTL", 0,                              RC_SYS,     dt_byte,  nullptr, 0 },
    { "MDUC",   0,                              RC_SYS,     dt_byte,  nullptr, 0 },
    { "BECTL",  0,                              RC_SYS,     dt_byte,  nullptr, 0 },
    { "PFCMD",  0,                              RC_SYS,     dt_byte,  nullptr, 0 },
    { "FLPMC",  0,                              RC_SYS,     dt_byte,  nullptr, 0 },
    { "FLRST",  0,                              RC_SYS,     dt_byte,  nullptr, 0 },
    { "CYCLES", REGISTER_READONLY,              RC_SYS,     dt_qword, nullptr, 0 },

    // Timers (RC_TIMERS)
    { "TCR00",  0,                              RC_TIMERS,  dt_word,  nullptr, 0 },
    { "TDR00",  0,                              RC_TIMERS,  dt_word,  nullptr, 0 },
    { "TCR01",  0,                              RC_TIMERS,  dt_word,  nullptr, 0 },
    { "TDR01",  0,                              RC_TIMERS,  dt_word,  nullptr, 0 },
    { "TCR02",  0,                              RC_TIMERS,  dt_word,  nullptr, 0 },
    { "TDR02",  0,                              RC_TIMERS,  dt_word,  nullptr, 0 },
    { "TCR03",  0,                              RC_TIMERS,  dt_word,  nullptr, 0 },
    { "TDR03",  0,                              RC_TIMERS,  dt_word,  nullptr, 0 },
    { "TE0",    0,                              RC_TIMERS,  dt_word,  nullptr, 0 },
    { "TPS0",   0,                              RC_TIMERS,  dt_word,  nullptr, 0 },
    { "ITMC",   0,                              RC_TIMERS,  dt_word,  nullptr, 0 },
};

enum RegBackingKind : uint8_t {
    BACK_PC = 0,
    BACK_SP,
    BACK_PSW,
    BACK_CS,
    BACK_ES,
    BACK_PMC,
    BACK_MEM,
    BACK_RP,
    BACK_R8,
    BACK_RB,
    BACK_CY,
    BACK_BANK_RP,
    BACK_SFR8,
    BACK_SFR16,
    BACK_CYCLES,
};

struct RegBackingDesc {
    RegBackingKind kind;
    uint32_t param0;
    uint8_t param1;
};

const RegBackingDesc kRegBacking[] = {
    // General registers
    { BACK_PC,      0,          0 },
    { BACK_SP,      0,          0 },
    { BACK_PSW,     0,          0 },
    { BACK_CS,      0,          0 },
    { BACK_ES,      0,          0 },
    { BACK_PMC,     0,          0 },
    { BACK_MEM,     0,          0 },
    { BACK_RP,      rl78::RP_AX, 0 },
    { BACK_RP,      rl78::RP_BC, 0 },
    { BACK_RP,      rl78::RP_DE, 0 },
    { BACK_RP,      rl78::RP_HL, 0 },
    { BACK_R8,      rl78::REG_A, 0 },
    { BACK_R8,      rl78::REG_X, 0 },
    { BACK_R8,      rl78::REG_B, 0 },
    { BACK_R8,      rl78::REG_C, 0 },
    { BACK_R8,      rl78::REG_D, 0 },
    { BACK_R8,      rl78::REG_E, 0 },
    { BACK_R8,      rl78::REG_H, 0 },
    { BACK_R8,      rl78::REG_L, 0 },
    { BACK_RB,      0,          0 },
    { BACK_CY,      0,          0 },
    { BACK_SFR16,   rl78::kMacrlAddress, 0 },
    { BACK_SFR16,   rl78::kMacrhAddress, 0 },

    // Register banks
    { BACK_BANK_RP, rl78::RP_AX, 0 },
    { BACK_BANK_RP, rl78::RP_BC, 0 },
    { BACK_BANK_RP, rl78::RP_DE, 0 },
    { BACK_BANK_RP, rl78::RP_HL, 0 },
    { BACK_BANK_RP, rl78::RP_AX, 1 },
    { BACK_BANK_RP, rl78::RP_BC, 1 },
    { BACK_BANK_RP, rl78::RP_DE, 1 },
    { BACK_BANK_RP, rl78::RP_HL, 1 },
    { BACK_BANK_RP, rl78::RP_AX, 2 },
    { BACK_BANK_RP, rl78::RP_BC, 2 },
    { BACK_BANK_RP, rl78::RP_DE, 2 },
    { BACK_BANK_RP, rl78::RP_HL, 2 },
    { BACK_BANK_RP, rl78::RP_AX, 3 },
    { BACK_BANK_RP, rl78::RP_BC, 3 },
    { BACK_BANK_RP, rl78::RP_DE, 3 },
    { BACK_BANK_RP, rl78::RP_HL, 3 },

    // Interrupt controller
    { BACK_SFR8,    0xFFFE0u,   0 },
    { BACK_SFR8,    0xFFFE1u,   0 },
    { BACK_SFR8,    0xFFFE2u,   0 },
    { BACK_SFR8,    0xFFFE3u,   0 },
    { BACK_SFR8,    0xFFFD0u,   0 },
    { BACK_SFR8,    0xFFFD1u,   0 },
    { BACK_SFR8,    0xFFFE4u,   0 },
    { BACK_SFR8,    0xFFFE5u,   0 },
    { BACK_SFR8,    0xFFFE6u,   0 },
    { BACK_SFR8,    0xFFFE7u,   0 },
    { BACK_SFR8,    0xFFFD4u,   0 },
    { BACK_SFR8,    0xFFFD5u,   0 },
    { BACK_SFR8,    0xFFFE8u,   0 },
    { BACK_SFR8,    0xFFFE9u,   0 },
    { BACK_SFR8,    0xFFFEAu,   0 },
    { BACK_SFR8,    0xFFFEBu,   0 },
    { BACK_SFR8,    0xFFFECu,   0 },
    { BACK_SFR8,    0xFFFEDu,   0 },
    { BACK_SFR8,    0xFFFEEu,   0 },
    { BACK_SFR8,    0xFFFEFu,   0 },

    // System & Clock
    { BACK_SFR8,    0xFFFA0u,   0 },
    { BACK_SFR8,    0xFFFA1u,   0 },
    { BACK_SFR8,    0xFFFA2u,   0 },
    { BACK_SFR8,    0xFFFA3u,   0 },
    { BACK_SFR8,    0xFFFA4u,   0 },
    { BACK_SFR8,    0xF00F0u,   0 },
    { BACK_SFR8,    0xF00F3u,   0 },
    { BACK_SFR8,    0xFFFA8u,   0 },
    { BACK_SFR8,    0xFFFA9u,   0 },
    { BACK_SFR8,    0xFFFAAu,   0 },
    { BACK_SFR8,    0xFFFABu,   0 },
    { BACK_SFR8,    0xF0090u,   0 },
    { BACK_SFR8,    0xF00E8u,   0 },
    { BACK_SFR8,    0xFFFBEu,   0 },
    { BACK_SFR8,    0xFFFC0u,   0 },
    { BACK_SFR8,    0xFFFC4u,   0 },
    { BACK_SFR8,    0xF00C0u,   0 },
    { BACK_CYCLES,  0,          0 },

    // Timers
    { BACK_SFR16,   0xF0180u,   0 },
    { BACK_SFR16,   0xFFF18u,   0 },
    { BACK_SFR16,   0xF0182u,   0 },
    { BACK_SFR16,   0xFFF1Au,   0 },
    { BACK_SFR16,   0xF0184u,   0 },
    { BACK_SFR16,   0xFFF64u,   0 },
    { BACK_SFR16,   0xF0186u,   0 },
    { BACK_SFR16,   0xFFF66u,   0 },
    { BACK_SFR16,   0xF01B0u,   0 },
    { BACK_SFR16,   0xF01B6u,   0 },
    { BACK_SFR16,   0xFFF90u,   0 },
};

static_assert(qnumber(kRegBacking) == qnumber(kRegisters),
              "kRegBacking must stay aligned with kRegisters");

int FindRegIdxByExactName(const char *name) {
    if (!name || !*name) return -1;
    for (size_t i = 0; i < qnumber(kRegisters); ++i) {
        if (strieq(kRegisters[i].name, name)) {
            return static_cast<int>(i);
        }
    }
    return -1;
}

bool ResolveRegInfo(const char *name, const char **main_regname, bitrange_t *bitrange) {
    if (!name || !*name) return false;

    const int exact = FindRegIdxByExactName(name);
    if (exact >= 0) {
        if (main_regname) *main_regname = kRegisters[exact].name;
        if (bitrange) {
            const uint16 bits = (kRegisters[exact].dtype == dt_qword) ? 64
                              : (kRegisters[exact].dtype == dt_dword) ? 32
                              : (kRegisters[exact].dtype == dt_word)  ? 16
                              :                                         8;
            *bitrange = bitrange_t(0, bits);
        }
        return true;
    }

    struct RegAliasInfo {
        const char *alias;
        const char *target;
        uint16 bit_ofs;
        uint16 bit_len;
    };
    static const RegAliasInfo kAliases[] = {
        { "R0",  "X",  0,  8 }, { "R1",  "A",  0,  8 },
        { "R2",  "C",  0,  8 }, { "R3",  "B",  0,  8 },
        { "R4",  "E",  0,  8 }, { "R5",  "D",  0,  8 },
        { "R6",  "L",  0,  8 }, { "R7",  "H",  0,  8 },
        { "RP0", "AX", 0, 16 }, { "RP1", "BC", 0, 16 },
        { "RP2", "DE", 0, 16 }, { "RP3", "HL", 0, 16 },
        { "SPL", "SP", 0,  8 }, { "SPH", "SP", 8,  8 },
        { "RB0", "RB", 0,  8 }, { "RB1", "RB", 0,  8 },
        { "RB2", "RB", 0,  8 }, { "RB3", "RB", 0,  8 },
    };

    for (const auto &a : kAliases) {
        if (strieq(a.alias, name)) {
            if (main_regname) *main_regname = a.target;
            if (bitrange) *bitrange = bitrange_t(a.bit_ofs, a.bit_len);
            return true;
        }
    }
    return false;
}

int FindRegIdxByName(const char *name) {
    const char *canonical = nullptr;
    if (!ResolveRegInfo(name, &canonical, nullptr) || !canonical) return -1;
    return FindRegIdxByExactName(canonical);
}

uchar ToIdaSegPerm(uint8_t perm) {
    uchar p = 0;
    if (perm & rl78::MEM_PERM_READ)  p |= SEGPERM_READ;
    if (perm & rl78::MEM_PERM_WRITE) p |= SEGPERM_WRITE;
    if (perm & rl78::MEM_PERM_EXEC)  p |= SEGPERM_EXEC;
    return p;
}

int WatchTypeFromBpt(bpttype_t type) {
    switch (type) {
    case BPT_WRITE: return 1;
    case BPT_READ:  return 2;
    case BPT_RDWR:  return 3;
    default:        return 0;
    }
}

void IdaLogCallback(const char *line) {
    if (line && *line) {
        msg("%s", line);
    }
}

struct rl78dbg_plugmod_t;
rl78dbg_plugmod_t *g_active_plugmod = nullptr;

struct idd_listener_t final : public event_listener_t {
    rl78dbg_plugmod_t *pm = nullptr;
    ssize_t idaapi on_event(ssize_t code, va_list va) override;
};

struct idp_rl78_listener_t final : public event_listener_t {
    ssize_t idaapi on_event(ssize_t code, va_list va) override;
};

struct ui_listener_t final : public event_listener_t {
    bool debugger_selected = false;
    ssize_t idaapi on_event(ssize_t code, va_list va) override;
};

struct rl78dbg_plugmod_t final : public plugmod_t {
    rl78::Rl78Machine machine;
    std::deque<debug_event_t> event_queue;
    std::unordered_set<uint32_t> ida_exec_bpts;
    std::atomic<bool> pause_requested{false};
    bool is_running = false;
    bool attached = false;
    bool hooks_installed = false;
    bool idc_registered = false;
    resume_mode_t resmod = RESMOD_NONE;
    bool ignore_bpt_once = false;
    uint32_t entry_pc = 0;
    uint32_t last_boot_swap_count = 0;
    uint32_t last_flash_mut_count = 0;

    idd_listener_t idd_listener;
    idp_rl78_listener_t idp_listener;
    ui_listener_t ui_listener;

    rl78dbg_plugmod_t() {
        g_active_plugmod = this;
        idd_listener.pm = this;
        InstallHooks();
        RegisterIdcFunctions();
    }

    ~rl78dbg_plugmod_t() override {
        set_log_callback(nullptr);
        UnregisterIdcFunctions();
        UninstallHooks();
        if (g_active_plugmod == this) {
            g_active_plugmod = nullptr;
        }
    }

    bool idaapi run(size_t arg) override;

    void InstallHooks();
    void UninstallHooks();
    void RegisterIdcFunctions();
    void UnregisterIdcFunctions();
    void ResetSessionState();
    void DetectLayoutFromIdb(rl78::CoreProfile *core_out,
                             uint32_t *flash_end_out,
                             uint32_t *dflash_sz_out,
                             uint32_t *ram_start_out) const;
    void LoadSegmentsFromIdb();
    uint32_t DetermineEntryPc(uint32_t flash_end) const;
    void QueueEvent(const debug_event_t &ev);
    void QueueStopEvent(const rl78::StopInfo &stop, bool from_single_step);
    uint64_t ReadRegByIdx(size_t idx) const;
    void WriteRegByIdx(size_t idx, uint64_t val);
    void InvalidateBusCacheOnChange(bool prev_maa, bool prev_dfl) const;
    void InvalidateFlashIfChanged();
    void WriteRegAndInvalidate(size_t idx, uint64_t val);
    ssize_t HandleIddEvent(ssize_t code, va_list va);
    ssize_t HandleRexec(const char *cmdline);
};

debugger_t g_debugger = {
    IDD_INTERFACE_VERSION,
    "rl78emu",
    DEBUGGER_ID_6811_EMULATOR,
    "rl78",
    DBG_FLAG_CAN_CONT_BPT
    | DBG_FLAG_SAFE
    | DBG_FLAG_FAKE_ATTACH
    | DBG_FLAG_NOHOST
    | DBG_FLAG_NOPARAMETERS
    | DBG_FLAG_NOPASSWORD
    | DBG_FLAG_NOSTARTDIR
    | DBG_FLAG_SMALLBLKS
    | DBG_FLAG_ANYSIZE_HWBPT
    | DBG_FLAG_FAST_STEP
    | DBG_HAS_GET_PROCESSES
    | DBG_HAS_ATTACH_PROCESS
    | DBG_HAS_DETACH_PROCESS
    | DBG_HAS_REQUEST_PAUSE
    | DBG_HAS_THREAD_SUSPEND
    | DBG_HAS_THREAD_CONTINUE
    | DBG_HAS_SET_RESUME_MODE
    | DBG_HAS_CHECK_BPT
    | DBG_HAS_REXEC,
    const_cast<const char **>(kRegClasses),
    RC_GENERAL,
    const_cast<register_info_t *>(kRegisters),
    static_cast<int>(qnumber(kRegisters)),
    0x100,
    kSoftBptBytes,
    sizeof(kSoftBptBytes),
    0,
    DBG_RESMOD_STEP_INTO,
};

void rl78dbg_plugmod_t::InstallHooks() {
    if (!hooks_installed) {
        hook_event_listener(HT_IDD, &idd_listener);
        hook_event_listener(HT_IDP, &idp_listener);
        hook_event_listener(HT_UI,  &ui_listener);
        hooks_installed = true;
    }
}

void rl78dbg_plugmod_t::UninstallHooks() {
    if (hooks_installed) {
        unhook_event_listener(HT_UI,  &ui_listener);
        unhook_event_listener(HT_IDP, &idp_listener);
        unhook_event_listener(HT_IDD, &idd_listener);
        hooks_installed = false;
    }
}

bool idaapi rl78dbg_plugmod_t::run(size_t) {
    if (load_debugger("rl78emu", false) || load_debugger("rl78dbg.dll", false)) {
        msg("[rl78emu] Selected Renesas RL78 emulator debugger backend.\n");
    } else {
        warning("Failed to activate rl78emu debugger backend.");
    }
    return true;
}

void rl78dbg_plugmod_t::DetectLayoutFromIdb(rl78::CoreProfile *core_out,
                                            uint32_t *flash_end_out,
                                            uint32_t *dflash_sz_out,
                                            uint32_t *ram_start_out) const {
    rl78::CoreProfile core = rl78::CoreProfile::S3;
    uint32_t flash_end = kDefaultCodeFlashEnd;
    uint32_t dflash_sz = 0x002000u;
    uint32_t ram_start = rl78::Rl78Bus::kDefaultRamStart;

    const int qty = get_segm_qty();
    for (int i = 0; i < qty; ++i) {
        segment_t *seg = getnseg(i);
        if (!seg || seg->start_ea >= seg->end_ea || seg->is_header_segm()) continue;
        qstring sname;
        get_segm_name(&sname, seg);
        if (sname == "ABS" || seg->type == SEG_XTRN) continue;
        if (seg->start_ea >= rl78::Rl78Bus::kAddressSpaceSize) continue;

        const uint32_t s_start = static_cast<uint32_t>(seg->start_ea);
        const uint32_t s_end = static_cast<uint32_t>(std::min<ea_t>(seg->end_ea, rl78::Rl78Bus::kAddressSpaceSize));
        if (s_start < rl78::Rl78Bus::kNearBase) {
            const uint32_t clamped = std::min<uint32_t>(s_end, rl78::Rl78Bus::kMaxCodeFlashEnd);
            if (clamped > flash_end) flash_end = clamped;
        }
        if (s_start >= rl78::Rl78Bus::kMaxRamBase && s_end <= rl78::Rl78Bus::kGprStart &&
            (stristr(sname.c_str(), "RAM") != nullptr || seg->type == SEG_BSS || seg->type == SEG_DATA)) {
            ram_start = s_start;
        }
    }

    // Check if IDB loaded 0xF1000..0xF2FFF matching 0x01000..0x02FFF (mirror area instead of Data Flash).
    if (is_loaded(0x01000u) && is_loaded(0xF1000u)) {
        uint8_t b0[256], bf[256];
        if (get_bytes(b0, sizeof(b0), 0x01000u, GMB_READALL) == sizeof(b0) &&
            get_bytes(bf, sizeof(bf), 0xF1000u, GMB_READALL) == sizeof(bf) &&
            std::memcmp(b0, bf, sizeof(b0)) == 0) {
            dflash_sz = 0u;
        }
    }

    // If 0xF0000..0xFFFFF is a single monolithic segment, detect RAM boundary automatically inside it.
    if (is_loaded(0xF3000u) && is_loaded(0x03000u)) {
        for (uint32_t a = rl78::Rl78Bus::kMaxRamBase; a < rl78::Rl78Bus::kGprStart; a += 0x100u) {
            uint8_t ba[256], b0[256], b1[256];
            if (get_bytes(ba, sizeof(ba), a, GMB_READALL) == sizeof(ba) &&
                get_bytes(b0, sizeof(b0), a & 0xFFFFu, GMB_READALL) == sizeof(b0) &&
                get_bytes(b1, sizeof(b1), 0x10000u | (a & 0xFFFFu), GMB_READALL) == sizeof(b1)) {
                if (std::memcmp(ba, b0, sizeof(ba)) != 0 && std::memcmp(ba, b1, sizeof(ba)) != 0) {
                    ram_start = a;
                    break;
                }
            }
        }
    }

    *core_out = core;
    *flash_end_out = flash_end;
    *dflash_sz_out = dflash_sz;
    *ram_start_out = ram_start;
}

void rl78dbg_plugmod_t::LoadSegmentsFromIdb() {
    const int qty = get_segm_qty();
    std::vector<uint8_t> buf;
    for (int i = 0; i < qty; ++i) {
        segment_t *seg = getnseg(i);
        if (!seg || seg->start_ea >= seg->end_ea || seg->is_header_segm()) continue;
        qstring sname;
        get_segm_name(&sname, seg);
        if (sname == "ABS" || seg->type == SEG_XTRN) continue;
        if (seg->start_ea >= rl78::Rl78Bus::kAddressSpaceSize) continue;

        const ea_t clamped_end = std::min<ea_t>(seg->end_ea, rl78::Rl78Bus::kAddressSpaceSize);
        if (clamped_end <= seg->start_ea) continue;

        const uint32_t start = static_cast<uint32_t>(seg->start_ea);
        const size_t seg_size = static_cast<size_t>(clamped_end - seg->start_ea);
        buf.resize(seg_size);
        const ssize_t got = get_bytes(buf.data(), seg_size, seg->start_ea, GMB_READALL);
        if (got <= 0) continue;

        for (size_t off = 0; off < seg_size; ) {
            const uint32_t cur_ea = start + static_cast<uint32_t>(off);
            if (!is_loaded(cur_ea) || cur_ea >= rl78::Rl78Bus::kSfrStart ||
                (cur_ea >= rl78::Rl78Bus::kSfr2Start && cur_ea <= rl78::Rl78Bus::kSfr2End)) {
                ++off;
                continue;
            }
            size_t run_end = off + 1;
            while (run_end < seg_size) {
                const uint32_t next_ea = start + static_cast<uint32_t>(run_end);
                if (!is_loaded(next_ea) || next_ea >= rl78::Rl78Bus::kSfrStart ||
                    (next_ea >= rl78::Rl78Bus::kSfr2Start && next_ea <= rl78::Rl78Bus::kSfr2End)) {
                    break;
                }
                if (next_ea >= rl78::Rl78Bus::kNearBase && cur_ea < rl78::Rl78Bus::kNearBase) {
                    break;
                }
                ++run_end;
            }
            if (cur_ea < rl78::Rl78Bus::kNearBase) {
                machine.bus.LoadRom(buf.data() + off, run_end - off, cur_ea);
            } else if (cur_ea >= machine.bus.RamStart() && cur_ea <= rl78::Rl78Bus::kHighSpeedRamEnd) {
                machine.bus.WriteDebug(cur_ea, run_end - off, buf.data() + off);
            } else if (cur_ea >= rl78::Rl78Bus::kDataFlashStart && cur_ea < machine.bus.DataFlashEnd()) {
                const size_t avail = machine.bus.DataFlashEnd() - cur_ea;
                machine.bus.LoadDataFlash(buf.data() + off, std::min(avail, run_end - off),
                                          cur_ea - rl78::Rl78Bus::kDataFlashStart);
            }
            off = run_end;
        }
    }
}

uint32_t rl78dbg_plugmod_t::DetermineEntryPc(uint32_t flash_end) const {
    if (is_loaded(rl78::kResetVectorAddress) && is_loaded(rl78::kResetVectorAddress + 1u)) {
        const uint8_t lo = machine.bus.PeekByte(rl78::kResetVectorAddress);
        const uint8_t hi = machine.bus.PeekByte(rl78::kResetVectorAddress + 1u);
        const uint32_t vec = static_cast<uint32_t>(lo) | (static_cast<uint32_t>(hi) << 8);
        if (vec != 0x0000u && vec != 0xFFFFu && vec < flash_end) {
            return vec;
        }
    }

    const ea_t start_ip = inf_get_start_ip();
    if (start_ip != BADADDR && start_ip < rl78::Rl78Bus::kAddressSpaceSize) {
        return static_cast<uint32_t>(start_ip);
    }

    const ea_t main_ea = get_name_ea(BADADDR, "main");
    if (main_ea != BADADDR && main_ea < rl78::Rl78Bus::kAddressSpaceSize) {
        return static_cast<uint32_t>(main_ea);
    }

    const ea_t reset_ea = get_name_ea(BADADDR, "RESET");
    if (reset_ea != BADADDR && reset_ea < rl78::Rl78Bus::kAddressSpaceSize) {
        return static_cast<uint32_t>(reset_ea);
    }

    return 0;
}

void rl78dbg_plugmod_t::ResetSessionState() {
    rl78::CoreProfile core = rl78::CoreProfile::S3;
    uint32_t flash_end = kDefaultCodeFlashEnd;
    uint32_t dflash_sz = 0x002000u;
    uint32_t ram_start = rl78::Rl78Bus::kDefaultRamStart;
    DetectLayoutFromIdb(&core, &flash_end, &dflash_sz, &ram_start);

    machine.Configure(core, flash_end, dflash_sz, ram_start);
    machine.bus.ClearMemory();
    machine.cpu.ClearBreakpoints();
    machine.bus.ClearWatchpoints();

    LoadSegmentsFromIdb();
    entry_pc = DetermineEntryPc(flash_end);

    // Reset after loading ROM so Option Byte (0x000C0) & reset vector are present.
    machine.Reset(static_cast<int32_t>(entry_pc));
    last_boot_swap_count = machine.bus.BootSwapCount();
    last_flash_mut_count = machine.bus.FlashMutationCount();
}

void rl78dbg_plugmod_t::QueueEvent(const debug_event_t &ev) {
    event_queue.push_back(ev);
}

void rl78dbg_plugmod_t::QueueStopEvent(const rl78::StopInfo &stop, bool from_single_step) {
    debug_event_t ev;
    ev.pid = kPid;
    ev.tid = kTid;
    ev.ea = stop.pc;
    ev.handled = true;

    switch (stop.reason) {
    case rl78::StopReason::None:
        if (from_single_step) {
            ev.set_eid(STEP);
            ev.ea = machine.cpu.GetPC();
        } else {
            ev.set_eid(PROCESS_SUSPENDED);
        }
        break;

    case rl78::StopReason::Breakpoint:
        {
            ev.ea = stop.pc;
            bptaddr_t &bpt = ev.set_bpt();
            bpt.hea = BADADDR;
            bpt.kea = BADADDR;
        }
        break;

    case rl78::StopReason::Watchpoint:
        {
            bptaddr_t &bpt = ev.set_bpt();
            bpt.hea = static_cast<ea_t>(stop.detail);
            bpt.kea = BADADDR;
        }
        break;

    case rl78::StopReason::BreakInsn:
        {
            excinfo_t &exc = ev.set_exception();
            exc.code = 5;
            exc.can_cont = true;
            exc.ea = stop.pc;
            exc.info = "BRK / BRK1 instruction";
        }
        break;

    case rl78::StopReason::Halt:
        {
            excinfo_t &exc = ev.set_exception();
            exc.code = 5;
            exc.can_cont = true;
            exc.ea = stop.pc;
            exc.info = "CPU HALT instruction";
        }
        break;

    case rl78::StopReason::Stop:
        {
            excinfo_t &exc = ev.set_exception();
            exc.code = 5;
            exc.can_cont = true;
            exc.ea = stop.pc;
            exc.info = "CPU STOP instruction";
        }
        break;

    case rl78::StopReason::UnmappedMemory:
        {
            excinfo_t &exc = ev.set_exception();
            exc.code = 11;
            exc.can_cont = true;
            exc.ea = static_cast<ea_t>(stop.detail);
            exc.info.sprnt("Unmapped memory %s at 0x%05X",
                           stop.is_write ? "write" : "read",
                           static_cast<unsigned>(stop.detail));
        }
        break;

    case rl78::StopReason::InvalidInsn:
        {
            excinfo_t &exc = ev.set_exception();
            exc.code = 4;
            exc.can_cont = true;
            exc.ea = stop.pc;
            exc.info.sprnt("Invalid opcode 0x%X at 0x%05X",
                           static_cast<unsigned>(stop.detail),
                           static_cast<unsigned>(stop.pc));
        }
        break;

    case rl78::StopReason::WdtReset:
        {
            excinfo_t &exc = ev.set_exception();
            exc.code = 5;
            exc.can_cont = true;
            exc.ea = stop.pc;
            exc.info = "Watchdog timer overflow reset (RESF.WDTRF=1)";
        }
        break;
    }

    invalidate_dbgmem_contents(0, BADADDR);
    QueueEvent(ev);
}

uint64_t rl78dbg_plugmod_t::ReadRegByIdx(size_t idx) const {
    if (idx >= qnumber(kRegBacking)) return 0;
    const RegBackingDesc &d = kRegBacking[idx];
    switch (d.kind) {
    case BACK_PC:      return machine.cpu.GetPC();
    case BACK_SP:      return machine.cpu.GetSP();
    case BACK_PSW:     return machine.cpu.GetPSW();
    case BACK_CS:      return machine.cpu.GetCS();
    case BACK_ES:      return machine.cpu.GetES();
    case BACK_PMC:     return machine.cpu.GetPMC();
    case BACK_MEM:     return machine.cpu.GetMEM();
    case BACK_RP:      return machine.cpu.ReadRegPair(static_cast<uint8_t>(d.param0));
    case BACK_R8:      return machine.cpu.ReadReg(static_cast<uint8_t>(d.param0));
    case BACK_RB:      return machine.cpu.GetRB();
    case BACK_CY:      return machine.cpu.GetCY() ? 1u : 0u;
    case BACK_BANK_RP: return machine.cpu.ReadRegPairBank(static_cast<uint8_t>(d.param0), d.param1);
    case BACK_SFR8:    return machine.bus.PeekByte(d.param0);
    case BACK_SFR16: {
        const uint8_t lo = machine.bus.PeekByte(d.param0);
        const uint8_t hi = machine.bus.PeekByte(d.param0 + 1u);
        return static_cast<uint64_t>(lo) | (static_cast<uint64_t>(hi) << 8);
    }
    case BACK_CYCLES:  return machine.cpu.TotalCycles();
    }
    return 0;
}

void rl78dbg_plugmod_t::WriteRegByIdx(size_t idx, uint64_t val) {
    if (idx >= qnumber(kRegBacking)) return;
    const RegBackingDesc &d = kRegBacking[idx];
    switch (d.kind) {
    case BACK_PC:      machine.cpu.SetPC(static_cast<uint32_t>(val & rl78::Rl78Bus::kAddressMask)); break;
    case BACK_SP:      machine.cpu.SetSP(static_cast<uint16_t>(val & 0xFFFFu)); break;
    case BACK_PSW:     machine.cpu.SetPSW(static_cast<uint8_t>(val & 0xFFu)); break;
    case BACK_CS:      machine.cpu.SetCS(static_cast<uint8_t>(val & 0xFFu)); break;
    case BACK_ES:      machine.cpu.SetES(static_cast<uint8_t>(val & 0xFFu)); break;
    case BACK_PMC:     machine.cpu.SetPMC(static_cast<uint8_t>(val & 0xFFu)); break;
    case BACK_MEM:     machine.cpu.SetMEM(static_cast<uint8_t>(val & 0xFFu)); break;
    case BACK_RP:      machine.cpu.WriteRegPair(static_cast<uint8_t>(d.param0), static_cast<uint16_t>(val & 0xFFFFu)); break;
    case BACK_R8:      machine.cpu.WriteReg(static_cast<uint8_t>(d.param0), static_cast<uint8_t>(val & 0xFFu)); break;
    case BACK_RB:      machine.cpu.SetRB(static_cast<uint8_t>(val & 3u)); break;
    case BACK_CY:      machine.cpu.SetCY((val & 1u) != 0); break;
    case BACK_BANK_RP: machine.cpu.WriteRegPairBank(static_cast<uint8_t>(d.param0), d.param1, static_cast<uint16_t>(val & 0xFFFFu)); break;
    case BACK_SFR8:    machine.bus.PokeByte(d.param0, static_cast<uint8_t>(val & 0xFFu)); break;
    case BACK_SFR16:
        machine.bus.PokeByte(d.param0, static_cast<uint8_t>(val & 0xFFu));
        machine.bus.PokeByte(d.param0 + 1u, static_cast<uint8_t>((val >> 8) & 0xFFu));
        break;
    case BACK_CYCLES:  break;
    }
}

void rl78dbg_plugmod_t::InvalidateBusCacheOnChange(bool prev_maa, bool prev_dfl) const {
    if (machine.bus.GetMirrorAreaAlt() != prev_maa || machine.bus.IsDataFlashEnabled() != prev_dfl) {
        invalidate_dbgmem_contents(rl78::Rl78Bus::kDataFlashStart,
                                  machine.bus.RamStart() - rl78::Rl78Bus::kDataFlashStart);
    }
}

void rl78dbg_plugmod_t::InvalidateFlashIfChanged() {
    const uint32_t swap_cnt = machine.bus.BootSwapCount();
    const uint32_t mut_cnt = machine.bus.FlashMutationCount();
    if (swap_cnt != last_boot_swap_count || mut_cnt != last_flash_mut_count) {
        last_boot_swap_count = swap_cnt;
        last_flash_mut_count = mut_cnt;
        invalidate_dbgmem_contents(0x00000u, machine.bus.CodeFlashEnd());
        invalidate_dbgmem_contents(rl78::Rl78Bus::kDataFlashStart,
                                  machine.bus.RamStart() - rl78::Rl78Bus::kDataFlashStart);
        invalidate_dbg_state(DBGINV_MEMORY | DBGINV_REGS);
    }
}

void rl78dbg_plugmod_t::WriteRegAndInvalidate(size_t idx, uint64_t val) {
    if (idx >= qnumber(kRegBacking)) return;
    const bool prev_maa = machine.bus.GetMirrorAreaAlt();
    const bool prev_dfl = machine.bus.IsDataFlashEnabled();
    WriteRegByIdx(idx, val);

    const RegBackingDesc &d = kRegBacking[idx];
    if (d.kind == BACK_CYCLES) return;

    if (d.kind == BACK_PC) {
        invalidate_dbg_state(DBGINV_REGS);
        return;
    }
    if (d.kind == BACK_BANK_RP || d.kind == BACK_RP || d.kind == BACK_R8) {
        invalidate_dbgmem_contents(rl78::Rl78Bus::kGprStart, 0x0020u);
    } else if (d.kind == BACK_SP) {
        invalidate_dbgmem_contents(rl78::kSpAddress, 2u);
    } else if (d.kind == BACK_PSW || d.kind == BACK_RB || d.kind == BACK_CY) {
        invalidate_dbgmem_contents(rl78::kPswAddress, 1u);
    } else if (d.kind == BACK_PMC) {
        invalidate_dbgmem_contents(rl78::kPmcAddress, 1u);
    } else if (d.kind == BACK_SFR8) {
        invalidate_dbgmem_contents(d.param0, 1u);
    } else if (d.kind == BACK_SFR16) {
        invalidate_dbgmem_contents(d.param0, 2u);
    }

    InvalidateBusCacheOnChange(prev_maa, prev_dfl);
    invalidate_dbg_state(DBGINV_REGS | DBGINV_MEMORY);
}

ssize_t rl78dbg_plugmod_t::HandleRexec(const char *cmdline) {
    std::string out;
    const char *cmd = (cmdline && *cmdline) ? cmdline : "help";
    machine.ExecuteCommand(cmd, out);
    if (!out.empty()) {
        msg("%s\n", out.c_str());
    }
    invalidate_dbgmem_contents(0, BADADDR);
    invalidate_dbg_state(DBGINV_REGS | DBGINV_MEMORY);
    return 0;
}

ssize_t rl78dbg_plugmod_t::HandleIddEvent(ssize_t code, va_list va) {
    switch (code) {
    case debugger_t::ev_init_debugger:
        {
            va_arg(va, const char *);
            va_arg(va, int);
            va_arg(va, const char *);
            va_arg(va, qstring *);
            set_log_callback(IdaLogCallback);
            event_queue.clear();
            ida_exec_bpts.clear();
            pause_requested.store(false);
            is_running = false;
            attached = false;
            return DRC_OK;
        }

    case debugger_t::ev_term_debugger:
        {
            set_log_callback(nullptr);
            event_queue.clear();
            ida_exec_bpts.clear();
            is_running = false;
            attached = false;
            return DRC_OK;
        }

    case debugger_t::ev_get_processes:
        {
            procinfo_vec_t *procs = va_arg(va, procinfo_vec_t *);
            va_arg(va, qstring *);
            if (procs) {
                process_info_t &pi = procs->push_back();
                pi.pid = kPid;
                pi.name = "Renesas RL78 Emulator";
            }
            return DRC_OK;
        }

    case debugger_t::ev_start_process:
        {
            const char *path = va_arg(va, const char *);
            va_arg(va, const char *);
            va_arg(va, const char *);
            va_arg(va, uint32);
            const char *input_path = va_arg(va, const char *);
            va_arg(va, uint32);
            va_arg(va, qstring *);
            va_arg(va, launch_env_t *);

            ResetSessionState();
            event_queue.clear();
            ida_exec_bpts.clear();
            pause_requested.store(false);
            is_running = false;
            attached = true;
            resmod = RESMOD_NONE;
            ignore_bpt_once = false;

            debug_event_t ev;
            ev.set_eid(PROCESS_STARTED);
            ev.pid = kPid;
            ev.tid = kTid;
            ev.ea = entry_pc;
            ev.handled = true;
            ev.modinfo().name = (input_path && *input_path) ? input_path : (path && *path ? path : "rl78.bin");
            ev.modinfo().base = entry_pc;
            ev.modinfo().size = 0;
            ev.modinfo().rebase_to = BADADDR;
            QueueEvent(ev);

            debug_event_t susp;
            susp.set_eid(PROCESS_SUSPENDED);
            susp.pid = kPid;
            susp.tid = kTid;
            susp.ea = entry_pc;
            susp.handled = true;
            QueueEvent(susp);
            return DRC_OK;
        }

    case debugger_t::ev_attach_process:
        {
            va_arg(va, pid_t);
            va_arg(va, int);
            va_arg(va, uint32);
            va_arg(va, qstring *);

            ResetSessionState();
            event_queue.clear();
            ida_exec_bpts.clear();
            pause_requested.store(false);
            is_running = false;
            attached = true;
            resmod = RESMOD_NONE;
            ignore_bpt_once = false;

            debug_event_t ev;
            ev.set_eid(PROCESS_STARTED);
            ev.pid = kPid;
            ev.tid = kTid;
            ev.ea = entry_pc;
            ev.handled = true;
            ev.modinfo().name = "rl78.bin";
            ev.modinfo().base = entry_pc;
            ev.modinfo().size = 0;
            ev.modinfo().rebase_to = BADADDR;
            QueueEvent(ev);
            return DRC_OK;
        }

    case debugger_t::ev_detach_process:
    case debugger_t::ev_exit_process:
        {
            va_arg(va, qstring *);
            is_running = false;
            attached = false;
            debug_event_t ev;
            ev.set_exit_code(PROCESS_EXITED, 0);
            ev.pid = kPid;
            ev.tid = kTid;
            ev.ea = machine.cpu.GetPC();
            ev.handled = true;
            QueueEvent(ev);
            return DRC_OK;
        }

    case debugger_t::ev_get_debapp_attrs:
        {
            debapp_attrs_t *out_pattrs = va_arg(va, debapp_attrs_t *);
            if (out_pattrs) {
                out_pattrs->addrsize = 4;
                out_pattrs->platform = "gdb";
                out_pattrs->is_be = false;
            }
            return DRC_OK;
        }

    case debugger_t::ev_rebase_if_required_to:
        va_arg(va, ea_t);
        return DRC_OK;

    case debugger_t::ev_request_pause:
        va_arg(va, qstring *);
        pause_requested.store(true);
        return DRC_OK;

    case debugger_t::ev_set_resume_mode:
        va_arg(va, thid_t);
        resmod = static_cast<resume_mode_t>(va_arg(va, int));
        va_arg(va, qstring *);
        return DRC_OK;

    case debugger_t::ev_resume:
        {
            const debug_event_t *ev = va_arg(va, const debug_event_t *);
            if (attached) {
                pause_requested.store(false);
                if (ev && ev->eid() == PROCESS_STARTED && !event_queue.empty()) {
                    is_running = false;
                } else {
                    is_running = true;
                    ignore_bpt_once = true;
                }
            }
            return DRC_OK;
        }

    case debugger_t::ev_get_debug_event:
        {
            gdecode_t *out_code = va_arg(va, gdecode_t *);
            debug_event_t *event = va_arg(va, debug_event_t *);
            const int timeout_ms = va_arg(va, int);
            if (!out_code || !event) return DRC_FAILED;

            if (event_queue.empty() && is_running) {
                if (resmod == RESMOD_INTO) {
                    const rl78::StopInfo stop = machine.Step(ignore_bpt_once);
                    InvalidateFlashIfChanged();
                    ignore_bpt_once = false;
                    is_running = false;
                    resmod = RESMOD_NONE;
                    QueueStopEvent(stop, true);
                } else {
                    const rl78::StopInfo stop = machine.RunSteps(100000ULL, ignore_bpt_once, &pause_requested);
                    InvalidateFlashIfChanged();
                    ignore_bpt_once = false;
                    if (pause_requested.exchange(false)) {
                        is_running = false;
                        QueueStopEvent(rl78::StopInfo{rl78::StopReason::None, machine.cpu.GetPC(), 0, false}, false);
                    } else if (stop.reason != rl78::StopReason::None) {
                        is_running = false;
                        QueueStopEvent(stop, false);
                    } else if (machine.cpu.GetRunState() != rl78::RunState::Running && timeout_ms > 0) {
                        std::this_thread::sleep_for(std::chrono::milliseconds(std::min(timeout_ms, 25)));
                    }
                }
            }

            if (event_queue.empty()) {
                if (!is_running && timeout_ms > 0) {
                    std::this_thread::sleep_for(std::chrono::milliseconds(std::min(timeout_ms, 10)));
                }
                *out_code = GDE_NO_EVENT;
                return DRC_OK;
            }

            *event = event_queue.front();
            event_queue.pop_front();
            if (event->eid() == PROCESS_SUSPENDED) is_running = false;
            *out_code = event_queue.empty() ? GDE_ONE_EVENT : GDE_MANY_EVENTS;
            return DRC_OK;
        }

    case debugger_t::ev_thread_suspend:
    case debugger_t::ev_thread_continue:
        va_arg(va, thid_t);
        va_arg(va, qstring *);
        return DRC_OK;

    case debugger_t::ev_read_registers:
        {
            va_arg(va, thid_t);
            const int clsmask = va_arg(va, int);
            regval_t *values = va_arg(va, regval_t *);
            va_arg(va, qstring *);
            if (!values) return DRC_FAILED;
            for (size_t i = 0; i < qnumber(kRegisters); ++i) {
                if (clsmask == 0 || (kRegisters[i].register_class_mask & clsmask) != 0) {
                    values[i].set_int(ReadRegByIdx(i));
                }
            }
            return DRC_OK;
        }

    case debugger_t::ev_write_register:
        {
            va_arg(va, thid_t);
            const int regidx = va_arg(va, int);
            const regval_t *value = va_arg(va, const regval_t *);
            va_arg(va, qstring *);
            if (!value || regidx < 0 || static_cast<size_t>(regidx) >= qnumber(kRegisters)) {
                return DRC_FAILED;
            }
            WriteRegAndInvalidate(static_cast<size_t>(regidx), value->ival);
            return DRC_OK;
        }

    case debugger_t::ev_get_memory_info:
        {
            meminfo_vec_t *ranges = va_arg(va, meminfo_vec_t *);
            va_arg(va, qstring *);
            if (!ranges) return DRC_FAILED;
            ranges->qclear();
            const auto regions = machine.bus.GetRegions();
            for (const auto &reg : regions) {
                memory_info_t &mi = ranges->push_back();
                mi.start_ea = reg.start;
                mi.end_ea = static_cast<ea_t>(reg.start) + static_cast<ea_t>(reg.size);
                mi.name = reg.name.c_str();
                mi.sclass = reg.is_device ? "DATA" : "CODE";
                mi.sbase = 0;
                mi.bitness = 1;  // match 32-bit ea_t addressing used by rl78prox
                mi.perm = ToIdaSegPerm(reg.perm);
            }
            return DRC_OK;
        }

    case debugger_t::ev_read_memory:
        {
            size_t *nbytes = va_arg(va, size_t *);
            const ea_t ea = va_arg(va, ea_t);
            void *buffer = va_arg(va, void *);
            const size_t size = va_arg(va, size_t);
            va_arg(va, qstring *);
            if (!nbytes || !buffer) return DRC_FAILED;
            if (size == 0) { *nbytes = 0; return DRC_OK; }
            if (ea >= rl78::Rl78Bus::kAddressSpaceSize) { *nbytes = 0; return DRC_FAILED; }
            const size_t avail = static_cast<size_t>(rl78::Rl78Bus::kAddressSpaceSize - ea);
            const size_t to_read = std::min(size, avail);
            if (!machine.bus.ReadDebug(static_cast<uint32_t>(ea), to_read, buffer)) {
                *nbytes = 0;
                return DRC_FAILED;
            }
            *nbytes = to_read;
            return DRC_OK;
        }

    case debugger_t::ev_write_memory:
        {
            size_t *nbytes = va_arg(va, size_t *);
            const ea_t ea = va_arg(va, ea_t);
            const void *buffer = va_arg(va, const void *);
            const size_t size = va_arg(va, size_t);
            va_arg(va, qstring *);
            if (!nbytes || !buffer) return DRC_FAILED;
            if (size == 0) { *nbytes = 0; return DRC_OK; }
            if (ea >= rl78::Rl78Bus::kAddressSpaceSize) { *nbytes = 0; return DRC_FAILED; }
            const size_t avail = static_cast<size_t>(rl78::Rl78Bus::kAddressSpaceSize - ea);
            const size_t to_write = std::min(size, avail);
            const bool prev_maa = machine.bus.GetMirrorAreaAlt();
            const bool prev_dfl = machine.bus.IsDataFlashEnabled();
            if (!machine.bus.WriteDebug(static_cast<uint32_t>(ea), to_write, buffer)) {
                *nbytes = 0;
                return DRC_FAILED;
            }
            if (ea + to_write > rl78::Rl78Bus::kGprStart) {
                invalidate_dbg_state(DBGINV_REGS);
            }
            InvalidateBusCacheOnChange(prev_maa, prev_dfl);
            *nbytes = to_write;
            return DRC_OK;
        }

    case debugger_t::ev_check_bpt:
        {
            int *bptvc = va_arg(va, int *);
            const bpttype_t type = va_arg(va, bpttype_t);
            const ea_t ea = va_arg(va, ea_t);
            va_arg(va, int);
            if (bptvc) {
                if (ea >= rl78::Rl78Bus::kAddressSpaceSize) {
                    *bptvc = BPT_BAD_ADDR;
                } else {
                    switch (type) {
                    case BPT_SOFT:
                    case BPT_EXEC:
                    case BPT_DEFAULT:
                    case BPT_WRITE:
                    case BPT_READ:
                    case BPT_RDWR:
                        *bptvc = BPT_OK;
                        break;
                    default:
                        *bptvc = BPT_BAD_TYPE;
                        break;
                    }
                }
            }
            return DRC_OK;
        }

    case debugger_t::ev_update_bpts:
        {
            int *nbpts = va_arg(va, int *);
            update_bpt_info_t *bpts = va_arg(va, update_bpt_info_t *);
            const int nadd = va_arg(va, int);
            const int ndel = va_arg(va, int);
            va_arg(va, qstring *);
            int count = 0;
            for (int i = 0; i < nadd + ndel; ++i) {
                update_bpt_info_t &b = bpts[i];
                if (b.code == BPT_SKIP) continue;
                if (b.ea >= rl78::Rl78Bus::kAddressSpaceSize) { b.code = BPT_BAD_ADDR; continue; }
                const bool is_add = i < nadd;
                const uint32_t ea = static_cast<uint32_t>(b.ea);
                if (b.type == BPT_SOFT || b.type == BPT_EXEC || b.type == BPT_DEFAULT) {
                    if (is_add) {
                        if (b.type == BPT_SOFT || b.type == BPT_DEFAULT) {
                            b.orgbytes.resize(1);
                            b.orgbytes[0] = machine.bus.PeekByte(ea);
                        }
                        machine.cpu.AddBreakpoint(ea);
                        ida_exec_bpts.insert(ea);
                    } else {
                        machine.cpu.RemoveBreakpoint(ea);
                        ida_exec_bpts.erase(ea);
                    }
                    b.code = BPT_OK;
                    ++count;
                } else {
                    const int wt = WatchTypeFromBpt(b.type);
                    const uint32_t wsize = b.size > 0 ? static_cast<uint32_t>(b.size) : 1u;
                    if (wt != 0) {
                        if (is_add) machine.bus.AddWatchpoint(ea, wsize, wt);
                        else machine.bus.RemoveWatchpoint(ea, wsize, wt);
                        b.code = BPT_OK;
                        ++count;
                    } else {
                        b.code = BPT_BAD_TYPE;
                    }
                }
            }
            if (nbpts) *nbpts = count;
            return DRC_OK;
        }

    case debugger_t::ev_rexec:
        return HandleRexec(va_arg(va, const char *));

    default:
        break;
    }

    return DRC_NONE;
}

ssize_t idaapi idd_listener_t::on_event(ssize_t code, va_list va) {
    return pm ? pm->HandleIddEvent(code, va) : DRC_NONE;
}

ssize_t idaapi idp_rl78_listener_t::on_event(ssize_t code, va_list va) {
    if (!IsRl78Proc()) return 0;

    switch (code) {
    case processor_t::ev_get_reg_info:
        {
            const char **main_regname = va_arg(va, const char **);
            bitrange_t *bitrange = va_arg(va, bitrange_t *);
            const char *regname = va_arg(va, const char *);
            if (ResolveRegInfo(regname, main_regname, bitrange)) {
                return 1;
            }
            return -1;
        }

    case processor_t::ev_is_call_insn:
        {
            const insn_t *insn = va_arg(va, const insn_t *);
            if (!insn || insn->ea == BADADDR) return 0;
            qstring mnem;
            if (!print_insn_mnem(&mnem, insn->ea)) return 0;
            if (strieq(mnem.c_str(), "call") || strieq(mnem.c_str(), "callt")) {
                return 1;
            }
            return -1;
        }

    case processor_t::ev_calc_step_over:
        {
            ea_t *target = va_arg(va, ea_t *);
            const ea_t ip = va_arg(va, ea_t);
            if (!target || ip == BADADDR) return 0;
            insn_t ins;
            if (decode_insn(&ins, ip) <= 0) return 0;
            qstring mnem;
            print_insn_mnem(&mnem, ip);
            if (strieq(mnem.c_str(), "call") ||
                strieq(mnem.c_str(), "callt") ||
                strieq(mnem.c_str(), "brk")) {
                *target = ip + ins.size;
                return 1;
            }
            *target = BADADDR;
            return 1;
        }

    default:
        break;
    }

    return 0;
}

ssize_t idaapi ui_listener_t::on_event(ssize_t code, va_list) {
    if (IsRl78Proc() &&
        (code == ui_database_inited || code == ui_ready_to_run) &&
        !debugger_selected) {
        if (load_debugger("rl78emu", false) || load_debugger("rl78dbg.dll", false)) {
            debugger_selected = true;
        }
    }
    return 0;
}

// ============================================================================
// IDC helpers (rl78dbg_*)
// ============================================================================

error_t idaapi idc_rl78dbg_start(idc_value_t *, idc_value_t *r) {
    rl78dbg_plugmod_t *pm = g_active_plugmod;
    if (!pm) { r->set_long(-1); return eOk; }
    pm->ResetSessionState();
    pm->event_queue.clear();
    pm->ida_exec_bpts.clear();
    pm->pause_requested.store(false);
    pm->is_running = false;
    pm->attached = true;
    pm->resmod = RESMOD_NONE;
    pm->ignore_bpt_once = false;
    r->set_long(static_cast<sval_t>(pm->entry_pc));
    return eOk;
}

error_t idaapi idc_rl78dbg_stop(idc_value_t *, idc_value_t *r) {
    rl78dbg_plugmod_t *pm = g_active_plugmod;
    if (!pm) { r->set_long(0); return eOk; }
    pm->is_running = false;
    pm->attached = false;
    pm->event_queue.clear();
    r->set_long(1);
    return eOk;
}

error_t idaapi idc_rl78dbg_step(idc_value_t *argv, idc_value_t *r) {
    rl78dbg_plugmod_t *pm = g_active_plugmod;
    if (!pm) { r->set_long(-1); return eOk; }
    const uint64_t count = argv[0].num > 0 ? static_cast<uint64_t>(argv[0].num) : 1ULL;
    if (count == 1) pm->machine.Step(true);
    else pm->machine.RunSteps(count, true, &pm->pause_requested);
    invalidate_dbgmem_contents(0, BADADDR);
    invalidate_dbg_state(DBGINV_REGS);
    r->set_long(static_cast<sval_t>(pm->machine.cpu.GetPC()));
    return eOk;
}

error_t idaapi idc_rl78dbg_run_to(idc_value_t *argv, idc_value_t *r) {
    rl78dbg_plugmod_t *pm = g_active_plugmod;
    if (!pm) { r->set_long(-1); return eOk; }
    const uint32_t target = static_cast<uint32_t>(argv[0].num & rl78::Rl78Bus::kAddressMask);
    const uint64_t max_steps = argv[1].num > 0 ? static_cast<uint64_t>(argv[1].num) : 1000000ULL;
    for (uint64_t i = 0; i < max_steps; ++i) {
        const rl78::StopInfo stop = pm->machine.Step(i == 0);
        if (pm->machine.cpu.GetPC() == target || stop.reason != rl78::StopReason::None) break;
    }
    invalidate_dbgmem_contents(0, BADADDR);
    invalidate_dbg_state(DBGINV_REGS);
    r->set_long(static_cast<sval_t>(pm->machine.cpu.GetPC()));
    return eOk;
}

error_t idaapi idc_rl78dbg_get_reg(idc_value_t *argv, idc_value_t *r) {
    rl78dbg_plugmod_t *pm = g_active_plugmod;
    if (!pm) { r->set_long(-1); return eOk; }
    const int idx = FindRegIdxByName(argv[0].c_str());
    if (idx < 0) { r->set_long(-1); return eOk; }
    r->set_long(static_cast<sval_t>(pm->ReadRegByIdx(static_cast<size_t>(idx))));
    return eOk;
}

error_t idaapi idc_rl78dbg_set_reg(idc_value_t *argv, idc_value_t *r) {
    rl78dbg_plugmod_t *pm = g_active_plugmod;
    if (!pm) { r->set_long(0); return eOk; }
    const int idx = FindRegIdxByName(argv[0].c_str());
    if (idx < 0) { r->set_long(0); return eOk; }
    pm->WriteRegAndInvalidate(static_cast<size_t>(idx), static_cast<uint64_t>(argv[1].num));
    r->set_long(1);
    return eOk;
}

error_t idaapi idc_rl78dbg_read_u8(idc_value_t *argv, idc_value_t *r) {
    rl78dbg_plugmod_t *pm = g_active_plugmod;
    if (!pm) { r->set_long(-1); return eOk; }
    const uint32_t addr = static_cast<uint32_t>(argv[0].num & rl78::Rl78Bus::kAddressMask);
    r->set_long(static_cast<sval_t>(pm->machine.bus.PeekByte(addr)));
    return eOk;
}

error_t idaapi idc_rl78dbg_write_u8(idc_value_t *argv, idc_value_t *r) {
    rl78dbg_plugmod_t *pm = g_active_plugmod;
    if (!pm) { r->set_long(0); return eOk; }
    const uint32_t addr = static_cast<uint32_t>(argv[0].num & rl78::Rl78Bus::kAddressMask);
    const uint8_t val = static_cast<uint8_t>(argv[1].num & 0xFF);
    const bool prev_maa = pm->machine.bus.GetMirrorAreaAlt();
    const bool prev_dfl = pm->machine.bus.IsDataFlashEnabled();
    pm->machine.bus.PokeByte(addr, val);
    invalidate_dbgmem_contents(addr, 1);
    pm->InvalidateBusCacheOnChange(prev_maa, prev_dfl);
    if (addr >= rl78::Rl78Bus::kGprStart) invalidate_dbg_state(DBGINV_REGS);
    r->set_long(1);
    return eOk;
}

error_t idaapi idc_rl78dbg_read_u16(idc_value_t *argv, idc_value_t *r) {
    rl78dbg_plugmod_t *pm = g_active_plugmod;
    if (!pm) { r->set_long(-1); return eOk; }
    const uint32_t addr = static_cast<uint32_t>(argv[0].num & rl78::Rl78Bus::kAddressMask);
    uint8_t buf[2] = {};
    if (!pm->machine.bus.ReadDebug(addr, 2, buf)) { r->set_long(-1); return eOk; }
    r->set_long(static_cast<sval_t>(static_cast<uint16_t>(buf[0]) | (static_cast<uint16_t>(buf[1]) << 8)));
    return eOk;
}

error_t idaapi idc_rl78dbg_write_u16(idc_value_t *argv, idc_value_t *r) {
    rl78dbg_plugmod_t *pm = g_active_plugmod;
    if (!pm) { r->set_long(0); return eOk; }
    const uint32_t addr = static_cast<uint32_t>(argv[0].num & rl78::Rl78Bus::kAddressMask);
    const uint16_t val = static_cast<uint16_t>(argv[1].num & 0xFFFF);
    const bool prev_maa = pm->machine.bus.GetMirrorAreaAlt();
    const bool prev_dfl = pm->machine.bus.IsDataFlashEnabled();
    const uint8_t buf[2] = { static_cast<uint8_t>(val & 0xFFu), static_cast<uint8_t>((val >> 8) & 0xFFu) };
    if (!pm->machine.bus.WriteDebug(addr, 2, buf)) { r->set_long(0); return eOk; }
    invalidate_dbgmem_contents(addr, 2);
    pm->InvalidateBusCacheOnChange(prev_maa, prev_dfl);
    if (addr + 2u > rl78::Rl78Bus::kGprStart) invalidate_dbg_state(DBGINV_REGS);
    r->set_long(1);
    return eOk;
}

error_t idaapi idc_rl78dbg_add_bpt(idc_value_t *argv, idc_value_t *r) {
    rl78dbg_plugmod_t *pm = g_active_plugmod;
    if (!pm) { r->set_long(0); return eOk; }
    pm->machine.cpu.AddBreakpoint(static_cast<uint32_t>(argv[0].num & rl78::Rl78Bus::kAddressMask));
    r->set_long(1);
    return eOk;
}

error_t idaapi idc_rl78dbg_del_bpt(idc_value_t *argv, idc_value_t *r) {
    rl78dbg_plugmod_t *pm = g_active_plugmod;
    if (!pm) { r->set_long(0); return eOk; }
    pm->machine.cpu.RemoveBreakpoint(static_cast<uint32_t>(argv[0].num & rl78::Rl78Bus::kAddressMask));
    r->set_long(1);
    return eOk;
}

error_t idaapi idc_rl78dbg_exec(idc_value_t *argv, idc_value_t *r) {
    rl78dbg_plugmod_t *pm = g_active_plugmod;
    if (!pm) { r->set_string("ERROR: rl78dbg plugmod not active"); return eOk; }
    std::string out;
    pm->machine.ExecuteCommand(argv[0].c_str(), out);
    pm->InvalidateFlashIfChanged();
    invalidate_dbgmem_contents(0, BADADDR);
    invalidate_dbg_state(DBGINV_REGS | DBGINV_MEMORY);
    r->set_string(out.c_str());
    return eOk;
}

error_t idaapi idc_rl78dbg_boot_swap(idc_value_t *, idc_value_t *r) {
    rl78dbg_plugmod_t *pm = g_active_plugmod;
    if (!pm) { r->set_long(-1); return eOk; }
    pm->machine.bus.SwapBootClusters();
    pm->machine.flash.SyncBootFlagFromBus();
    pm->InvalidateFlashIfChanged();
    invalidate_dbgmem_contents(0, BADADDR);
    invalidate_dbg_state(DBGINV_REGS | DBGINV_MEMORY);
    r->set_long(pm->machine.bus.IsBootSwapped() ? 1 : 0);
    return eOk;
}

const char kArgsNone[] = { 0 };
const char kArgsLong[] = { VT_LONG, 0 };
const char kArgsStr[] = { VT_STR, 0 };
const char kArgsStrLong[] = { VT_STR, VT_LONG, 0 };
const char kArgsLongLong[] = { VT_LONG, VT_LONG, 0 };

const ext_idcfunc_t kIdcFuncs[] = {
    { "rl78dbg_start",     idc_rl78dbg_start,     kArgsNone,     nullptr, 0, EXTFUN_BASE },
    { "rl78dbg_stop",      idc_rl78dbg_stop,      kArgsNone,     nullptr, 0, EXTFUN_BASE },
    { "rl78dbg_step",      idc_rl78dbg_step,      kArgsLong,     nullptr, 0, EXTFUN_BASE },
    { "rl78dbg_run_to",    idc_rl78dbg_run_to,    kArgsLongLong, nullptr, 0, EXTFUN_BASE },
    { "rl78dbg_get_reg",   idc_rl78dbg_get_reg,   kArgsStr,      nullptr, 0, EXTFUN_BASE },
    { "rl78dbg_set_reg",   idc_rl78dbg_set_reg,   kArgsStrLong,  nullptr, 0, EXTFUN_BASE },
    { "rl78dbg_read_u8",   idc_rl78dbg_read_u8,   kArgsLong,     nullptr, 0, EXTFUN_BASE },
    { "rl78dbg_write_u8",  idc_rl78dbg_write_u8,  kArgsLongLong, nullptr, 0, EXTFUN_BASE },
    { "rl78dbg_read_u16",  idc_rl78dbg_read_u16,  kArgsLong,     nullptr, 0, EXTFUN_BASE },
    { "rl78dbg_write_u16", idc_rl78dbg_write_u16, kArgsLongLong, nullptr, 0, EXTFUN_BASE },
    { "rl78dbg_add_bpt",   idc_rl78dbg_add_bpt,   kArgsLong,     nullptr, 0, EXTFUN_BASE },
    { "rl78dbg_del_bpt",   idc_rl78dbg_del_bpt,   kArgsLong,     nullptr, 0, EXTFUN_BASE },
    { "rl78dbg_exec",      idc_rl78dbg_exec,      kArgsStr,      nullptr, 0, EXTFUN_BASE },
    { "rl78dbg_boot_swap", idc_rl78dbg_boot_swap, kArgsNone,     nullptr, 0, EXTFUN_BASE },
};

void rl78dbg_plugmod_t::RegisterIdcFunctions() {
    if (!idc_registered) {
        for (const auto &fn : kIdcFuncs) add_idc_func(fn);
        idc_registered = true;
    }
}

void rl78dbg_plugmod_t::UnregisterIdcFunctions() {
    if (idc_registered) {
        for (const auto &fn : kIdcFuncs) del_idc_func(fn.name);
        idc_registered = false;
    }
}

plugmod_t *idaapi init(void) {
    if (!IsRl78Proc()) {
        return PLUGIN_SKIP;
    }
    const char *proc0 = (PH.psnames != nullptr && PH.psnames[0] != nullptr) ? PH.psnames[0] : nullptr;
    if (proc0 != nullptr) {
        g_debugger.processor = proc0;
    }
    dbg = &g_debugger;
    return new rl78dbg_plugmod_t();
}

}  // namespace

plugin_t PLUGIN = {
    IDP_INTERFACE_VERSION,
    PLUGIN_DBG | PLUGIN_PROC | PLUGIN_MULTI,
    init,
    nullptr,
    nullptr,
    "Integrated Renesas RL78 Emulator Debugger",
    "In-process Renesas RL78-S1/S2/S3 & G13 emulator debugger powered by rl78emu.",
    "RL78 rl78emu",
    ""
};
