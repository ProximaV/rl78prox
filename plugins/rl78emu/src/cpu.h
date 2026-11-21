#pragma once

#include <array>
#include <cstdint>
#include <unordered_set>

#include "memory.h"

namespace rl78 {

inline constexpr uint32_t kResetVectorAddress = 0x00000u;
inline constexpr uint32_t kBrkVectorAddress   = 0x0007Eu;
inline constexpr uint32_t kCalltTableStart    = 0x00080u;
inline constexpr uint32_t kRegBank0Base       = 0x0FFEF8u;

inline constexpr uint32_t kMacrlAddress       = 0x0FFFF0u;
inline constexpr uint32_t kMacrhAddress       = 0x0FFFF2u;
inline constexpr uint32_t kSpAddress          = 0x0FFFF8u;
inline constexpr uint32_t kPswAddress         = 0x0FFFFAu;
inline constexpr uint32_t kCsAddress          = 0x0FFFFCu;
inline constexpr uint32_t kEsAddress          = 0x0FFFFDu;
inline constexpr uint32_t kPmcAddress         = 0x0FFFFEu;
inline constexpr uint32_t kMemAddress         = 0x0FFFFFu;

enum Reg8 : uint8_t {
    REG_X = 0,
    REG_A = 1,
    REG_C = 2,
    REG_B = 3,
    REG_E = 4,
    REG_D = 5,
    REG_L = 6,
    REG_H = 7,
};

enum Reg16 : uint8_t {
    RP_AX = 0,
    RP_BC = 1,
    RP_DE = 2,
    RP_HL = 3,
};

enum PswFlag : uint8_t {
    PSW_CY   = 0x01u,
    PSW_ISP0 = 0x02u,
    PSW_ISP1 = 0x04u,
    PSW_RBS0 = 0x08u,
    PSW_AC   = 0x10u,
    PSW_RBS1 = 0x20u,
    PSW_Z    = 0x40u,
    PSW_IE   = 0x80u,
    PSW_ISP_MASK = PSW_ISP0 | PSW_ISP1,
    PSW_RBS_MASK = PSW_RBS0 | PSW_RBS1,
    PSW_RESET    = PSW_ISP0 | PSW_ISP1,  // 0x06: ISP=3 (all levels enabled), IE=0
};

enum class RunState : uint8_t {
    Running = 0,
    Halted  = 1,
    Stopped = 2,
};

enum class StopReason : uint8_t {
    None = 0,
    Breakpoint,
    Watchpoint,
    BreakInsn,
    Halt,
    Stop,
    UnmappedMemory,
    InvalidInsn,
    WdtReset,
};

struct StopInfo {
    StopReason reason = StopReason::None;
    uint32_t pc = 0;
    uint32_t detail = 0;
    bool is_write = false;
};

struct PendingInterrupt {
    bool pending = false;
    uint8_t source_index = 0;
    uint8_t priority = 3;  // 0 (highest) .. 3 (lowest)
    uint16_t vector_address = 0;
};

class InterruptControllerBase : public PeripheralDevice {
public:
    virtual PendingInterrupt EvaluatePending() const = 0;
    virtual bool HasUnmaskedPending() const = 0;
    virtual void Acknowledge(uint8_t source_index) = 0;
};

class Rl78ClockSource {
public:
    virtual ~Rl78ClockSource() = default;
    virtual void OnEnterStop() {}
    virtual void OnExitStop() {}
    virtual void LatchResetCause(uint8_t mask) { (void)mask; }
    virtual void ComputeSubClocks(uint32_t cpu_cycles,
                                  bool in_halt,
                                  bool in_stop,
                                  uint32_t *prs_cycles_out,
                                  uint32_t *sub_cycles_out,
                                  uint32_t *il_cycles_out) = 0;
};

class FlashControllerBase : public PeripheralDevice {
public:
    virtual uint32_t RomEntryAddress() const = 0;
    virtual void ExecuteFslEntry() = 0;
};

class Rl78Cpu {
public:
    Rl78Cpu();

    void AttachBus(Rl78Bus *bus);
    void AttachIntc(InterruptControllerBase *intc) { intc_ = intc; }
    void AttachClock(Rl78ClockSource *clock) { clock_ = clock; }
    void AttachFlash(FlashControllerBase *flash) { flash_ = flash; }

    void Reset();
    void ResetTo(uint32_t entry_pc);

    // Execute one instruction (or advance one standby tick when HALT/STOP).
    StopInfo Step(bool ignore_bpt_at_pc = false);

    // Control registers (masked per RL78 specification).
    uint32_t GetPC() const { return pc_ & Rl78Bus::kAddressMask; }
    void SetPC(uint32_t pc) { pc_ = pc & Rl78Bus::kAddressMask; }

    uint16_t GetSP() const { return sp_ & 0xFFFEu; }
    void SetSP(uint16_t sp) { sp_ = sp & 0xFFFEu; }

    uint8_t GetPSW() const;
    void SetPSW(uint8_t psw);

    uint8_t GetCS() const { return cs_ & 0x0Fu; }
    void SetCS(uint8_t cs) { cs_ = cs & 0x0Fu; }

    uint8_t GetES() const { return es_ & 0x0Fu; }
    void SetES(uint8_t es) { es_ = es & 0x0Fu; }

    uint8_t GetPMC() const { return pmc_ & 0x01u; }
    void SetPMC(uint8_t pmc);

    uint8_t GetMEM() const { return mem_; }
    void SetMEM(uint8_t mem) { mem_ = mem; }

    uint32_t GetMACR() const { return macr_; }
    void SetMACR(uint32_t macr) { macr_ = macr; }
    uint16_t GetMACRL() const { return static_cast<uint16_t>(macr_ & 0xFFFFu); }
    uint16_t GetMACRH() const { return static_cast<uint16_t>((macr_ >> 16) & 0xFFFFu); }

    uint8_t GetRB() const {
        if (bus_ && bus_->Core() == CoreProfile::S1) {
            return 0u;
        }
        return static_cast<uint8_t>(((psw_ & PSW_RBS1) >> 4) | ((psw_ & PSW_RBS0) >> 3));
    }
    void SetRB(uint8_t rb) {
        if (bus_ && bus_->Core() == CoreProfile::S1) {
            psw_ &= ~PSW_RBS_MASK;
            return;
        }
        const uint8_t b = rb & 3u;
        SetPSW(static_cast<uint8_t>((psw_ & ~PSW_RBS_MASK) | ((b & 1u) << 3) | ((b & 2u) << 4)));
    }

    uint8_t GetISP() const { return static_cast<uint8_t>((psw_ >> 1) & 3u); }
    bool GetCY() const { return (psw_ & PSW_CY) != 0; }
    void SetCY(bool cy) {
        if (cy) psw_ |= PSW_CY;
        else psw_ &= ~PSW_CY;
    }

    static constexpr uint32_t AddressOfReg(uint8_t reg, uint8_t bank) {
        return kRegBank0Base - static_cast<uint32_t>(bank & 3u) * 8u + (reg & 7u);
    }
    uint8_t ReadReg(uint8_t reg) const { return ReadRegBank(reg, GetRB()); }
    void WriteReg(uint8_t reg, uint8_t val) { WriteRegBank(reg, GetRB(), val); }
    uint16_t ReadRegPair(uint8_t rp) const { return ReadRegPairBank(rp, GetRB()); }
    void WriteRegPair(uint8_t rp, uint16_t val) { WriteRegPairBank(rp, GetRB(), val); }

    uint8_t ReadRegBank(uint8_t reg, uint8_t bank) const;
    void WriteRegBank(uint8_t reg, uint8_t bank, uint8_t val);
    uint16_t ReadRegPairBank(uint8_t rp, uint8_t bank) const;
    void WriteRegPairBank(uint8_t rp, uint8_t bank, uint16_t val);

    // Breakpoint management (20-bit addresses).
    void AddBreakpoint(uint32_t addr);
    void RemoveBreakpoint(uint32_t addr);
    void ClearBreakpoints();
    bool HasBreakpoint(uint32_t addr) const;

    // Standby & runtime statistics.
    RunState GetRunState() const { return run_state_; }
    void SetRunState(RunState state) { run_state_ = state; }
    uint64_t TotalCycles() const { return total_cycles_; }
    uint32_t LastInsnCycles() const { return inst_cycles_; }
    uint64_t InstructionCount() const { return insn_count_; }
    bool IsInterruptDelayed() const { return interrupt_delayed_; }
    void RequestWdtReset() { wdt_reset_pending_ = true; }

    // Execution stop flags.
    bool stop_on_brk = false;   // If false, BRK vectors through 0x0007E when valid.
    bool stop_on_halt = false;  // If true, HALT breaks to debugger instead of idling.
    bool stop_on_stop = false;  // If true, STOP breaks to debugger instead of idling.

private:
    class CoreSfrDevice final : public PeripheralDevice {
    public:
        explicit CoreSfrDevice(Rl78Cpu *cpu) : cpu_(cpu) {}
        uint8_t Read(uint32_t addr) override;
        void Write(uint32_t addr, uint8_t value) override;
        uint8_t Peek(uint32_t addr) const override;
        void Poke(uint32_t addr, uint8_t value) override;
    private:
        Rl78Cpu *cpu_;
    };

    void CheckInterruptHold(uint32_t addr);
    void TickBus(uint32_t cycles, bool in_halt, bool in_stop);
    void DispatchInterruptIfReady();

    uint8_t ConsumeByte();
    uint16_t ConsumeWord();
    uint32_t ConsumeAddr20();
    uint32_t ConsumeSfr();
    uint32_t ConsumeSfrP();
    uint32_t ConsumeSaddr();
    uint32_t ConsumeSaddrP();
    uint32_t ConsumeDataAddr16();
    uint32_t ConsumeCodeAddr16();
    uint32_t ConsumeRel8();
    uint32_t ConsumeRel16();

    uint8_t BusRead8(uint32_t addr);
    void BusWrite8(uint32_t addr, uint8_t value);
    uint16_t BusRead16(uint32_t addr);
    void BusWrite16(uint32_t addr, uint16_t value);

    void PushWord16(uint16_t val);
    uint16_t PopWord16();
    void PushCallFrame(uint32_t ret_pc);
    uint32_t PopCallFrame();
    void PushInterruptFrame(uint32_t ret_pc, uint8_t psw_snapshot);
    void PopInterruptFrame();

    uint32_t ResolveBasedHlImm(uint8_t disp);
    uint32_t ResolveBasedDeImm(uint8_t disp);
    uint32_t ResolveBasedSpImm(uint8_t disp) const;
    uint32_t ResolveBasedHlReg(uint8_t reg_idx);
    uint32_t ResolveIndirect(uint8_t rp);
    uint32_t ResolveWordIndexed(uint16_t base_word, uint16_t offset_val);

    void SetFlagsZAcCy(bool z, bool ac, bool cy);
    uint8_t OpAdd8(uint8_t a, uint8_t b, bool with_carry);
    uint8_t OpSub8(uint8_t a, uint8_t b, bool with_borrow, bool write_back);
    uint8_t OpAnd8(uint8_t a, uint8_t b);
    uint8_t OpOr8(uint8_t a, uint8_t b);
    uint8_t OpXor8(uint8_t a, uint8_t b);
    uint8_t OpInc8(uint8_t val);
    uint8_t OpDec8(uint8_t val);
    uint16_t OpAdd16(uint16_t a, uint16_t b);
    uint16_t OpSub16(uint16_t a, uint16_t b, bool write_back);

    void ExecuteNextInstruction();
    void ExecuteMap1(uint8_t code);
    void ExecuteMap2_61(uint8_t code);
    void ExecuteMap3_71(uint8_t code);
    void ExecuteMap4_31(uint8_t code);
    void ExecuteS3Extended();
    void PerformSkipIfTrue(bool cond);
    void SkipNextInstruction();

    CoreSfrDevice core_sfr_dev_;
    Rl78Bus *bus_ = nullptr;
    InterruptControllerBase *intc_ = nullptr;
    Rl78ClockSource *clock_ = nullptr;
    FlashControllerBase *flash_ = nullptr;

    uint32_t pc_ = 0;
    uint16_t sp_ = 0;
    uint8_t psw_ = PSW_RESET;
    uint8_t cs_ = 0;
    uint8_t es_ = 0x0Fu;
    uint8_t pmc_ = 0x00u;
    uint8_t mem_ = 0x00u;
    uint32_t macr_ = 0;

    RunState run_state_ = RunState::Running;
    uint64_t total_cycles_ = 0;
    uint32_t inst_cycles_ = 0;
    uint64_t insn_count_ = 0;

    bool interrupt_delayed_ = false;
    bool wdt_reset_pending_ = false;

    // Per-instruction transient execution state.
    bool has_es_ = false;
    bool es_used_ = false;
    bool invalid_insn_ = false;
    bool brk_stopped_ = false;
    bool halt_entered_ = false;
    bool stop_entered_ = false;
    uint32_t current_insn_pc_ = 0;
    uint32_t last_invalid_opcode_ = 0;

    std::unordered_set<uint32_t> breakpoints_;
};

}  // namespace rl78
