#include "cpu.h"

#include "log.h"

namespace rl78 {

namespace {

inline uint16_t MakeWord(uint8_t lo, uint8_t hi) {
    return static_cast<uint16_t>(lo) | (static_cast<uint16_t>(hi) << 8);
}

inline uint8_t Map31AluIndex(uint8_t op) {
    return op;
}

}  // namespace

// ============================================================================
// CoreSfrDevice (0xFFFF0..0xFFFF3, 0xFFFF8..0xFFFFA, 0xFFFFC..0xFFFFF)
// ============================================================================

uint8_t Rl78Cpu::CoreSfrDevice::Read(uint32_t addr) {
    return Peek(addr);
}

void Rl78Cpu::CoreSfrDevice::Write(uint32_t addr, uint8_t value) {
    Poke(addr, value);
    if (cpu_) {
        cpu_->CheckInterruptHold(addr);
    }
}

uint8_t Rl78Cpu::CoreSfrDevice::Peek(uint32_t addr) const {
    if (!cpu_) return 0;
    switch (addr) {
    case kMacrlAddress:      return static_cast<uint8_t>(cpu_->macr_ & 0xFFu);
    case kMacrlAddress + 1u: return static_cast<uint8_t>((cpu_->macr_ >> 8) & 0xFFu);
    case kMacrhAddress:      return static_cast<uint8_t>((cpu_->macr_ >> 16) & 0xFFu);
    case kMacrhAddress + 1u: return static_cast<uint8_t>((cpu_->macr_ >> 24) & 0xFFu);
    case kSpAddress:         return static_cast<uint8_t>(cpu_->GetSP() & 0xFFu);
    case kSpAddress + 1u:    return static_cast<uint8_t>((cpu_->GetSP() >> 8) & 0xFFu);
    case kPswAddress:        return cpu_->GetPSW();
    case kCsAddress:         return cpu_->GetCS();
    case kEsAddress:         return cpu_->GetES();
    case kPmcAddress:        return cpu_->GetPMC();
    case kMemAddress:        return cpu_->GetMEM();
    default:                 return 0xFFu;
    }
}

void Rl78Cpu::CoreSfrDevice::Poke(uint32_t addr, uint8_t value) {
    if (!cpu_) return;
    switch (addr) {
    case kMacrlAddress:
        cpu_->macr_ = (cpu_->macr_ & 0xFFFFFF00u) | value;
        break;
    case kMacrlAddress + 1u:
        cpu_->macr_ = (cpu_->macr_ & 0xFFFF00FFu) | (static_cast<uint32_t>(value) << 8);
        break;
    case kMacrhAddress:
        cpu_->macr_ = (cpu_->macr_ & 0xFF00FFFFu) | (static_cast<uint32_t>(value) << 16);
        break;
    case kMacrhAddress + 1u:
        cpu_->macr_ = (cpu_->macr_ & 0x00FFFFFFu) | (static_cast<uint32_t>(value) << 24);
        break;
    case kSpAddress:
        cpu_->SetSP(static_cast<uint16_t>((cpu_->sp_ & 0xFF00u) | value));
        break;
    case kSpAddress + 1u:
        cpu_->SetSP(static_cast<uint16_t>((cpu_->sp_ & 0x00FFu) | (static_cast<uint16_t>(value) << 8)));
        break;
    case kPswAddress:
        cpu_->SetPSW(value);
        break;
    case kCsAddress:
        cpu_->SetCS(value);
        break;
    case kEsAddress:
        cpu_->SetES(value);
        break;
    case kPmcAddress:
        cpu_->SetPMC(value);
        break;
    case kMemAddress:
        cpu_->SetMEM(value);
        break;
    default:
        break;
    }
}

// ============================================================================
// Rl78Cpu lifecycle & register access
// ============================================================================

Rl78Cpu::Rl78Cpu() : core_sfr_dev_(this) {}

void Rl78Cpu::AttachBus(Rl78Bus *bus) {
    bus_ = bus;
    if (bus_) {
        bus_->MapSfrRange(kMacrlAddress, kMacrhAddress + 1u, &core_sfr_dev_);
        bus_->MapSfrRange(kSpAddress, kPswAddress, &core_sfr_dev_);
        bus_->MapSfrRange(kCsAddress, kMemAddress, &core_sfr_dev_);
    }
}

void Rl78Cpu::Reset() {
    uint32_t entry = 0;
    if (bus_) {
        const uint8_t lo = bus_->PeekByte(kResetVectorAddress);
        const uint8_t hi = bus_->PeekByte(kResetVectorAddress + 1u);
        entry = MakeWord(lo, hi);
    }
    ResetTo(entry);
}

void Rl78Cpu::ResetTo(uint32_t entry_pc) {
    SetPSW(PSW_RESET);
    SetSP(0x0000u);
    SetCS(0x00u);
    SetES(0x0Fu);
    SetPMC(0x00u);
    SetMEM(0x00u);
    macr_ = 0;
    pc_ = entry_pc & Rl78Bus::kAddressMask;
    run_state_ = RunState::Running;
    total_cycles_ = 0;
    inst_cycles_ = 0;
    insn_count_ = 0;
    interrupt_delayed_ = false;
    wdt_reset_pending_ = false;
    has_es_ = false;
    es_used_ = false;
    invalid_insn_ = false;
    brk_stopped_ = false;
    halt_entered_ = false;
    stop_entered_ = false;
    current_insn_pc_ = pc_;
    last_invalid_opcode_ = 0;
}

uint8_t Rl78Cpu::GetPSW() const {
    if (bus_ && bus_->Core() == CoreProfile::S1) {
        return psw_ & static_cast<uint8_t>(~PSW_RBS_MASK);
    }
    return psw_;
}

void Rl78Cpu::SetPSW(uint8_t psw) {
    if (bus_ && bus_->Core() == CoreProfile::S1) {
        psw_ = psw & static_cast<uint8_t>(~PSW_RBS_MASK);
    } else {
        psw_ = psw;
    }
}

void Rl78Cpu::SetPMC(uint8_t pmc) {
    pmc_ = pmc & 0x01u;
    if (bus_) {
        bus_->SetMirrorAreaAlt((pmc_ & 0x01u) != 0);
    }
}

uint8_t Rl78Cpu::ReadRegBank(uint8_t reg, uint8_t bank) const {
    if (!bus_) return 0;
    const uint8_t effective_bank = (bus_->Core() == CoreProfile::S1) ? 0u : (bank & 3u);
    return bus_->PeekByte(AddressOfReg(reg, effective_bank));
}

void Rl78Cpu::WriteRegBank(uint8_t reg, uint8_t bank, uint8_t val) {
    if (!bus_) return;
    const uint8_t effective_bank = (bus_->Core() == CoreProfile::S1) ? 0u : (bank & 3u);
    bus_->PokeByte(AddressOfReg(reg, effective_bank), val);
}

uint16_t Rl78Cpu::ReadRegPairBank(uint8_t rp, uint8_t bank) const {
    const uint8_t lo = ReadRegBank(static_cast<uint8_t>((rp & 3u) << 1), bank);
    const uint8_t hi = ReadRegBank(static_cast<uint8_t>(((rp & 3u) << 1) + 1u), bank);
    return MakeWord(lo, hi);
}

void Rl78Cpu::WriteRegPairBank(uint8_t rp, uint8_t bank, uint16_t val) {
    WriteRegBank(static_cast<uint8_t>((rp & 3u) << 1), bank, static_cast<uint8_t>(val & 0xFFu));
    WriteRegBank(static_cast<uint8_t>(((rp & 3u) << 1) + 1u), bank, static_cast<uint8_t>((val >> 8) & 0xFFu));
}

void Rl78Cpu::AddBreakpoint(uint32_t addr) {
    breakpoints_.insert(addr & Rl78Bus::kAddressMask);
}

void Rl78Cpu::RemoveBreakpoint(uint32_t addr) {
    breakpoints_.erase(addr & Rl78Bus::kAddressMask);
}

void Rl78Cpu::ClearBreakpoints() {
    breakpoints_.clear();
}

bool Rl78Cpu::HasBreakpoint(uint32_t addr) const {
    return breakpoints_.find(addr & Rl78Bus::kAddressMask) != breakpoints_.end();
}

void Rl78Cpu::CheckInterruptHold(uint32_t addr) {
    if (addr == kPswAddress ||
        (addr >= 0x0FFFD0u && addr <= 0x0FFFDFu) ||
        (addr >= 0x0FFFE0u && addr <= 0x0FFFEFu)) {
        interrupt_delayed_ = true;
    }
}

void Rl78Cpu::TickBus(uint32_t cycles, bool in_halt, bool in_stop) {
    if (!bus_ || cycles == 0) {
        return;
    }
    uint32_t prs = cycles;
    uint32_t sub = 0;
    uint32_t il = 0;
    if (clock_) {
        clock_->ComputeSubClocks(cycles, in_halt, in_stop, &prs, &sub, &il);
    }
    bus_->TickDevices((in_halt || in_stop) ? 0u : cycles, prs, sub, il, in_halt, in_stop);
}

void Rl78Cpu::DispatchInterruptIfReady() {
    if (!intc_) {
        return;
    }
    if (interrupt_delayed_) {
        interrupt_delayed_ = false;
        return;
    }
    const uint8_t psw = GetPSW();
    if ((psw & PSW_IE) == 0) {
        return;
    }
    const PendingInterrupt pending = intc_->EvaluatePending();
    if (!pending.pending) {
        return;
    }
    const uint8_t current_isp = GetISP();
    if (pending.priority > current_isp) {
        return;
    }

    intc_->Acknowledge(pending.source_index);
    const uint8_t saved_psw = psw;
    const uint8_t next_isp = (pending.priority == 0) ? 0u : static_cast<uint8_t>(pending.priority - 1u);
    uint8_t next_psw = static_cast<uint8_t>((saved_psw & ~(PSW_IE | PSW_ISP_MASK)) |
                                            ((next_isp & 3u) << 1));
    SetPSW(next_psw);
    PushInterruptFrame(pc_, saved_psw);
    const uint8_t lo = bus_->PeekByte(pending.vector_address);
    const uint8_t hi = bus_->PeekByte(pending.vector_address + 1u);
    pc_ = MakeWord(lo, hi);
}

StopInfo Rl78Cpu::Step(bool ignore_bpt_at_pc) {
    if (!bus_) {
        return StopInfo{StopReason::InvalidInsn, pc_, 0, false};
    }

    bus_->ClearFaults();
    invalid_insn_ = false;
    brk_stopped_ = false;
    halt_entered_ = false;
    stop_entered_ = false;
    wdt_reset_pending_ = false;
    current_insn_pc_ = pc_;

    if (!ignore_bpt_at_pc && HasBreakpoint(pc_)) {
        return StopInfo{StopReason::Breakpoint, pc_, 0, false};
    }

    // Standby states (HALT / STOP): clock peripherals until an unmasked interrupt releases standby.
    if (run_state_ == RunState::Halted || run_state_ == RunState::Stopped) {
        const bool was_stop = (run_state_ == RunState::Stopped);
        const uint32_t standby_cycles = 2u;
        inst_cycles_ = standby_cycles;
        total_cycles_ += standby_cycles;
        TickBus(standby_cycles, !was_stop, was_stop);

        if (wdt_reset_pending_) {
            wdt_reset_pending_ = false;
            return StopInfo{StopReason::WdtReset, pc_, 0, false};
        }

        if (intc_ && intc_->HasUnmaskedPending()) {
            if (was_stop && clock_) {
                clock_->OnExitStop();
            }
            run_state_ = RunState::Running;
            DispatchInterruptIfReady();
        }
        return StopInfo{StopReason::None, pc_, 0, false};
    }

    inst_cycles_ = 0;
    ExecuteNextInstruction();
    total_cycles_ += inst_cycles_;

    if (invalid_insn_) {
        pc_ = current_insn_pc_;
        return StopInfo{StopReason::InvalidInsn, current_insn_pc_, last_invalid_opcode_, false};
    }

    ++insn_count_;

    TickBus(inst_cycles_, halt_entered_, stop_entered_);

    if (wdt_reset_pending_) {
        wdt_reset_pending_ = false;
        return StopInfo{StopReason::WdtReset, pc_, 0, false};
    }
    if (brk_stopped_) {
        return StopInfo{StopReason::BreakInsn, current_insn_pc_, 0, false};
    }
    if (bus_->unmapped_fault) {
        return StopInfo{StopReason::UnmappedMemory, current_insn_pc_, bus_->fault_addr, bus_->fault_is_write};
    }
    if (bus_->watchpoint_hit) {
        return StopInfo{StopReason::Watchpoint, current_insn_pc_, bus_->watchpoint_addr, bus_->watchpoint_is_write};
    }

    if (halt_entered_) {
        if (stop_on_halt) {
            run_state_ = RunState::Halted;
            return StopInfo{StopReason::Halt, current_insn_pc_, 0, false};
        }
        if (intc_ && intc_->HasUnmaskedPending()) {
            run_state_ = RunState::Running;
            DispatchInterruptIfReady();
        } else {
            run_state_ = RunState::Halted;
        }
        return StopInfo{StopReason::None, pc_, 0, false};
    }

    if (stop_entered_) {
        if (stop_on_stop) {
            run_state_ = RunState::Stopped;
            return StopInfo{StopReason::Stop, current_insn_pc_, 0, false};
        }
        if (intc_ && intc_->HasUnmaskedPending()) {
            if (clock_) {
                clock_->OnExitStop();
            }
            run_state_ = RunState::Running;
            DispatchInterruptIfReady();
        } else {
            run_state_ = RunState::Stopped;
        }
        return StopInfo{StopReason::None, pc_, 0, false};
    }

    DispatchInterruptIfReady();
    return StopInfo{StopReason::None, pc_, 0, false};
}

// ============================================================================
// Instruction fetch & bus access helpers
// ============================================================================

uint8_t Rl78Cpu::ConsumeByte() {
    ++inst_cycles_;
    const uint8_t v = bus_->FetchByte(pc_);
    pc_ = (pc_ + 1u) & Rl78Bus::kAddressMask;
    return v;
}

uint16_t Rl78Cpu::ConsumeWord() {
    const uint8_t lo = ConsumeByte();
    const uint8_t hi = ConsumeByte();
    return MakeWord(lo, hi);
}

uint32_t Rl78Cpu::ConsumeAddr20() {
    const uint8_t lo = ConsumeByte();
    const uint8_t mid = ConsumeByte();
    const uint8_t hi = ConsumeByte() & 0x0Fu;
    return static_cast<uint32_t>(lo) |
           (static_cast<uint32_t>(mid) << 8) |
           (static_cast<uint32_t>(hi) << 16);
}

uint32_t Rl78Cpu::ConsumeSfr() {
    return Rl78Bus::ResolveSfr(ConsumeByte());
}

uint32_t Rl78Cpu::ConsumeSfrP() {
    return Rl78Bus::ResolveSfr(ConsumeByte());
}

uint32_t Rl78Cpu::ConsumeSaddr() {
    return Rl78Bus::ResolveSaddr(ConsumeByte());
}

uint32_t Rl78Cpu::ConsumeSaddrP() {
    return Rl78Bus::ResolveSaddr(ConsumeByte());
}

uint32_t Rl78Cpu::ConsumeDataAddr16() {
    const uint16_t addr16 = ConsumeWord();
    if (has_es_) {
        es_used_ = true;
    }
    return Rl78Bus::ResolveWithEs(addr16, has_es_, es_);
}

uint32_t Rl78Cpu::ConsumeCodeAddr16() {
    return static_cast<uint32_t>(ConsumeWord());
}

uint32_t Rl78Cpu::ConsumeRel8() {
    const int8_t disp = static_cast<int8_t>(ConsumeByte());
    return static_cast<uint32_t>(static_cast<int32_t>(pc_) + disp) & Rl78Bus::kAddressMask;
}

uint32_t Rl78Cpu::ConsumeRel16() {
    const int16_t disp = static_cast<int16_t>(ConsumeWord());
    return static_cast<uint32_t>(static_cast<int32_t>(pc_) + disp) & Rl78Bus::kAddressMask;
}

uint8_t Rl78Cpu::BusRead8(uint32_t addr) {
    addr &= Rl78Bus::kAddressMask;
    inst_cycles_ += (addr < Rl78Bus::kNearBase) ? 3u : 1u;
    return bus_->ReadCpu(addr);
}

void Rl78Cpu::BusWrite8(uint32_t addr, uint8_t value) {
    addr &= Rl78Bus::kAddressMask;
    ++inst_cycles_;
    bus_->WriteCpu(addr, value);
    CheckInterruptHold(addr);
}

uint16_t Rl78Cpu::BusRead16(uint32_t addr) {
    const uint8_t lo = BusRead8(addr);
    const uint8_t hi = BusRead8((addr + 1u) & Rl78Bus::kAddressMask);
    return MakeWord(lo, hi);
}

void Rl78Cpu::BusWrite16(uint32_t addr, uint16_t value) {
    BusWrite8(addr, static_cast<uint8_t>(value & 0xFFu));
    BusWrite8((addr + 1u) & Rl78Bus::kAddressMask, static_cast<uint8_t>((value >> 8) & 0xFFu));
}

void Rl78Cpu::PushWord16(uint16_t val) {
    const uint16_t new_sp = static_cast<uint16_t>((sp_ - 2u) & 0xFFFEu);
    SetSP(new_sp);
    BusWrite16(Rl78Bus::ResolveNear(new_sp), val);
}

uint16_t Rl78Cpu::PopWord16() {
    const uint16_t cur_sp = GetSP();
    const uint16_t val = BusRead16(Rl78Bus::ResolveNear(cur_sp));
    SetSP(static_cast<uint16_t>((cur_sp + 2u) & 0xFFFEu));
    return val;
}

void Rl78Cpu::PushCallFrame(uint32_t ret_pc) {
    const uint16_t new_sp = static_cast<uint16_t>((sp_ - 4u) & 0xFFFEu);
    SetSP(new_sp);
    const uint32_t base = Rl78Bus::ResolveNear(new_sp);
    BusWrite8(base + 0u, static_cast<uint8_t>(ret_pc & 0xFFu));
    BusWrite8(base + 1u, static_cast<uint8_t>((ret_pc >> 8) & 0xFFu));
    BusWrite8(base + 2u, static_cast<uint8_t>((ret_pc >> 16) & 0x0Fu));
    BusWrite8(base + 3u, 0x00u);
}

uint32_t Rl78Cpu::PopCallFrame() {
    const uint16_t cur_sp = GetSP();
    const uint32_t base = Rl78Bus::ResolveNear(cur_sp);
    const uint8_t b0 = BusRead8(base + 0u);
    const uint8_t b1 = BusRead8(base + 1u);
    const uint8_t b2 = BusRead8(base + 2u) & 0x0Fu;
    (void)BusRead8(base + 3u);
    SetSP(static_cast<uint16_t>((cur_sp + 4u) & 0xFFFEu));
    return static_cast<uint32_t>(b0) |
           (static_cast<uint32_t>(b1) << 8) |
           (static_cast<uint32_t>(b2) << 16);
}

void Rl78Cpu::PushInterruptFrame(uint32_t ret_pc, uint8_t psw_snapshot) {
    const uint16_t new_sp = static_cast<uint16_t>((sp_ - 4u) & 0xFFFEu);
    SetSP(new_sp);
    const uint32_t base = Rl78Bus::ResolveNear(new_sp);
    BusWrite8(base + 0u, static_cast<uint8_t>(ret_pc & 0xFFu));
    BusWrite8(base + 1u, static_cast<uint8_t>((ret_pc >> 8) & 0xFFu));
    BusWrite8(base + 2u, static_cast<uint8_t>((ret_pc >> 16) & 0x0Fu));
    BusWrite8(base + 3u, psw_snapshot);
}

void Rl78Cpu::PopInterruptFrame() {
    const uint16_t cur_sp = GetSP();
    const uint32_t base = Rl78Bus::ResolveNear(cur_sp);
    const uint8_t b0 = BusRead8(base + 0u);
    const uint8_t b1 = BusRead8(base + 1u);
    const uint8_t b2 = BusRead8(base + 2u) & 0x0Fu;
    const uint8_t restored_psw = BusRead8(base + 3u);
    SetSP(static_cast<uint16_t>((cur_sp + 4u) & 0xFFFEu));
    SetPSW(restored_psw);
    interrupt_delayed_ = true;
    pc_ = static_cast<uint32_t>(b0) |
          (static_cast<uint32_t>(b1) << 8) |
          (static_cast<uint32_t>(b2) << 16);
}

uint32_t Rl78Cpu::ResolveBasedHlImm(uint8_t disp) {
    const uint16_t ea16 = static_cast<uint16_t>(ReadRegPair(RP_HL) + disp);
    if (has_es_) {
        es_used_ = true;
    }
    return Rl78Bus::ResolveWithEs(ea16, has_es_, es_);
}

uint32_t Rl78Cpu::ResolveBasedDeImm(uint8_t disp) {
    const uint16_t ea16 = static_cast<uint16_t>(ReadRegPair(RP_DE) + disp);
    if (has_es_) {
        es_used_ = true;
    }
    return Rl78Bus::ResolveWithEs(ea16, has_es_, es_);
}

uint32_t Rl78Cpu::ResolveBasedSpImm(uint8_t disp) const {
    const uint16_t ea16 = static_cast<uint16_t>(GetSP() + disp);
    return Rl78Bus::ResolveNear(ea16);
}

uint32_t Rl78Cpu::ResolveBasedHlReg(uint8_t reg_idx) {
    const uint16_t ea16 = static_cast<uint16_t>(ReadRegPair(RP_HL) + ReadReg(reg_idx));
    if (has_es_) {
        es_used_ = true;
    }
    return Rl78Bus::ResolveWithEs(ea16, has_es_, es_);
}

uint32_t Rl78Cpu::ResolveIndirect(uint8_t rp) {
    const uint16_t ea16 = ReadRegPair(rp);
    if (has_es_) {
        es_used_ = true;
    }
    return Rl78Bus::ResolveWithEs(ea16, has_es_, es_);
}

uint32_t Rl78Cpu::ResolveWordIndexed(uint16_t base_word, uint16_t offset_val) {
    if (has_es_) {
        es_used_ = true;
        return ((static_cast<uint32_t>(es_ & 0x0Fu) << 16) + base_word + offset_val) & Rl78Bus::kAddressMask;
    }
    const uint16_t ea16 = static_cast<uint16_t>(base_word + offset_val);
    return Rl78Bus::ResolveNear(ea16);
}

// ============================================================================
// ALU & Flag Helpers
// ============================================================================

void Rl78Cpu::SetFlagsZAcCy(bool z, bool ac, bool cy) {
    uint8_t p = psw_ & static_cast<uint8_t>(~(PSW_Z | PSW_AC | PSW_CY));
    if (z)  p |= PSW_Z;
    if (ac) p |= PSW_AC;
    if (cy) p |= PSW_CY;
    psw_ = p;
}

uint8_t Rl78Cpu::OpAdd8(uint8_t a, uint8_t b, bool with_carry) {
    const uint16_t c = (with_carry && GetCY()) ? 1u : 0u;
    const uint16_t sum = static_cast<uint16_t>(a) + b + c;
    const uint8_t res = static_cast<uint8_t>(sum & 0xFFu);
    const bool ac = ((a & 0x0Fu) + (b & 0x0Fu) + c) > 0x0Fu;
    SetFlagsZAcCy(res == 0, ac, sum > 0xFFu);
    return res;
}

uint8_t Rl78Cpu::OpSub8(uint8_t a, uint8_t b, bool with_borrow, bool write_back) {
    (void)write_back;
    const uint16_t c = (with_borrow && GetCY()) ? 1u : 0u;
    const int32_t diff = static_cast<int32_t>(a) - static_cast<int32_t>(b) - static_cast<int32_t>(c);
    const uint8_t res = static_cast<uint8_t>(diff & 0xFF);
    const bool ac = (static_cast<int32_t>(a & 0x0Fu) - static_cast<int32_t>(b & 0x0Fu) - static_cast<int32_t>(c)) < 0;
    SetFlagsZAcCy(res == 0, ac, diff < 0);
    return res;
}

uint8_t Rl78Cpu::OpAnd8(uint8_t a, uint8_t b) {
    const uint8_t res = static_cast<uint8_t>(a & b);
    if (res == 0) psw_ |= PSW_Z;
    else psw_ &= static_cast<uint8_t>(~PSW_Z);
    return res;
}

uint8_t Rl78Cpu::OpOr8(uint8_t a, uint8_t b) {
    const uint8_t res = static_cast<uint8_t>(a | b);
    if (res == 0) psw_ |= PSW_Z;
    else psw_ &= static_cast<uint8_t>(~PSW_Z);
    return res;
}

uint8_t Rl78Cpu::OpXor8(uint8_t a, uint8_t b) {
    const uint8_t res = static_cast<uint8_t>(a ^ b);
    if (res == 0) psw_ |= PSW_Z;
    else psw_ &= static_cast<uint8_t>(~PSW_Z);
    return res;
}

uint8_t Rl78Cpu::OpInc8(uint8_t val) {
    const uint8_t res = static_cast<uint8_t>(val + 1u);
    const bool ac = ((val & 0x0Fu) + 1u) > 0x0Fu;
    SetFlagsZAcCy(res == 0, ac, GetCY());
    return res;
}

uint8_t Rl78Cpu::OpDec8(uint8_t val) {
    const uint8_t res = static_cast<uint8_t>(val - 1u);
    const bool ac = (val & 0x0Fu) == 0u;
    SetFlagsZAcCy(res == 0, ac, GetCY());
    return res;
}

uint16_t Rl78Cpu::OpAdd16(uint16_t a, uint16_t b) {
    const uint32_t sum = static_cast<uint32_t>(a) + b;
    const uint16_t res = static_cast<uint16_t>(sum & 0xFFFFu);
    const bool ac = ((a & 0x0FFFu) + (b & 0x0FFFu)) > 0x0FFFu;
    SetFlagsZAcCy(res == 0, ac, sum > 0xFFFFu);
    return res;
}

uint16_t Rl78Cpu::OpSub16(uint16_t a, uint16_t b, bool write_back) {
    (void)write_back;
    const int32_t diff = static_cast<int32_t>(a) - static_cast<int32_t>(b);
    const uint16_t res = static_cast<uint16_t>(diff & 0xFFFF);
    const bool ac = (a & 0x0FFFu) < (b & 0x0FFFu);
    SetFlagsZAcCy(res == 0, ac, diff < 0);
    return res;
}

// ============================================================================
// Execution Engine
// ============================================================================

void Rl78Cpu::ExecuteNextInstruction() {
    has_es_ = false;
    es_used_ = false;

    if (flash_ && pc_ == flash_->RomEntryAddress()) {
        flash_->ExecuteFslEntry();
    }

    uint8_t code = ConsumeByte();
    if (code == 0x11u) {
        has_es_ = true;
        code = ConsumeByte();
    }

    ExecuteMap1(code);

    if (!invalid_insn_ && has_es_ && !es_used_) {
        invalid_insn_ = true;
        last_invalid_opcode_ = (static_cast<uint32_t>(0x11u) << 8) | code;
    }
}

void Rl78Cpu::PerformSkipIfTrue(bool cond) {
    if (cond) {
        SkipNextInstruction();
    }
}

void Rl78Cpu::SkipNextInstruction() {
    // Advance PC past the full length of the next instruction without modifying architectural state.
    bool next_es = false;
    uint8_t code = ConsumeByte();
    if (code == 0x11u) {
        next_es = true;
        code = ConsumeByte();
    }
    (void)next_es;

    const uint8_t lo = code & 0x0Fu;
    const uint8_t hi = (code >> 4) & 0x0Fu;

    if (lo >= 0xAu && hi <= 0x7u) {
        switch (lo) {
        case 0xAu: ConsumeByte(); ConsumeByte(); return;  // saddr, #byte
        case 0xBu:
        case 0xCu:
        case 0xEu: ConsumeByte(); return;                 // saddr / #byte / [hl+byte]
        case 0xDu: return;                                // [hl]
        case 0xFu: ConsumeWord(); return;                 // !addr16
        }
    }

    if (code == 0x31u) {
        const uint8_t m4 = ConsumeByte();
        const uint8_t m4_lo = m4 & 0x0Fu;
        if (m4_lo <= 5u) {
            if ((m4 & 0x81u) == 0x00u || (m4 & 0x81u) == 0x80u) {
                ConsumeByte();  // saddr or sfr
            }
            ConsumeByte();      // $rel
        }
        return;
    }

    if (code == 0x61u) {
        const uint8_t m2 = ConsumeByte();
        switch (m2) {
        case 0x09u: case 0x29u: case 0x49u: case 0x59u:
        case 0x69u: case 0x79u: case 0x89u:
        case 0xA8u: case 0xB8u: case 0xADu: case 0xAFu:
        case 0xABu: case 0xC3u: case 0xD3u: case 0xCEu: case 0xDEu:
            ConsumeByte();
            return;
        case 0xAAu:
            ConsumeWord();
            return;
        default:
            return;
        }
    }

    if (code == 0x71u) {
        const uint8_t m3 = ConsumeByte();
        const uint8_t m3_lo = m3 & 0x0Fu;
        const uint8_t m3_hi = (m3 >> 4) & 0x0Fu;
        if ((m3_hi >= 8u && (m3_lo == 0u || m3_lo == 8u))) {
            return;  // set1/clr1/not1 cy
        }
        switch (m3 & 0x8Fu) {
        case 0x00u: case 0x08u:
            ConsumeWord();
            return;
        case 0x01u: case 0x02u: case 0x03u:
        case 0x04u: case 0x05u: case 0x06u: case 0x07u:
        case 0x09u: case 0x0Au: case 0x0Bu:
        case 0x0Cu: case 0x0Du: case 0x0Eu: case 0x0Fu:
            ConsumeByte();
            return;
        default:
            return;
        }
    }

    switch (code) {
    // 2-byte Map 1 instructions
    case 0x10u: case 0x20u: case 0x41u:
    case 0x50u: case 0x51u: case 0x52u: case 0x53u:
    case 0x54u: case 0x55u: case 0x56u: case 0x57u:
    case 0x88u: case 0x8Au: case 0x8Cu: case 0x8Du: case 0x8Eu:
    case 0x98u: case 0x9Au: case 0x9Cu: case 0x9Du: case 0x9Eu:
    case 0xA4u: case 0xB4u: case 0xA6u: case 0xB6u:
    case 0xA8u: case 0xB8u: case 0xAAu: case 0xBAu:
    case 0xACu: case 0xBCu: case 0xADu: case 0xBDu: case 0xAEu: case 0xBEu:
    case 0xD4u: case 0xD8u: case 0xE8u: case 0xF8u:
    case 0xDAu: case 0xEAu: case 0xFAu:
    case 0xDCu: case 0xDDu: case 0xDEu: case 0xDFu:
    case 0xE4u: case 0xF4u: case 0xEFu:
        ConsumeByte();
        return;

    // 3-byte Map 1 instructions
    case 0x02u: case 0x04u: case 0x09u: case 0x18u:
    case 0x22u: case 0x24u: case 0x28u: case 0x29u:
    case 0x30u: case 0x32u: case 0x34u: case 0x36u:
    case 0x42u: case 0x44u: case 0x48u: case 0x49u:
    case 0x58u: case 0x59u: case 0x68u: case 0x69u:
    case 0x78u: case 0x79u:
    case 0x8Fu: case 0x9Fu: case 0xA0u: case 0xB0u: case 0xA2u: case 0xB2u:
    case 0xAFu: case 0xBFu:
    case 0xC8u: case 0xCAu: case 0xCCu: case 0xCDu:
    case 0xD5u: case 0xD9u: case 0xE9u: case 0xF9u:
    case 0xDBu: case 0xEBu: case 0xFBu:
    case 0xE5u: case 0xF5u:
    case 0xEDu: case 0xEEu: case 0xFDu: case 0xFEu:
        ConsumeWord();
        return;

    case 0x06u: case 0x26u: case 0x46u:
        ConsumeByte();
        return;

    case 0xCEu: {
        const uint8_t b = ConsumeByte();
        if (b == 0xFBu) {
            ConsumeByte();  // S3 extended opcode (CE FB xx)
        } else {
            ConsumeByte();  // MOV sfr, #byte immediate
        }
        return;
    }

    // 4-byte Map 1 instructions
    case 0x19u: case 0x38u: case 0x39u:
    case 0x40u:
    case 0xC9u: case 0xCBu: case 0xCFu:
    case 0xECu: case 0xFCu:
        ConsumeByte();
        ConsumeWord();
        return;

    default:
        return;
    }
}

void Rl78Cpu::ExecuteS3Extended() {
    const uint8_t ext_op = ConsumeByte();
    if (bus_ && bus_->Core() != CoreProfile::S3) {
        invalid_insn_ = true;
        last_invalid_opcode_ = 0x00CEFB00u | ext_op;
        return;
    }

    switch (ext_op) {
    case 0x01u: {  // MULHU: BC:AX = AX * BC (unsigned)
        const uint32_t prod = static_cast<uint32_t>(ReadRegPair(RP_AX)) *
                              static_cast<uint32_t>(ReadRegPair(RP_BC));
        WriteRegPair(RP_AX, static_cast<uint16_t>(prod & 0xFFFFu));
        WriteRegPair(RP_BC, static_cast<uint16_t>((prod >> 16) & 0xFFFFu));
        break;
    }
    case 0x02u: {  // MULH: BC:AX = int16(AX) * int16(BC) (signed)
        const int32_t prod = static_cast<int32_t>(static_cast<int16_t>(ReadRegPair(RP_AX))) *
                             static_cast<int32_t>(static_cast<int16_t>(ReadRegPair(RP_BC)));
        const uint32_t u = static_cast<uint32_t>(prod);
        WriteRegPair(RP_AX, static_cast<uint16_t>(u & 0xFFFFu));
        WriteRegPair(RP_BC, static_cast<uint16_t>((u >> 16) & 0xFFFFu));
        break;
    }
    case 0x03u: {  // DIVHU: AX = AX / DE, DE = AX % DE (on DE==0: DE=old AX, AX=0xFFFF)
        const uint16_t dividend = ReadRegPair(RP_AX);
        const uint16_t divisor = ReadRegPair(RP_DE);
        if (divisor == 0) {
            WriteRegPair(RP_DE, dividend);
            WriteRegPair(RP_AX, 0xFFFFu);
        } else {
            WriteRegPair(RP_AX, static_cast<uint16_t>(dividend / divisor));
            WriteRegPair(RP_DE, static_cast<uint16_t>(dividend % divisor));
        }
        inst_cycles_ += 7u;
        break;
    }
    case 0x0Bu: {  // DIVWU: BC:AX = BC:AX / HL:DE, HL:DE = BC:AX % HL:DE
        const uint32_t dividend = (static_cast<uint32_t>(ReadRegPair(RP_BC)) << 16) |
                                  static_cast<uint32_t>(ReadRegPair(RP_AX));
        const uint32_t divisor = (static_cast<uint32_t>(ReadRegPair(RP_HL)) << 16) |
                                 static_cast<uint32_t>(ReadRegPair(RP_DE));
        if (divisor == 0) {
            WriteRegPair(RP_DE, static_cast<uint16_t>(dividend & 0xFFFFu));
            WriteRegPair(RP_HL, static_cast<uint16_t>((dividend >> 16) & 0xFFFFu));
            WriteRegPair(RP_AX, 0xFFFFu);
            WriteRegPair(RP_BC, 0xFFFFu);
        } else {
            const uint32_t q = dividend / divisor;
            const uint32_t rem = dividend % divisor;
            WriteRegPair(RP_AX, static_cast<uint16_t>(q & 0xFFFFu));
            WriteRegPair(RP_BC, static_cast<uint16_t>((q >> 16) & 0xFFFFu));
            WriteRegPair(RP_DE, static_cast<uint16_t>(rem & 0xFFFFu));
            WriteRegPair(RP_HL, static_cast<uint16_t>((rem >> 16) & 0xFFFFu));
        }
        inst_cycles_ += 15u;
        break;
    }
    case 0x05u: {  // MACHU: MACR += AX * BC (unsigned), CY = overflow, AC = 0
        const uint64_t prod = static_cast<uint64_t>(ReadRegPair(RP_AX)) *
                              static_cast<uint64_t>(ReadRegPair(RP_BC));
        const uint64_t sum = static_cast<uint64_t>(macr_) + prod;
        macr_ = static_cast<uint32_t>(sum & 0xFFFFFFFFu);
        psw_ &= static_cast<uint8_t>(~(PSW_AC | PSW_CY));
        if (sum > 0xFFFFFFFFULL) {
            psw_ |= PSW_CY;
        }
        inst_cycles_ += 2u;
        break;
    }
    case 0x06u: {  // MACH: MACR += int16(AX) * int16(BC) (signed), CY = signed overflow, AC = negative
        const int64_t prod = static_cast<int64_t>(static_cast<int16_t>(ReadRegPair(RP_AX))) *
                             static_cast<int64_t>(static_cast<int16_t>(ReadRegPair(RP_BC)));
        const int64_t sum = static_cast<int64_t>(static_cast<int32_t>(macr_)) + prod;
        macr_ = static_cast<uint32_t>(static_cast<int32_t>(sum));
        psw_ &= static_cast<uint8_t>(~(PSW_AC | PSW_CY));
        if (sum > 0x7FFFFFFFLL || sum < -0x80000000LL) {
            psw_ |= PSW_CY;
        }
        if ((macr_ & 0x80000000u) != 0) {
            psw_ |= PSW_AC;
        }
        inst_cycles_ += 2u;
        break;
    }
    default:
        invalid_insn_ = true;
        last_invalid_opcode_ = 0x00CEFB00u | ext_op;
        break;
    }
}

void Rl78Cpu::ExecuteMap4_31(uint8_t code) {
    const uint8_t lo = code & 0x0Fu;
    const uint8_t hi = (code >> 4) & 0x0Fu;

    if (lo <= 5u) {
        // btclr / bt / bf across saddr.bit, A.bit, sfr.bit, [HL].bit
        const uint8_t bit = hi & 7u;
        const uint8_t bit_mask = static_cast<uint8_t>(1u << bit);
        const bool is_btclr = (lo <= 1u);
        const bool branch_on_true = (lo <= 3u);

        uint8_t val = 0;
        bool target_is_a = false;
        uint32_t target_addr = 0;

        switch (code & 0x81u) {
        case 0x00u:
            target_addr = ConsumeSaddr();
            val = BusRead8(target_addr);
            break;
        case 0x01u:
            target_is_a = true;
            val = ReadReg(REG_A);
            break;
        case 0x80u:
            target_addr = ConsumeSfr();
            val = BusRead8(target_addr);
            break;
        case 0x81u:
            target_addr = ResolveIndirect(RP_HL);
            val = BusRead8(target_addr);
            break;
        }

        const uint32_t branch_target = ConsumeRel8();
        const bool bit_set = (val & bit_mask) != 0;
        const bool cond = branch_on_true ? bit_set : !bit_set;
        if (cond) {
            if (is_btclr) {
                const uint8_t cleared = static_cast<uint8_t>(val & ~bit_mask);
                if (target_is_a) {
                    WriteReg(REG_A, cleared);
                } else {
                    BusWrite8(target_addr, cleared);
                }
            }
            pc_ = branch_target;
            inst_cycles_ += 2u;
        }
        return;
    }

    if (lo >= 7u && lo <= 0xBu && hi >= 1u && hi <= 7u) {
        const uint8_t cnt = hi;
        if (lo <= 9u) {  // SHL C / B / A, cnt
            const uint8_t r = (lo == 7u) ? REG_C : (lo == 8u) ? REG_B : REG_A;
            uint8_t v = ReadReg(r);
            bool cy = GetCY();
            for (uint8_t i = 0; i < cnt; ++i) {
                cy = (v & 0x80u) != 0;
                v = static_cast<uint8_t>(v << 1);
            }
            WriteReg(r, v);
            SetCY(cy);
        } else if (lo == 0xAu) {  // SHR A, cnt
            uint8_t v = ReadReg(REG_A);
            bool cy = GetCY();
            for (uint8_t i = 0; i < cnt; ++i) {
                cy = (v & 0x01u) != 0;
                v = static_cast<uint8_t>(v >> 1);
            }
            WriteReg(REG_A, v);
            SetCY(cy);
        } else {  // SAR A, cnt
            int8_t v = static_cast<int8_t>(ReadReg(REG_A));
            bool cy = GetCY();
            for (uint8_t i = 0; i < cnt; ++i) {
                cy = (v & 1) != 0;
                v = static_cast<int8_t>(v >> 1);
            }
            WriteReg(REG_A, static_cast<uint8_t>(v));
            SetCY(cy);
        }
        return;
    }

    if (lo >= 0xCu && hi >= 1u) {
        const uint8_t cnt = hi;
        if (lo <= 0xDu) {  // SHLW BC / AX, cnt
            const uint8_t rp = (lo == 0xCu) ? RP_BC : RP_AX;
            uint16_t v = ReadRegPair(rp);
            bool cy = GetCY();
            for (uint8_t i = 0; i < cnt; ++i) {
                cy = (v & 0x8000u) != 0;
                v = static_cast<uint16_t>(v << 1);
            }
            WriteRegPair(rp, v);
            SetCY(cy);
        } else if (lo == 0xEu) {  // SHRW AX, cnt
            uint16_t v = ReadRegPair(RP_AX);
            bool cy = GetCY();
            for (uint8_t i = 0; i < cnt; ++i) {
                cy = (v & 0x0001u) != 0;
                v = static_cast<uint16_t>(v >> 1);
            }
            WriteRegPair(RP_AX, v);
            SetCY(cy);
        } else {  // SARW AX, cnt
            int16_t v = static_cast<int16_t>(ReadRegPair(RP_AX));
            bool cy = GetCY();
            for (uint8_t i = 0; i < cnt; ++i) {
                cy = (v & 1) != 0;
                v = static_cast<int16_t>(v >> 1);
            }
            WriteRegPair(RP_AX, static_cast<uint16_t>(v));
            SetCY(cy);
        }
        inst_cycles_ += 1u;
        return;
    }

    invalid_insn_ = true;
    last_invalid_opcode_ = 0x3100u | code;
}

void Rl78Cpu::ExecuteMap2_61(uint8_t code) {
    const uint8_t lo = code & 0x0Fu;
    const uint8_t hi = (code >> 4) & 0x0Fu;

    auto exec_alu8_op = [this](uint8_t op_idx, uint8_t lhs, uint8_t rhs, bool *write_back) -> uint8_t {
        *write_back = true;
        switch (op_idx) {
        case 0: return OpAdd8(lhs, rhs, false);
        case 1: return OpAdd8(lhs, rhs, true);
        case 2: return OpSub8(lhs, rhs, false, true);
        case 3: return OpSub8(lhs, rhs, true, true);
        case 4: *write_back = false; return OpSub8(lhs, rhs, false, false);
        case 5: return OpAnd8(lhs, rhs);
        case 6: return OpOr8(lhs, rhs);
        case 7: return OpXor8(lhs, rhs);
        default: return lhs;
        }
    };

    // ALU/XCH r, A (hi <= 7, lo <= 7) and ALU/XCH A, r ((hi <= 7 && lo == 8) || (hi <= 8 && lo >= 0xA))
    if (hi <= 7u && lo <= 7u) {
        const uint8_t r = lo;
        bool wb = true;
        const uint8_t res = exec_alu8_op(hi, ReadReg(r), ReadReg(REG_A), &wb);
        if (wb) {
            WriteReg(r, res);
        }
        return;
    }
    if ((hi <= 7u && lo == 8u) || (hi <= 8u && lo >= 0xAu)) {
        const uint8_t r = lo & 7u;
        const uint8_t a = ReadReg(REG_A);
        const uint8_t b = ReadReg(r);
        if (hi == 8u) {  // XCH A, r
            WriteReg(REG_A, b);
            WriteReg(r, a);
        } else {
            bool wb = true;
            const uint8_t res = exec_alu8_op(hi, a, b, &wb);
            if (wb) {
                WriteReg(REG_A, res);
            }
        }
        return;
    }

    // CALLT [addr5]
    if (hi >= 8u && lo >= 4u && lo <= 7u) {
        const uint32_t tbl_addr = 0x00080u |
                                  (static_cast<uint32_t>(lo & 3u) << 4) |
                                  (static_cast<uint32_t>(hi & 7u) << 1);
        const uint16_t target = MakeWord(bus_->ReadCpu(tbl_addr), bus_->ReadCpu(tbl_addr + 1u));
        PushCallFrame(pc_);
        pc_ = target;
        inst_cycles_ += 4u;
        return;
    }

    // ALU A, [HL+B] / A, [HL+C]
    if (lo == 0u && hi >= 8u) {
        const uint8_t op_idx = hi & 7u;
        const uint8_t rhs = BusRead8(ResolveBasedHlReg(REG_B));
        bool wb = true;
        const uint8_t res = exec_alu8_op(op_idx, ReadReg(REG_A), rhs, &wb);
        if (wb) {
            WriteReg(REG_A, res);
        }
        return;
    }
    if (lo == 2u && hi >= 8u) {
        const uint8_t op_idx = hi & 7u;
        const uint8_t rhs = BusRead8(ResolveBasedHlReg(REG_C));
        bool wb = true;
        const uint8_t res = exec_alu8_op(op_idx, ReadReg(REG_A), rhs, &wb);
        if (wb) {
            WriteReg(REG_A, res);
        }
        return;
    }

    switch (code) {
    case 0x09u: {  // ADDW AX, [HL+byte]
        const uint32_t ea = ResolveBasedHlImm(ConsumeByte());
        const uint16_t rhs = BusRead16(ea);
        WriteRegPair(RP_AX, OpAdd16(ReadRegPair(RP_AX), rhs));
        break;
    }
    case 0x29u: {  // SUBW AX, [HL+byte]
        const uint32_t ea = ResolveBasedHlImm(ConsumeByte());
        const uint16_t rhs = BusRead16(ea);
        WriteRegPair(RP_AX, OpSub16(ReadRegPair(RP_AX), rhs, true));
        break;
    }
    case 0x49u: {  // CMPW AX, [HL+byte]
        const uint32_t ea = ResolveBasedHlImm(ConsumeByte());
        const uint16_t rhs = BusRead16(ea);
        (void)OpSub16(ReadRegPair(RP_AX), rhs, false);
        break;
    }
    case 0x59u: {  // INC [HL+byte]
        const uint32_t ea = ResolveBasedHlImm(ConsumeByte());
        BusWrite8(ea, OpInc8(BusRead8(ea)));
        break;
    }
    case 0x69u: {  // DEC [HL+byte]
        const uint32_t ea = ResolveBasedHlImm(ConsumeByte());
        BusWrite8(ea, OpDec8(BusRead8(ea)));
        break;
    }
    case 0x79u: {  // INCW [HL+byte]
        const uint32_t ea = ResolveBasedHlImm(ConsumeByte());
        BusWrite16(ea, static_cast<uint16_t>(BusRead16(ea) + 1u));
        break;
    }
    case 0x89u: {  // DECW [HL+byte]
        const uint32_t ea = ResolveBasedHlImm(ConsumeByte());
        BusWrite16(ea, static_cast<uint16_t>(BusRead16(ea) - 1u));
        break;
    }

    case 0xC3u: {  // BH $addr20 (!CY && !Z)
        const uint32_t tgt = ConsumeRel8();
        if ((psw_ & (PSW_CY | PSW_Z)) == 0) {
            pc_ = tgt;
            inst_cycles_ += 2u;
        }
        break;
    }
    case 0xD3u: {  // BNH $addr20 (CY || Z)
        const uint32_t tgt = ConsumeRel8();
        if ((psw_ & (PSW_CY | PSW_Z)) != 0) {
            pc_ = tgt;
            inst_cycles_ += 2u;
        }
        break;
    }
    case 0xE3u: PerformSkipIfTrue((psw_ & (PSW_CY | PSW_Z)) == 0); break;  // SKH
    case 0xF3u: PerformSkipIfTrue((psw_ & (PSW_CY | PSW_Z)) != 0); break;  // SKNH
    case 0xC8u: PerformSkipIfTrue((psw_ & PSW_CY) != 0); break;            // SKC
    case 0xD8u: PerformSkipIfTrue((psw_ & PSW_CY) == 0); break;            // SKNC
    case 0xE8u: PerformSkipIfTrue((psw_ & PSW_Z) != 0); break;             // SKZ
    case 0xF8u: PerformSkipIfTrue((psw_ & PSW_Z) == 0); break;             // SKNZ

    case 0xA8u: {  // XCH A, saddr
        const uint32_t ea = ConsumeSaddr();
        const uint8_t a = ReadReg(REG_A);
        WriteReg(REG_A, BusRead8(ea));
        BusWrite8(ea, a);
        break;
    }
    case 0xB8u: {  // MOV ES, saddr
        const uint32_t ea = ConsumeSaddr();
        SetES(BusRead8(ea));
        break;
    }
    case 0xA9u: {  // XCH A, [HL+C]
        const uint32_t ea = ResolveBasedHlReg(REG_C);
        const uint8_t a = ReadReg(REG_A);
        WriteReg(REG_A, BusRead8(ea));
        BusWrite8(ea, a);
        break;
    }
    case 0xB9u: {  // XCH A, [HL+B]
        const uint32_t ea = ResolveBasedHlReg(REG_B);
        const uint8_t a = ReadReg(REG_A);
        WriteReg(REG_A, BusRead8(ea));
        BusWrite8(ea, a);
        break;
    }
    case 0xAAu: {  // XCH A, !addr16
        const uint32_t ea = ConsumeDataAddr16();
        const uint8_t a = ReadReg(REG_A);
        WriteReg(REG_A, BusRead8(ea));
        BusWrite8(ea, a);
        break;
    }
    case 0xABu: {  // XCH A, sfr
        const uint32_t ea = ConsumeSfr();
        const uint8_t a = ReadReg(REG_A);
        WriteReg(REG_A, BusRead8(ea));
        BusWrite8(ea, a);
        break;
    }
    case 0xACu: {  // XCH A, [HL]
        const uint32_t ea = ResolveIndirect(RP_HL);
        const uint8_t a = ReadReg(REG_A);
        WriteReg(REG_A, BusRead8(ea));
        BusWrite8(ea, a);
        break;
    }
    case 0xADu: {  // XCH A, [HL+byte]
        const uint32_t ea = ResolveBasedHlImm(ConsumeByte());
        const uint8_t a = ReadReg(REG_A);
        WriteReg(REG_A, BusRead8(ea));
        BusWrite8(ea, a);
        break;
    }
    case 0xAEu: {  // XCH A, [DE]
        const uint32_t ea = ResolveIndirect(RP_DE);
        const uint8_t a = ReadReg(REG_A);
        WriteReg(REG_A, BusRead8(ea));
        BusWrite8(ea, a);
        break;
    }
    case 0xAFu: {  // XCH A, [DE+byte]
        const uint32_t ea = ResolveBasedDeImm(ConsumeByte());
        const uint8_t a = ReadReg(REG_A);
        WriteReg(REG_A, BusRead8(ea));
        BusWrite8(ea, a);
        break;
    }

    case 0xC9u: WriteReg(REG_A, BusRead8(ResolveBasedHlReg(REG_B))); break;  // MOV A, [HL+B]
    case 0xD9u: BusWrite8(ResolveBasedHlReg(REG_B), ReadReg(REG_A)); break;  // MOV [HL+B], A
    case 0xE9u: WriteReg(REG_A, BusRead8(ResolveBasedHlReg(REG_C))); break;  // MOV A, [HL+C]
    case 0xF9u: BusWrite8(ResolveBasedHlReg(REG_C), ReadReg(REG_A)); break;  // MOV [HL+C], A

    case 0xCAu: case 0xDAu: case 0xEAu: case 0xFAu: {  // CALL rp
        const uint32_t tgt = (static_cast<uint32_t>(GetCS()) << 16) | ReadRegPair(hi & 3u);
        PushCallFrame(pc_);
        pc_ = tgt;
        inst_cycles_ += 2u;
        break;
    }
    case 0xCBu:  // BR AX
        pc_ = (static_cast<uint32_t>(GetCS()) << 16) | ReadRegPair(RP_AX);
        inst_cycles_ += 2u;
        break;

    case 0xDBu: {  // ROR A, 1
        const uint8_t a = ReadReg(REG_A);
        const bool cy = (a & 0x01u) != 0;
        WriteReg(REG_A, static_cast<uint8_t>((a >> 1) | (cy ? 0x80u : 0x00u)));
        SetCY(cy);
        break;
    }
    case 0xEBu: {  // ROL A, 1
        const uint8_t a = ReadReg(REG_A);
        const bool cy = (a & 0x80u) != 0;
        WriteReg(REG_A, static_cast<uint8_t>((a << 1) | (cy ? 0x01u : 0x00u)));
        SetCY(cy);
        break;
    }
    case 0xFBu: {  // RORC A, 1
        const uint8_t a = ReadReg(REG_A);
        const bool old_cy = GetCY();
        SetCY((a & 0x01u) != 0);
        WriteReg(REG_A, static_cast<uint8_t>((a >> 1) | (old_cy ? 0x80u : 0x00u)));
        break;
    }
    case 0xDCu: {  // ROLC A, 1
        const uint8_t a = ReadReg(REG_A);
        const bool old_cy = GetCY();
        SetCY((a & 0x80u) != 0);
        WriteReg(REG_A, static_cast<uint8_t>((a << 1) | (old_cy ? 0x01u : 0x00u)));
        break;
    }
    case 0xEEu: {  // ROLWC AX, 1
        const uint16_t ax = ReadRegPair(RP_AX);
        const bool old_cy = GetCY();
        SetCY((ax & 0x8000u) != 0);
        WriteRegPair(RP_AX, static_cast<uint16_t>((ax << 1) | (old_cy ? 0x0001u : 0x0000u)));
        break;
    }
    case 0xFEu: {  // ROLWC BC, 1
        const uint16_t bc = ReadRegPair(RP_BC);
        const bool old_cy = GetCY();
        SetCY((bc & 0x8000u) != 0);
        WriteRegPair(RP_BC, static_cast<uint16_t>((bc << 1) | (old_cy ? 0x0001u : 0x0000u)));
        break;
    }

    case 0xCCu: {  // BRK
        const uint16_t vec = MakeWord(bus_->PeekByte(kBrkVectorAddress),
                                      bus_->PeekByte(kBrkVectorAddress + 1u));
        if (stop_on_brk || vec == 0x0000u || vec == 0xFFFFu) {
            brk_stopped_ = true;
            break;
        }
        const uint8_t saved_psw = GetPSW();
        SetPSW(static_cast<uint8_t>(saved_psw & ~PSW_IE));
        PushInterruptFrame(pc_, saved_psw);
        pc_ = vec;
        inst_cycles_ += 5u;
        break;
    }
    case 0xECu:  // RETB
    case 0xFCu:  // RETI
        PopInterruptFrame();
        inst_cycles_ += 5u;
        break;

    case 0xCDu: {  // POP PSW: reads [SP+1] (sp += 2)
        const uint16_t cur_sp = GetSP();
        const uint32_t base = Rl78Bus::ResolveNear(cur_sp);
        (void)BusRead8(base + 0u);
        const uint8_t restored = BusRead8(base + 1u);
        SetSP(static_cast<uint16_t>((cur_sp + 2u) & 0xFFFEu));
        SetPSW(restored);
        interrupt_delayed_ = true;
        break;
    }
    case 0xDDu: {  // PUSH PSW: writes [SP-2]=0x00, [SP-1]=PSW
        const uint16_t new_sp = static_cast<uint16_t>((sp_ - 2u) & 0xFFFEu);
        SetSP(new_sp);
        const uint32_t base = Rl78Bus::ResolveNear(new_sp);
        BusWrite8(base + 0u, 0x00u);
        BusWrite8(base + 1u, GetPSW());
        break;
    }

    case 0xEDu:  // HALT
        halt_entered_ = true;
        break;
    case 0xFDu:  // STOP
        if (clock_) {
            clock_->OnEnterStop();
        }
        stop_entered_ = true;
        break;

    case 0xCEu: {  // MOVS [HL+byte], X
        const uint32_t ea = ResolveBasedHlImm(ConsumeByte());
        const uint8_t x = ReadReg(REG_X);
        BusWrite8(ea, x);
        if (x == 0) psw_ |= PSW_Z;
        else psw_ &= static_cast<uint8_t>(~PSW_Z);
        SetCY(x == 0 || ReadReg(REG_A) == 0);
        break;
    }
    case 0xDEu: {  // CMPS X, [HL+byte]
        const uint32_t ea = ResolveBasedHlImm(ConsumeByte());
        const uint8_t x = ReadReg(REG_X);
        const uint8_t rhs = BusRead8(ea);
        const uint8_t diff = static_cast<uint8_t>(x - rhs);
        const bool ac = (x & 0x0Fu) < (rhs & 0x0Fu);
        const bool cy = (diff != 0) || (x == 0) || (ReadReg(REG_A) == 0);
        SetFlagsZAcCy(diff == 0, ac, cy);
        break;
    }

    case 0xCFu: case 0xDFu: case 0xEFu: case 0xFFu:  // SEL RBn
        if (bus_ && bus_->Core() == CoreProfile::S1) {
            invalid_insn_ = true;
            last_invalid_opcode_ = 0x6100u | code;
            break;
        }
        SetRB(hi & 3u);
        break;

    default:
        invalid_insn_ = true;
        last_invalid_opcode_ = 0x6100u | code;
        break;
    }
}

void Rl78Cpu::ExecuteMap3_71(uint8_t code) {
    const uint8_t lo = code & 0x0Fu;
    const uint8_t hi = (code >> 4) & 0x0Fu;

    if (hi >= 8u && lo == 0u) {
        if (hi == 8u) {
            SetCY(true);   // SET1 CY
            return;
        }
        if (hi == 0xCu) {
            SetCY(!GetCY());  // NOT1 CY
            return;
        }
        invalid_insn_ = true;
        last_invalid_opcode_ = 0x7100u | code;
        return;
    }
    if (hi >= 8u && lo == 8u) {
        if (hi == 8u) {
            SetCY(false);  // CLR1 CY
            return;
        }
        invalid_insn_ = true;
        last_invalid_opcode_ = 0x7100u | code;
        return;
    }

    const uint8_t bit = hi & 7u;
    const uint8_t bit_mask = static_cast<uint8_t>(1u << bit);

    uint32_t mem_addr = 0;
    bool use_reg_a = false;
    bool read_only = false;

    const uint8_t sel = code & 0x8Fu;
    switch (sel) {
    case 0x00u: case 0x08u:  // SET1 / CLR1 !addr16.bit
        mem_addr = ConsumeDataAddr16();
        break;
    case 0x01u: case 0x02u: case 0x03u:
        mem_addr = ConsumeSaddr();
        break;
    case 0x04u: case 0x05u: case 0x06u: case 0x07u:
        mem_addr = ConsumeSaddr();
        read_only = true;
        break;
    case 0x81u: case 0x82u: case 0x83u:
        mem_addr = ResolveIndirect(RP_HL);
        break;
    case 0x84u: case 0x85u: case 0x86u: case 0x87u:
        mem_addr = ResolveIndirect(RP_HL);
        read_only = true;
        break;
    case 0x09u: case 0x0Au: case 0x0Bu:
        mem_addr = ConsumeSfr();
        break;
    case 0x0Cu: case 0x0Du: case 0x0Eu: case 0x0Fu:
        mem_addr = ConsumeSfr();
        read_only = true;
        break;
    case 0x89u: case 0x8Au: case 0x8Bu:
        use_reg_a = true;
        break;
    case 0x8Cu: case 0x8Du: case 0x8Eu: case 0x8Fu:
        use_reg_a = true;
        read_only = true;
        break;
    default:
        invalid_insn_ = true;
        last_invalid_opcode_ = 0x7100u | code;
        return;
    }

    uint8_t val = use_reg_a ? ReadReg(REG_A) : BusRead8(mem_addr);
    const bool src_bit = (val & bit_mask) != 0;

    if (read_only) {
        switch (lo & 3u) {
        case 0u: SetCY(src_bit); break;              // MOV1 CY, src.bit
        case 1u: SetCY(GetCY() && src_bit); break;   // AND1 CY, src.bit
        case 2u: SetCY(GetCY() || src_bit); break;   // OR1  CY, src.bit
        case 3u: SetCY(GetCY() != src_bit); break;   // XOR1 CY, src.bit
        }
        return;
    }

    uint8_t new_val = val;
    if (sel == 0x00u) {
        new_val = static_cast<uint8_t>(val | bit_mask);
    } else if (sel == 0x08u) {
        new_val = static_cast<uint8_t>(val & ~bit_mask);
    } else {
        switch (lo) {
        case 0x1u: case 0x9u:  // MOV1 dst.bit, CY
            new_val = GetCY() ? static_cast<uint8_t>(val | bit_mask)
                              : static_cast<uint8_t>(val & ~bit_mask);
            break;
        case 0x2u: case 0xAu:  // SET1 dst.bit
            new_val = static_cast<uint8_t>(val | bit_mask);
            break;
        case 0x3u: case 0xBu:  // CLR1 dst.bit
            new_val = static_cast<uint8_t>(val & ~bit_mask);
            break;
        default:
            break;
        }
    }

    if (use_reg_a) {
        WriteReg(REG_A, new_val);
    } else {
        BusWrite8(mem_addr, new_val);
    }
}

void Rl78Cpu::ExecuteMap1(uint8_t code) {
    const uint8_t lo = code & 0x0Fu;
    const uint8_t hi = (code >> 4) & 0x0Fu;

    // 8-bit ALU matrix: hi=0..7 (ADD, ADDC, SUB, SUBC, CMP, AND, OR, XOR), lo=A..F
    if (lo >= 0xAu && hi <= 0x7u) {
        uint8_t lhs = 0;
        uint8_t rhs = 0;
        bool dst_is_saddr = false;
        uint32_t saddr_ea = 0;

        if (lo == 0xAu) {
            dst_is_saddr = true;
            saddr_ea = ConsumeSaddr();
            lhs = BusRead8(saddr_ea);
            rhs = ConsumeByte();
        } else {
            lhs = ReadReg(REG_A);
            switch (lo) {
            case 0xBu: rhs = BusRead8(ConsumeSaddr()); break;
            case 0xCu: rhs = ConsumeByte(); break;
            case 0xDu: rhs = BusRead8(ResolveIndirect(RP_HL)); break;
            case 0xEu: rhs = BusRead8(ResolveBasedHlImm(ConsumeByte())); break;
            case 0xFu: rhs = BusRead8(ConsumeDataAddr16()); break;
            }
        }

        bool write_back = true;
        uint8_t res = 0;
        switch (hi) {
        case 0u: res = OpAdd8(lhs, rhs, false); break;
        case 1u: res = OpAdd8(lhs, rhs, true); break;
        case 2u: res = OpSub8(lhs, rhs, false, true); break;
        case 3u: res = OpSub8(lhs, rhs, true, true); break;
        case 4u: res = OpSub8(lhs, rhs, false, false); write_back = false; break;
        case 5u: res = OpAnd8(lhs, rhs); break;
        case 6u: res = OpOr8(lhs, rhs); break;
        case 7u: res = OpXor8(lhs, rhs); break;
        }
        if (write_back) {
            if (dst_is_saddr) {
                BusWrite8(saddr_ea, res);
            } else {
                WriteReg(REG_A, res);
            }
        }
        return;
    }

    switch (code) {
    case 0x00u: break;  // NOP

    case 0x31u: ExecuteMap4_31(ConsumeByte()); break;
    case 0x61u: ExecuteMap2_61(ConsumeByte()); break;
    case 0x71u: ExecuteMap3_71(ConsumeByte()); break;

    // 16-bit ADDW AX, ...
    case 0x01u: WriteRegPair(RP_AX, OpAdd16(ReadRegPair(RP_AX), ReadRegPair(RP_AX))); break;
    case 0x02u: WriteRegPair(RP_AX, OpAdd16(ReadRegPair(RP_AX), BusRead16(ConsumeDataAddr16()))); break;
    case 0x03u: WriteRegPair(RP_AX, OpAdd16(ReadRegPair(RP_AX), ReadRegPair(RP_BC))); break;
    case 0x04u: WriteRegPair(RP_AX, OpAdd16(ReadRegPair(RP_AX), ConsumeWord())); break;
    case 0x05u: WriteRegPair(RP_AX, OpAdd16(ReadRegPair(RP_AX), ReadRegPair(RP_DE))); break;
    case 0x06u: WriteRegPair(RP_AX, OpAdd16(ReadRegPair(RP_AX), BusRead16(ConsumeSaddrP()))); break;
    case 0x07u: WriteRegPair(RP_AX, OpAdd16(ReadRegPair(RP_AX), ReadRegPair(RP_HL))); break;

    case 0x08u: {  // XCH A, X
        const uint8_t a = ReadReg(REG_A);
        WriteReg(REG_A, ReadReg(REG_X));
        WriteReg(REG_X, a);
        break;
    }
    case 0x09u: {  // MOV A, word[B]
        const uint16_t w = ConsumeWord();
        WriteReg(REG_A, BusRead8(ResolveWordIndexed(w, ReadReg(REG_B))));
        break;
    }

    case 0x10u: {  // ADDW SP, #byte
        const uint8_t imm = ConsumeByte();
        SetSP(static_cast<uint16_t>(GetSP() + imm));
        break;
    }
    case 0x12u: WriteRegPair(RP_BC, ReadRegPair(RP_AX)); break;
    case 0x13u: WriteRegPair(RP_AX, ReadRegPair(RP_BC)); break;
    case 0x14u: WriteRegPair(RP_DE, ReadRegPair(RP_AX)); break;
    case 0x15u: WriteRegPair(RP_AX, ReadRegPair(RP_DE)); break;
    case 0x16u: WriteRegPair(RP_HL, ReadRegPair(RP_AX)); break;
    case 0x17u: WriteRegPair(RP_AX, ReadRegPair(RP_HL)); break;
    case 0x18u: {  // MOV word[B], A
        const uint16_t w = ConsumeWord();
        BusWrite8(ResolveWordIndexed(w, ReadReg(REG_B)), ReadReg(REG_A));
        break;
    }
    case 0x19u: {  // MOV word[B], #byte
        const uint16_t w = ConsumeWord();
        const uint8_t imm = ConsumeByte();
        BusWrite8(ResolveWordIndexed(w, ReadReg(REG_B)), imm);
        break;
    }

    case 0x20u: {  // SUBW SP, #byte
        const uint8_t imm = ConsumeByte();
        SetSP(static_cast<uint16_t>(GetSP() - imm));
        break;
    }
    case 0x22u: WriteRegPair(RP_AX, OpSub16(ReadRegPair(RP_AX), BusRead16(ConsumeDataAddr16()), true)); break;
    case 0x23u: WriteRegPair(RP_AX, OpSub16(ReadRegPair(RP_AX), ReadRegPair(RP_BC), true)); break;
    case 0x24u: WriteRegPair(RP_AX, OpSub16(ReadRegPair(RP_AX), ConsumeWord(), true)); break;
    case 0x25u: WriteRegPair(RP_AX, OpSub16(ReadRegPair(RP_AX), ReadRegPair(RP_DE), true)); break;
    case 0x26u: WriteRegPair(RP_AX, OpSub16(ReadRegPair(RP_AX), BusRead16(ConsumeSaddrP()), true)); break;
    case 0x27u: WriteRegPair(RP_AX, OpSub16(ReadRegPair(RP_AX), ReadRegPair(RP_HL), true)); break;
    case 0x28u: {  // MOV word[C], A
        const uint16_t w = ConsumeWord();
        BusWrite8(ResolveWordIndexed(w, ReadReg(REG_C)), ReadReg(REG_A));
        break;
    }
    case 0x29u: {  // MOV A, word[C]
        const uint16_t w = ConsumeWord();
        WriteReg(REG_A, BusRead8(ResolveWordIndexed(w, ReadReg(REG_C))));
        break;
    }

    case 0x30u: WriteRegPair(RP_AX, ConsumeWord()); break;
    case 0x32u: WriteRegPair(RP_BC, ConsumeWord()); break;
    case 0x34u: WriteRegPair(RP_DE, ConsumeWord()); break;
    case 0x36u: WriteRegPair(RP_HL, ConsumeWord()); break;
    case 0x33u: {  // XCHW AX, BC
        const uint16_t ax = ReadRegPair(RP_AX);
        WriteRegPair(RP_AX, ReadRegPair(RP_BC));
        WriteRegPair(RP_BC, ax);
        break;
    }
    case 0x35u: {  // XCHW AX, DE
        const uint16_t ax = ReadRegPair(RP_AX);
        WriteRegPair(RP_AX, ReadRegPair(RP_DE));
        WriteRegPair(RP_DE, ax);
        break;
    }
    case 0x37u: {  // XCHW AX, HL
        const uint16_t ax = ReadRegPair(RP_AX);
        WriteRegPair(RP_AX, ReadRegPair(RP_HL));
        WriteRegPair(RP_HL, ax);
        break;
    }
    case 0x38u: {  // MOV word[C], #byte
        const uint16_t w = ConsumeWord();
        const uint8_t imm = ConsumeByte();
        BusWrite8(ResolveWordIndexed(w, ReadReg(REG_C)), imm);
        break;
    }
    case 0x39u: {  // MOV word[BC], #byte
        const uint16_t w = ConsumeWord();
        const uint8_t imm = ConsumeByte();
        BusWrite8(ResolveWordIndexed(w, ReadRegPair(RP_BC)), imm);
        break;
    }

    case 0x40u: {  // CMP !addr16, #byte
        const uint32_t ea = ConsumeDataAddr16();
        const uint8_t imm = ConsumeByte();
        (void)OpSub8(BusRead8(ea), imm, false, false);
        break;
    }
    case 0x41u: SetES(ConsumeByte()); break;  // MOV ES, #byte
    case 0x42u: (void)OpSub16(ReadRegPair(RP_AX), BusRead16(ConsumeDataAddr16()), false); break;
    case 0x43u: (void)OpSub16(ReadRegPair(RP_AX), ReadRegPair(RP_BC), false); break;
    case 0x44u: (void)OpSub16(ReadRegPair(RP_AX), ConsumeWord(), false); break;
    case 0x45u: (void)OpSub16(ReadRegPair(RP_AX), ReadRegPair(RP_DE), false); break;
    case 0x46u: (void)OpSub16(ReadRegPair(RP_AX), BusRead16(ConsumeSaddrP()), false); break;
    case 0x47u: (void)OpSub16(ReadRegPair(RP_AX), ReadRegPair(RP_HL), false); break;
    case 0x48u: {  // MOV word[BC], A
        const uint16_t w = ConsumeWord();
        BusWrite8(ResolveWordIndexed(w, ReadRegPair(RP_BC)), ReadReg(REG_A));
        break;
    }
    case 0x49u: {  // MOV A, word[BC]
        const uint16_t w = ConsumeWord();
        WriteReg(REG_A, BusRead8(ResolveWordIndexed(w, ReadRegPair(RP_BC))));
        break;
    }

    case 0x50u: case 0x51u: case 0x52u: case 0x53u:
    case 0x54u: case 0x55u: case 0x56u: case 0x57u:
        WriteReg(lo, ConsumeByte());
        break;
    case 0x58u: {  // MOVW word[B], AX
        const uint16_t w = ConsumeWord();
        BusWrite16(ResolveWordIndexed(w, ReadReg(REG_B)), ReadRegPair(RP_AX));
        break;
    }
    case 0x59u: {  // MOVW AX, word[B]
        const uint16_t w = ConsumeWord();
        WriteRegPair(RP_AX, BusRead16(ResolveWordIndexed(w, ReadReg(REG_B))));
        break;
    }

    case 0x60u: case 0x62u: case 0x63u:
    case 0x64u: case 0x65u: case 0x66u: case 0x67u:
        WriteReg(REG_A, ReadReg(lo));
        break;
    case 0x68u: {  // MOVW word[C], AX
        const uint16_t w = ConsumeWord();
        BusWrite16(ResolveWordIndexed(w, ReadReg(REG_C)), ReadRegPair(RP_AX));
        break;
    }
    case 0x69u: {  // MOVW AX, word[C]
        const uint16_t w = ConsumeWord();
        WriteRegPair(RP_AX, BusRead16(ResolveWordIndexed(w, ReadReg(REG_C))));
        break;
    }

    case 0x70u: case 0x72u: case 0x73u:
    case 0x74u: case 0x75u: case 0x76u: case 0x77u:
        WriteReg(lo, ReadReg(REG_A));
        break;
    case 0x78u: {  // MOVW word[BC], AX
        const uint16_t w = ConsumeWord();
        BusWrite16(ResolveWordIndexed(w, ReadRegPair(RP_BC)), ReadRegPair(RP_AX));
        break;
    }
    case 0x79u: {  // MOVW AX, word[BC]
        const uint16_t w = ConsumeWord();
        WriteRegPair(RP_AX, BusRead16(ResolveWordIndexed(w, ReadRegPair(RP_BC))));
        break;
    }

    case 0x80u: case 0x81u: case 0x82u: case 0x83u:
    case 0x84u: case 0x85u: case 0x86u: case 0x87u:
        WriteReg(lo, OpInc8(ReadReg(lo)));
        break;
    case 0x88u: WriteReg(REG_A, BusRead8(ResolveBasedSpImm(ConsumeByte()))); break;
    case 0x89u: WriteReg(REG_A, BusRead8(ResolveIndirect(RP_DE))); break;
    case 0x8Au: WriteReg(REG_A, BusRead8(ResolveBasedDeImm(ConsumeByte()))); break;
    case 0x8Bu: WriteReg(REG_A, BusRead8(ResolveIndirect(RP_HL))); break;
    case 0x8Cu: WriteReg(REG_A, BusRead8(ResolveBasedHlImm(ConsumeByte()))); break;
    case 0x8Du: WriteReg(REG_A, BusRead8(ConsumeSaddr())); break;
    case 0x8Eu: WriteReg(REG_A, BusRead8(ConsumeSfr())); break;
    case 0x8Fu: WriteReg(REG_A, BusRead8(ConsumeDataAddr16())); break;

    case 0x90u: case 0x91u: case 0x92u: case 0x93u:
    case 0x94u: case 0x95u: case 0x96u: case 0x97u:
        WriteReg(lo, OpDec8(ReadReg(lo)));
        break;
    case 0x98u: BusWrite8(ResolveBasedSpImm(ConsumeByte()), ReadReg(REG_A)); break;
    case 0x99u: BusWrite8(ResolveIndirect(RP_DE), ReadReg(REG_A)); break;
    case 0x9Au: BusWrite8(ResolveBasedDeImm(ConsumeByte()), ReadReg(REG_A)); break;
    case 0x9Bu: BusWrite8(ResolveIndirect(RP_HL), ReadReg(REG_A)); break;
    case 0x9Cu: BusWrite8(ResolveBasedHlImm(ConsumeByte()), ReadReg(REG_A)); break;
    case 0x9Du: BusWrite8(ConsumeSaddr(), ReadReg(REG_A)); break;
    case 0x9Eu: BusWrite8(ConsumeSfr(), ReadReg(REG_A)); break;
    case 0x9Fu: BusWrite8(ConsumeDataAddr16(), ReadReg(REG_A)); break;

    case 0xA0u: { const uint32_t ea = ConsumeDataAddr16(); BusWrite8(ea, OpInc8(BusRead8(ea))); break; }
    case 0xB0u: { const uint32_t ea = ConsumeDataAddr16(); BusWrite8(ea, OpDec8(BusRead8(ea))); break; }
    case 0xA1u: WriteRegPair(RP_AX, static_cast<uint16_t>(ReadRegPair(RP_AX) + 1u)); break;
    case 0xB1u: WriteRegPair(RP_AX, static_cast<uint16_t>(ReadRegPair(RP_AX) - 1u)); break;
    case 0xA2u: { const uint32_t ea = ConsumeDataAddr16(); BusWrite16(ea, static_cast<uint16_t>(BusRead16(ea) + 1u)); break; }
    case 0xB2u: { const uint32_t ea = ConsumeDataAddr16(); BusWrite16(ea, static_cast<uint16_t>(BusRead16(ea) - 1u)); break; }
    case 0xA3u: WriteRegPair(RP_BC, static_cast<uint16_t>(ReadRegPair(RP_BC) + 1u)); break;
    case 0xB3u: WriteRegPair(RP_BC, static_cast<uint16_t>(ReadRegPair(RP_BC) - 1u)); break;
    case 0xA4u: { const uint32_t ea = ConsumeSaddr(); BusWrite8(ea, OpInc8(BusRead8(ea))); break; }
    case 0xB4u: { const uint32_t ea = ConsumeSaddr(); BusWrite8(ea, OpDec8(BusRead8(ea))); break; }
    case 0xA5u: WriteRegPair(RP_DE, static_cast<uint16_t>(ReadRegPair(RP_DE) + 1u)); break;
    case 0xB5u: WriteRegPair(RP_DE, static_cast<uint16_t>(ReadRegPair(RP_DE) - 1u)); break;
    case 0xA6u: { const uint32_t ea = ConsumeSaddrP(); BusWrite16(ea, static_cast<uint16_t>(BusRead16(ea) + 1u)); break; }
    case 0xB6u: { const uint32_t ea = ConsumeSaddrP(); BusWrite16(ea, static_cast<uint16_t>(BusRead16(ea) - 1u)); break; }
    case 0xA7u: WriteRegPair(RP_HL, static_cast<uint16_t>(ReadRegPair(RP_HL) + 1u)); break;
    case 0xB7u: WriteRegPair(RP_HL, static_cast<uint16_t>(ReadRegPair(RP_HL) - 1u)); break;

    case 0xA8u: WriteRegPair(RP_AX, BusRead16(ResolveBasedSpImm(ConsumeByte()))); break;
    case 0xB8u: BusWrite16(ResolveBasedSpImm(ConsumeByte()), ReadRegPair(RP_AX)); break;
    case 0xA9u: WriteRegPair(RP_AX, BusRead16(ResolveIndirect(RP_DE))); break;
    case 0xB9u: BusWrite16(ResolveIndirect(RP_DE), ReadRegPair(RP_AX)); break;
    case 0xAAu: WriteRegPair(RP_AX, BusRead16(ResolveBasedDeImm(ConsumeByte()))); break;
    case 0xBAu: BusWrite16(ResolveBasedDeImm(ConsumeByte()), ReadRegPair(RP_AX)); break;
    case 0xABu: WriteRegPair(RP_AX, BusRead16(ResolveIndirect(RP_HL))); break;
    case 0xBBu: BusWrite16(ResolveIndirect(RP_HL), ReadRegPair(RP_AX)); break;
    case 0xACu: WriteRegPair(RP_AX, BusRead16(ResolveBasedHlImm(ConsumeByte()))); break;
    case 0xBCu: BusWrite16(ResolveBasedHlImm(ConsumeByte()), ReadRegPair(RP_AX)); break;
    case 0xADu: WriteRegPair(RP_AX, BusRead16(ConsumeSaddrP())); break;
    case 0xBDu: BusWrite16(ConsumeSaddrP(), ReadRegPair(RP_AX)); break;
    case 0xAEu: WriteRegPair(RP_AX, BusRead16(ConsumeSfrP())); break;
    case 0xBEu: BusWrite16(ConsumeSfrP(), ReadRegPair(RP_AX)); break;
    case 0xAFu: WriteRegPair(RP_AX, BusRead16(ConsumeDataAddr16())); break;
    case 0xBFu: BusWrite16(ConsumeDataAddr16(), ReadRegPair(RP_AX)); break;

    case 0xC0u: case 0xC2u: case 0xC4u: case 0xC6u:
        WriteRegPair(lo >> 1, PopWord16());
        break;
    case 0xC1u: case 0xC3u: case 0xC5u: case 0xC7u:
        PushWord16(ReadRegPair(lo >> 1));
        break;

    case 0xC8u: { const uint32_t ea = ResolveBasedSpImm(ConsumeByte()); BusWrite8(ea, ConsumeByte()); break; }
    case 0xC9u: { const uint32_t ea = ConsumeSaddrP(); BusWrite16(ea, ConsumeWord()); break; }
    case 0xCAu: { const uint32_t ea = ResolveBasedDeImm(ConsumeByte()); BusWrite8(ea, ConsumeByte()); break; }
    case 0xCBu: { const uint32_t ea = ConsumeSfrP(); BusWrite16(ea, ConsumeWord()); break; }
    case 0xCCu: { const uint32_t ea = ResolveBasedHlImm(ConsumeByte()); BusWrite8(ea, ConsumeByte()); break; }
    case 0xCDu: { const uint32_t ea = ConsumeSaddr(); BusWrite8(ea, ConsumeByte()); break; }
    case 0xCEu: {
        const uint8_t sfr = ConsumeByte();
        if (sfr == 0xFBu && !has_es_) {
            ExecuteS3Extended();
        } else {
            const uint32_t ea = Rl78Bus::ResolveSfr(sfr);
            BusWrite8(ea, ConsumeByte());
        }
        break;
    }
    case 0xCFu: { const uint32_t ea = ConsumeDataAddr16(); BusWrite8(ea, ConsumeByte()); break; }

    case 0xD0u: case 0xD1u: case 0xD2u: case 0xD3u:
        SetFlagsZAcCy(ReadReg(lo) == 0, false, false);
        break;
    case 0xD4u:
        SetFlagsZAcCy(BusRead8(ConsumeSaddr()) == 0, false, false);
        break;
    case 0xD5u:
        SetFlagsZAcCy(BusRead8(ConsumeDataAddr16()) == 0, false, false);
        break;

    case 0xD6u: {  // MULU X: AX = A * X
        const uint16_t a = ReadReg(REG_A);
        const uint16_t x = ReadReg(REG_X);
        WriteRegPair(RP_AX, static_cast<uint16_t>(a * x));
        break;
    }
    case 0xD7u:  // RET
        pc_ = PopCallFrame();
        inst_cycles_ += 4u;
        break;

    case 0xD8u: WriteReg(REG_X, BusRead8(ConsumeSaddr())); break;
    case 0xE8u: WriteReg(REG_B, BusRead8(ConsumeSaddr())); break;
    case 0xF8u: WriteReg(REG_C, BusRead8(ConsumeSaddr())); break;
    case 0xD9u: WriteReg(REG_X, BusRead8(ConsumeDataAddr16())); break;
    case 0xE9u: WriteReg(REG_B, BusRead8(ConsumeDataAddr16())); break;
    case 0xF9u: WriteReg(REG_C, BusRead8(ConsumeDataAddr16())); break;
    case 0xDAu: WriteRegPair(RP_BC, BusRead16(ConsumeSaddrP())); break;
    case 0xEAu: WriteRegPair(RP_DE, BusRead16(ConsumeSaddrP())); break;
    case 0xFAu: WriteRegPair(RP_HL, BusRead16(ConsumeSaddrP())); break;
    case 0xDBu: WriteRegPair(RP_BC, BusRead16(ConsumeDataAddr16())); break;
    case 0xEBu: WriteRegPair(RP_DE, BusRead16(ConsumeDataAddr16())); break;
    case 0xFBu: WriteRegPair(RP_HL, BusRead16(ConsumeDataAddr16())); break;

    case 0xDCu: { const uint32_t t = ConsumeRel8(); if (GetCY()) { pc_ = t; inst_cycles_ += 2u; } break; }
    case 0xDDu: { const uint32_t t = ConsumeRel8(); if ((psw_ & PSW_Z) != 0) { pc_ = t; inst_cycles_ += 2u; } break; }
    case 0xDEu: { const uint32_t t = ConsumeRel8(); if (!GetCY()) { pc_ = t; inst_cycles_ += 2u; } break; }
    case 0xDFu: { const uint32_t t = ConsumeRel8(); if ((psw_ & PSW_Z) == 0) { pc_ = t; inst_cycles_ += 2u; } break; }

    case 0xECu: pc_ = ConsumeAddr20(); inst_cycles_ += 2u; break;     // BR !!addr20
    case 0xEDu: pc_ = ConsumeCodeAddr16(); inst_cycles_ += 2u; break; // BR !addr16
    case 0xEEu: pc_ = ConsumeRel16(); inst_cycles_ += 2u; break;      // BR $!addr20
    case 0xEFu: pc_ = ConsumeRel8(); inst_cycles_ += 2u; break;       // BR $addr20

    case 0xE0u: case 0xE1u: case 0xE2u: case 0xE3u: WriteReg(lo, 0x01u); break;
    case 0xE4u: BusWrite8(ConsumeSaddr(), 0x01u); break;
    case 0xE5u: BusWrite8(ConsumeDataAddr16(), 0x01u); break;
    case 0xE6u: WriteRegPair(RP_AX, 0x0001u); break;
    case 0xE7u: WriteRegPair(RP_BC, 0x0001u); break;

    case 0xF0u: case 0xF1u: case 0xF2u: case 0xF3u: WriteReg(lo, 0x00u); break;
    case 0xF4u: BusWrite8(ConsumeSaddr(), 0x00u); break;
    case 0xF5u: BusWrite8(ConsumeDataAddr16(), 0x00u); break;
    case 0xF6u: WriteRegPair(RP_AX, 0x0000u); break;
    case 0xF7u: WriteRegPair(RP_BC, 0x0000u); break;

    case 0xFCu: {  // CALL !!addr20
        const uint32_t tgt = ConsumeAddr20();
        PushCallFrame(pc_);
        pc_ = tgt;
        inst_cycles_ += 2u;
        break;
    }
    case 0xFDu: {  // CALL !addr16
        const uint32_t tgt = ConsumeCodeAddr16();
        PushCallFrame(pc_);
        pc_ = tgt;
        inst_cycles_ += 2u;
        break;
    }
    case 0xFEu: {  // CALL $!addr20
        const uint32_t tgt = ConsumeRel16();
        PushCallFrame(pc_);
        pc_ = tgt;
        inst_cycles_ += 2u;
        break;
    }

    case 0xFFu: {  // BRK1 / illegal 0xFF triggers internal reset (RESF.IAWRF=0x80) to [0x00000]
        const uint16_t reset_vec = MakeWord(bus_->PeekByte(0x00000u), bus_->PeekByte(0x00001u));
        if (stop_on_brk || reset_vec == 0x0000u || reset_vec == 0xFFFFu) {
            brk_stopped_ = true;
            break;
        }
        bus_->ResetDevices();
        if (clock_) {
            clock_->LatchResetCause(0x80u);  // RESF.IAWRF
        }
        macr_ = 0;
        SetSP(0x0000u);
        SetPSW(0x06u);
        SetCS(0x00u);
        SetES(0x0Fu);
        SetPMC(0x00u);
        pc_ = reset_vec;
        inst_cycles_ += 5u;
        break;
    }

    default:
        invalid_insn_ = true;
        last_invalid_opcode_ = code;
        break;
    }
}

}  // namespace rl78
