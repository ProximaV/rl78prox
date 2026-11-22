#include "rl78_peripherals.h"

#include <algorithm>
#include <cctype>
#include <cstring>

namespace rl78 {

namespace {

constexpr IrqSourceDef kG13IrqDefs[] = {
    { IRQ_WDTI,  0, 0x01u, 0x0004u, "INTWDTI" },
    { IRQ_LVI,   0, 0x02u, 0x0006u, "INTLVI"  },
    { IRQ_P0,    0, 0x04u, 0x0008u, "INTP0"   },
    { IRQ_P1,    0, 0x08u, 0x000Au, "INTP1"   },
    { IRQ_P2,    0, 0x10u, 0x000Cu, "INTP2"   },
    { IRQ_P3,    0, 0x20u, 0x000Eu, "INTP3"   },
    { IRQ_P4,    0, 0x40u, 0x0010u, "INTP4"   },
    { IRQ_P5,    0, 0x80u, 0x0012u, "INTP5"   },

    { IRQ_ST2,   1, 0x01u, 0x0014u, "INTST2"  },
    { IRQ_SR2,   1, 0x02u, 0x0016u, "INTSR2"  },
    { IRQ_SRE2,  1, 0x04u, 0x0018u, "INTSRE2" },
    { IRQ_DMA0,  1, 0x08u, 0x001Au, "INTDMA0" },
    { IRQ_DMA1,  1, 0x10u, 0x001Cu, "INTDMA1" },
    { IRQ_ST0,   1, 0x20u, 0x001Eu, "INTST0"  },
    { IRQ_SR0,   1, 0x40u, 0x0020u, "INTSR0"  },
    { IRQ_SRE0,  1, 0x80u, 0x0022u, "INTSRE0" },

    { IRQ_ST1,   2, 0x01u, 0x0024u, "INTST1"  },
    { IRQ_SR1,   2, 0x02u, 0x0026u, "INTSR1"  },
    { IRQ_SRE1,  2, 0x04u, 0x0028u, "INTSRE1" },
    { IRQ_IICA0, 2, 0x08u, 0x002Au, "INTIICA0"},
    { IRQ_TM00,  2, 0x10u, 0x002Cu, "INTTM00" },
    { IRQ_TM01,  2, 0x20u, 0x002Eu, "INTTM01" },
    { IRQ_TM02,  2, 0x40u, 0x0030u, "INTTM02" },
    { IRQ_TM03,  2, 0x80u, 0x0032u, "INTTM03" },

    { IRQ_AD,    3, 0x01u, 0x0034u, "INTAD"   },
    { IRQ_RTC,   3, 0x02u, 0x0036u, "INTRTC"  },
    { IRQ_IT,    3, 0x04u, 0x0038u, "INTIT"   },
    { IRQ_KR,    3, 0x08u, 0x003Au, "INTKR"   },
    { IRQ_ST3,   3, 0x10u, 0x003Cu, "INTST3"  },
    { IRQ_SR3,   3, 0x20u, 0x003Eu, "INTSR3"  },
    { IRQ_TM13,  3, 0x40u, 0x0040u, "INTTM13" },
    { IRQ_TM04,  3, 0x80u, 0x0042u, "INTTM04" },

    { IRQ_TM05,  4, 0x01u, 0x0044u, "INTTM05" },
    { IRQ_TM06,  4, 0x02u, 0x0046u, "INTTM06" },
    { IRQ_TM07,  4, 0x04u, 0x0048u, "INTTM07" },
    { IRQ_P6,    4, 0x08u, 0x004Au, "INTP6"   },
    { IRQ_P7,    4, 0x10u, 0x004Cu, "INTP7"   },
    { IRQ_P8,    4, 0x20u, 0x004Eu, "INTP8"   },
    { IRQ_P9,    4, 0x40u, 0x0050u, "INTP9"   },
    { IRQ_P10,   4, 0x80u, 0x0052u, "INTP10"  },

    { IRQ_P11,   5, 0x01u, 0x0054u, "INTP11"  },
    { IRQ_TM10,  5, 0x02u, 0x0056u, "INTTM10" },
    { IRQ_TM11,  5, 0x04u, 0x0058u, "INTTM11" },
    { IRQ_TM12,  5, 0x08u, 0x005Au, "INTTM12" },
    { IRQ_SRE3,  5, 0x10u, 0x005Cu, "INTSRE3" },
    { IRQ_MD,    5, 0x20u, 0x005Eu, "INTMD"   },
    { IRQ_IICA1, 5, 0x40u, 0x0060u, "INTIICA1"},
    { IRQ_FL,    5, 0x80u, 0x0062u, "INTFL"   },

    { IRQ_DMA2,  6, 0x01u, 0x0064u, "INTDMA2" },
    { IRQ_DMA3,  6, 0x02u, 0x0066u, "INTDMA3" },
    { IRQ_TM14,  6, 0x04u, 0x0068u, "INTTM14" },
    { IRQ_TM15,  6, 0x08u, 0x006Au, "INTTM15" },
    { IRQ_TM16,  6, 0x10u, 0x006Cu, "INTTM16" },
    { IRQ_TM17,  6, 0x20u, 0x006Eu, "INTTM17" },
};

bool AsciiEqualsIgnoreCase(const char *a, const char *b) {
    if (!a || !b) return false;
    while (*a && *b) {
        if (std::tolower(static_cast<unsigned char>(*a)) !=
            std::tolower(static_cast<unsigned char>(*b))) {
            return false;
        }
        ++a;
        ++b;
    }
    return *a == '\0' && *b == '\0';
}

uint16_t SetU16Half(uint16_t cur, bool hi, uint8_t value) {
    return hi ? static_cast<uint16_t>((cur & 0x00FFu) | (static_cast<uint16_t>(value) << 8))
              : static_cast<uint16_t>((cur & 0xFF00u) | value);
}

uint8_t GetU16Half(uint16_t cur, bool hi) {
    return hi ? static_cast<uint8_t>((cur >> 8) & 0xFFu) : static_cast<uint8_t>(cur & 0xFFu);
}

}  // namespace

// ============================================================================
// Rl78Intc
// ============================================================================

Rl78Intc::Rl78Intc() {
    sources_.assign(std::begin(kG13IrqDefs), std::end(kG13IrqDefs));
    Reset();
}

void Rl78Intc::Reset() {
    if_regs_.fill(0x00u);
    mk_regs_.fill(0xFFu);
    pr0_regs_.fill(0xFFu);
    pr1_regs_.fill(0xFFu);
}

bool Rl78Intc::DecodeRegAddr(uint32_t addr, uint8_t *bank_out, uint8_t *slot_out) {
    // 0xFFFE0..0xFFFEF: IF0(0..3), MK0(0..3), PR00(0..3), PR10(0..3)
    // 0xFFFD0..0xFFFDF: IF2L(4),IF2H(5),IF3L(6); MK2L..3L; PR02L..3L; PR12L..3L
    if (addr >= 0xFFFE0u && addr <= 0xFFFEFu) {
        const uint32_t off = addr - 0xFFFE0u;
        *bank_out = static_cast<uint8_t>(off / 4u);  // 0=IF, 1=MK, 2=PR0, 3=PR1
        *slot_out = static_cast<uint8_t>(off % 4u);  // 0..3
        return true;
    }
    if (addr >= 0xFFFD0u && addr <= 0xFFFDFu) {
        const uint32_t off = addr - 0xFFFD0u;
        const uint8_t sub = static_cast<uint8_t>(off % 4u);
        if (sub <= 2u) {
            *bank_out = static_cast<uint8_t>(off / 4u);
            *slot_out = static_cast<uint8_t>(4u + sub);  // 4=2L, 5=2H, 6=3L
            return true;
        }
    }
    return false;
}

uint8_t Rl78Intc::Read(uint32_t addr) {
    return Peek(addr);
}

void Rl78Intc::Write(uint32_t addr, uint8_t value) {
    Poke(addr, value);
}

uint8_t Rl78Intc::Peek(uint32_t addr) const {
    uint8_t bank = 0, slot = 0;
    if (!DecodeRegAddr(addr, &bank, &slot)) {
        return 0xFFu;
    }
    switch (bank) {
    case 0: return if_regs_[slot];
    case 1: return mk_regs_[slot];
    case 2: return pr0_regs_[slot];
    case 3: return pr1_regs_[slot];
    default: return 0xFFu;
    }
}

void Rl78Intc::Poke(uint32_t addr, uint8_t value) {
    uint8_t bank = 0, slot = 0;
    if (!DecodeRegAddr(addr, &bank, &slot)) {
        return;
    }
    switch (bank) {
    case 0: if_regs_[slot] = (slot == 6u) ? static_cast<uint8_t>(value & 0x3Fu) : value; break;
    case 1: mk_regs_[slot] = value; break;
    case 2: pr0_regs_[slot] = value; break;
    case 3: pr1_regs_[slot] = value; break;
    }
}

PendingInterrupt Rl78Intc::EvaluatePending() const {
    PendingInterrupt best;
    best.priority = 4u;  // sentinel worse than 3

    for (const auto &src : sources_) {
        const uint8_t req = if_regs_[src.reg_slot] & src.bit_mask;
        const uint8_t msk = mk_regs_[src.reg_slot] & src.bit_mask;
        if (req == 0 || msk != 0) {
            continue;
        }
        const uint8_t p0 = (pr0_regs_[src.reg_slot] & src.bit_mask) ? 1u : 0u;
        const uint8_t p1 = (pr1_regs_[src.reg_slot] & src.bit_mask) ? 2u : 0u;
        const uint8_t prio = static_cast<uint8_t>(p1 | p0);  // 0=highest .. 3=lowest
        if (!best.pending || prio < best.priority) {
            best.pending = true;
            best.source_index = src.index;
            best.priority = prio;
            best.vector_address = src.vector_addr;
        }
    }
    return best;
}

bool Rl78Intc::HasUnmaskedPending() const {
    return EvaluatePending().pending;
}

void Rl78Intc::Acknowledge(uint8_t source_index) {
    ClearIrq(source_index);
}

void Rl78Intc::RaiseIrq(uint8_t source_index) {
    for (const auto &src : sources_) {
        if (src.index == source_index) {
            if_regs_[src.reg_slot] |= src.bit_mask;
            return;
        }
    }
}

void Rl78Intc::ClearIrq(uint8_t source_index) {
    for (const auto &src : sources_) {
        if (src.index == source_index) {
            if_regs_[src.reg_slot] &= static_cast<uint8_t>(~src.bit_mask);
            return;
        }
    }
}

int Rl78Intc::FindIrqByName(const char *name) const {
    for (const auto &src : sources_) {
        if (AsciiEqualsIgnoreCase(src.name, name)) {
            return src.index;
        }
    }
    return -1;
}

// ============================================================================
// Rl78Clock
// ============================================================================

void Rl78Clock::Reset() {
    cmc_ = 0x00u;
    csc_ = 0xC0u;
    ostc_ = 0x00u;
    osts_ = 0x07u;
    ckc_ = 0x00u;
    cks0_ = 0x00u;
    cks1_ = 0x00u;
    resf_ = 0x00u;
    lvim_ = 0x00u;
    lvis_ = 0x00u;
    crcin_ = 0x00u;
    dflctl_ = 0x00u;
    hiotrm_ = 0x20u;
    hocodiv_ = 0x00u;
    per0_ = 0x00u;
    osmc_ = 0x00u;
    rmc_ = 0x00u;
    rpectl_ = 0x00u;
    iawctl_ = 0x00u;
    gdidis_ = 0x00u;
    sub_acc_ = 0;
    il_acc_ = 0;
    ostc_timer_ = 0;
    if (bus_) {
        bus_->SetDataFlashEnabled(false);
    }
}

uint8_t Rl78Clock::GetCkc() const {
    uint8_t v = ckc_ & 0x5Fu;
    if ((ckc_ & 0x10u) != 0) v |= 0x20u;  // MCM0 -> MCS
    if ((ckc_ & 0x40u) != 0) v |= 0x80u;  // CSS -> CLS
    return v;
}

void Rl78Clock::UpdateOstc() {
    if (IsMainStopped()) {
        ostc_ = 0x00u;
        ostc_timer_ = 0;
    } else {
        // Counts up to the stabilization bit mask selected by OSTS (0..7 -> 0x80..0xFF).
        ostc_ = static_cast<uint8_t>(0xFFu << (7u - (osts_ & 0x07u)));
    }
}

uint8_t Rl78Clock::Read(uint32_t addr) {
    return Peek(addr);
}

void Rl78Clock::Write(uint32_t addr, uint8_t value) {
    Poke(addr, value);
}

uint8_t Rl78Clock::Peek(uint32_t addr) const {
    switch (addr) {
    case 0xFFFA0u: return cmc_;
    case 0xFFFA1u: return csc_;
    case 0xFFFA2u: return ostc_;
    case 0xFFFA3u: return osts_;
    case 0xFFFA4u: return GetCkc();
    case 0xFFFA5u: return cks0_;
    case 0xFFFA6u: return cks1_;
    case 0xFFFA8u: return resf_;
    case 0xFFFA9u: return lvim_;
    case 0xFFFAAu: return lvis_;
    case 0xFFFACu: return crcin_;
    case 0xF0078u: return iawctl_;
    case 0xF007Du: return gdidis_;
    case 0xF0090u: return dflctl_;
    case 0xF00A0u: return hiotrm_;
    case 0xF00A8u: return hocodiv_;
    case 0xF00F0u: return per0_;
    case 0xF00F3u: return osmc_;
    case 0xF00F4u: return rmc_;
    case 0xF00F5u: return rpectl_;
    case 0xF00FEu: return 0x00u;
    default: return 0xFFu;
    }
}

void Rl78Clock::Poke(uint32_t addr, uint8_t value) {
    switch (addr) {
    case 0xFFFA0u: cmc_ = value; break;
    case 0xFFFA1u: csc_ = value & 0xC1u; UpdateOstc(); break;
    case 0xFFFA2u: ostc_ = value; break;
    case 0xFFFA3u: osts_ = value & 0x07u; break;
    case 0xFFFA4u: ckc_ = value & 0x5Fu; break;
    case 0xFFFA5u: cks0_ = value; break;
    case 0xFFFA6u: cks1_ = value; break;
    case 0xFFFA8u: resf_ = value; break;
    case 0xFFFA9u: lvim_ = value; break;
    case 0xFFFAAu: lvis_ = value; break;
    case 0xFFFACu: crcin_ = value; break;
    case 0xF0078u: iawctl_ = value; break;
    case 0xF007Du: gdidis_ = value; break;
    case 0xF0090u:
        dflctl_ = value & 0x01u;
        if (bus_) {
            bus_->SetDataFlashEnabled((dflctl_ & 0x01u) != 0);
        }
        break;
    case 0xF00A0u: hiotrm_ = value & 0x3Fu; break;
    case 0xF00A8u: hocodiv_ = value & 0x07u; break;
    case 0xF00F0u: per0_ = value; break;
    case 0xF00F3u: osmc_ = value; break;
    case 0xF00F4u: rmc_ = value; break;
    case 0xF00F5u: rpectl_ = value; break;
    default: break;
    }
}

void Rl78Clock::Tick(uint32_t cpu_cycles, uint32_t, uint32_t, uint32_t, bool, bool) {
    const uint8_t target = static_cast<uint8_t>(0xFFu << (7u - (osts_ & 0x07u)));
    if (!IsMainStopped() && ostc_ != target) {
        ostc_timer_ += cpu_cycles;
        ostc_ = target;
    }
}

void Rl78Clock::OnEnterStop() {
    ostc_ = 0x00u;
}

void Rl78Clock::OnExitStop() {
    UpdateOstc();
}

void Rl78Clock::ComputeSubClocks(uint32_t cpu_cycles,
                                 bool in_halt,
                                 bool in_stop,
                                 uint32_t *prs_cycles_out,
                                 uint32_t *sub_cycles_out,
                                 uint32_t *il_cycles_out) {
    // fSUB (~32.768 kHz) runs when XT1 enabled or in subsystem mode; approximate 1:64 vs fCLK if running.
    sub_acc_ += cpu_cycles;
    const uint32_t sub = (!IsSubStopped() || (osmc_ & 0x10u) != 0) ? (sub_acc_ / 64u) : 0u;
    if (sub > 0) sub_acc_ %= 64u;

    // fIL (~15 kHz) always runs for WDT/ITMC unless explicitly disabled; approximate 1:256 vs fCLK.
    il_acc_ += cpu_cycles;
    const uint32_t il = il_acc_ / 256u;
    il_acc_ %= 256u;

    uint32_t prs = 0;
    if (!in_stop) {
        if (IsSubClockSelected()) {
            prs = in_halt ? sub : cpu_cycles;
        } else {
            prs = cpu_cycles;
        }
    }

    if (prs_cycles_out) *prs_cycles_out = prs;
    if (sub_cycles_out) *sub_cycles_out = sub;
    if (il_cycles_out)  *il_cycles_out  = il;
}

// ============================================================================
// Rl78Wdt
// ============================================================================

void Rl78Wdt::Reset() {
    option_byte_ = bus_ ? bus_->PeekByte(0x000C0u) : 0x00u;
    // Bit 4 (WDTON): 1 = WDT enabled; bits 3..1 = overflow interval; bit 7 = WDTINT.
    wdton_ = (option_byte_ != 0xFFu) && ((option_byte_ & 0x10u) != 0);
    halt_run_ = (option_byte_ & 0x01u) != 0;
    wdcs_ = static_cast<uint8_t>((option_byte_ >> 1) & 0x07u);
    window_ = static_cast<uint8_t>((option_byte_ >> 5) & 0x03u);
    wdtint_ = (option_byte_ & 0x80u) != 0;
    int_fired_ = false;
    counter_ = 0;
    // Period in fIL ticks (min 2^6=64, up to 2^16=65536).
    static constexpr uint32_t kPeriods[8] = {
        64u, 128u, 256u, 512u, 1024u, 2048u, 4096u, 8192u
    };
    overflow_period_ = kPeriods[wdcs_];
}

uint8_t Rl78Wdt::Read(uint32_t) {
    return Peek(0xFFFABu);
}

void Rl78Wdt::Write(uint32_t, uint8_t value) {
    if (value == 0xACu) {
        counter_ = 0;
        int_fired_ = false;
    } else if (wdton_) {
        TriggerReset();
    }
}

uint8_t Rl78Wdt::Peek(uint32_t) const {
    return wdton_ ? 0x9Au : 0x1Au;
}

void Rl78Wdt::Poke(uint32_t, uint8_t value) {
    if (value == 0xACu) {
        counter_ = 0;
        int_fired_ = false;
    }
}

void Rl78Wdt::Tick(uint32_t, uint32_t, uint32_t, uint32_t il_cycles, bool in_halt, bool in_stop) {
    if (!wdton_ || il_cycles == 0) {
        return;
    }
    if ((in_halt || in_stop) && !halt_run_) {
        return;
    }
    counter_ += il_cycles;
    if (wdtint_ && !int_fired_ && intc_ && counter_ >= (overflow_period_ * 3u) / 4u) {
        int_fired_ = true;
        intc_->RaiseIrq(IRQ_WDTI);
    }
    if (counter_ >= overflow_period_) {
        counter_ = 0;
        TriggerReset();
    }
}

void Rl78Wdt::TriggerReset() {
    if (clk_) {
        clk_->SetResetFlag(0x10u);  // RESF.WDTRF bit 4
    }
    if (cpu_) {
        cpu_->RequestWdtReset();
    }
    if (!halt_on_reset && cpu_) {
        cpu_->Reset();
    }
}

// ============================================================================
// Rl78Ports
// ============================================================================

void Rl78Ports::Reset() {
    latch_.fill(0x00u);
    mode_.fill(0xFFu);
    pullup_.fill(0x00u);
    pullup_[4] = 0x01u;
    pim_.fill(0x00u);
    pom_.fill(0x00u);
    pmc_.fill(0x00u);
    ext_in_.fill(0xFFu);
    nfen0_ = nfen1_ = nfen2_ = 0;
    isc_ = tis0_ = adpc_ = pior_ = 0;
    krm_ = egp0_ = egn0_ = egp1_ = egn1_ = 0;
}

void Rl78Ports::CheckEdgeIntp(uint8_t port, uint8_t pin, bool old_high, bool new_high) {
    if (!intc_ || old_high == new_high) {
        return;
    }
    struct PinIrqMap { uint8_t port; uint8_t pin; uint8_t intp; };
    static constexpr PinIrqMap kMaps[] = {
        { 13, 7, 0 }, {  5, 0, 1 }, {  5, 1, 2 }, {  3, 0, 3 },
        {  3, 1, 4 }, {  1, 6, 5 }, { 14, 0, 6 }, { 14, 1, 7 },
        {  7, 4, 8 }, {  7, 5, 9 }, {  7, 6, 10 }, {  7, 7, 11 },
    };
    const bool rising = !old_high && new_high;
    const bool falling = old_high && !new_high;
    for (const auto &m : kMaps) {
        if (m.port == port && m.pin == pin) {
            const uint8_t mask = (m.intp < 8u) ? static_cast<uint8_t>(1u << m.intp)
                                               : static_cast<uint8_t>(1u << (m.intp - 8u));
            const uint8_t egp = (m.intp < 8u) ? egp0_ : egp1_;
            const uint8_t egn = (m.intp < 8u) ? egn0_ : egn1_;
            if ((rising && (egp & mask)) || (falling && (egn & mask))) {
                const uint8_t irq_id = (m.intp <= 5u) ? static_cast<uint8_t>(IRQ_P0 + m.intp)
                                     : (m.intp <= 10u) ? static_cast<uint8_t>(IRQ_P6 + (m.intp - 6u))
                                     : IRQ_P11;
                intc_->RaiseIrq(irq_id);
            }
        }
    }
    if (port == 7 && falling && (krm_ & (1u << pin))) {
        intc_->RaiseIrq(IRQ_KR);
    }
}

void Rl78Ports::SetExternalInput(uint8_t port, uint8_t pin, bool high) {
    if (port >= 16u || pin >= 8u) return;
    const uint8_t mask = static_cast<uint8_t>(1u << pin);
    const bool old_high = (ext_in_[port] & mask) != 0;
    if (high) ext_in_[port] |= mask;
    else ext_in_[port] &= static_cast<uint8_t>(~mask);
    CheckEdgeIntp(port, pin, old_high, high);
}

void Rl78Ports::SetExternalPortByte(uint8_t port, uint8_t value) {
    if (port >= 16u) return;
    for (uint8_t pin = 0; pin < 8u; ++pin) {
        SetExternalInput(port, pin, ((value >> pin) & 1u) != 0);
    }
}

uint8_t Rl78Ports::GetPinState(uint8_t port) const {
    if (port >= 16u) return 0xFFu;
    const uint8_t pm = mode_[port];
    const uint8_t out_bits = static_cast<uint8_t>(latch_[port] & ~pm);
    const uint8_t in_bits = static_cast<uint8_t>((ext_in_[port] | pullup_[port]) & pm);
    return static_cast<uint8_t>(out_bits | in_bits);
}

uint8_t Rl78Ports::Read(uint32_t addr) {
    if (addr >= 0xFFF00u && addr <= 0xFFF0Fu) {
        return GetPinState(static_cast<uint8_t>(addr - 0xFFF00u));
    }
    return Peek(addr);
}

void Rl78Ports::Write(uint32_t addr, uint8_t value) {
    Poke(addr, value);
}

uint8_t Rl78Ports::Peek(uint32_t addr) const {
    if (addr >= 0xFFF00u && addr <= 0xFFF0Fu) return latch_[addr - 0xFFF00u];
    if (addr >= 0xFFF20u && addr <= 0xFFF2Fu) return mode_[addr - 0xFFF20u];
    if (addr >= 0xF0030u && addr <= 0xF003Fu) return pullup_[addr - 0xF0030u];
    if (addr >= 0xF0040u && addr <= 0xF004Fu) return pim_[addr - 0xF0040u];
    if (addr >= 0xF0050u && addr <= 0xF005Fu) return pom_[addr - 0xF0050u];
    if (addr >= 0xF0060u && addr <= 0xF006Fu) return pmc_[addr - 0xF0060u];
    switch (addr) {
    case 0xFFF37u: return krm_;
    case 0xFFF38u: return egp0_;
    case 0xFFF39u: return egn0_;
    case 0xFFF3Au: return egp1_;
    case 0xFFF3Bu: return egn1_;
    case 0xF0070u: return nfen0_;
    case 0xF0071u: return nfen1_;
    case 0xF0072u: return nfen2_;
    case 0xF0073u: return isc_;
    case 0xF0074u: return tis0_;
    case 0xF0076u: return adpc_;
    case 0xF0077u: return pior_;
    default: return 0xFFu;
    }
}

void Rl78Ports::Poke(uint32_t addr, uint8_t value) {
    if (addr >= 0xFFF00u && addr <= 0xFFF0Fu) { latch_[addr - 0xFFF00u] = value; return; }
    if (addr >= 0xFFF20u && addr <= 0xFFF2Fu) { mode_[addr - 0xFFF20u] = value; return; }
    if (addr >= 0xF0030u && addr <= 0xF003Fu) { pullup_[addr - 0xF0030u] = value; return; }
    if (addr >= 0xF0040u && addr <= 0xF004Fu) { pim_[addr - 0xF0040u] = value; return; }
    if (addr >= 0xF0050u && addr <= 0xF005Fu) { pom_[addr - 0xF0050u] = value; return; }
    if (addr >= 0xF0060u && addr <= 0xF006Fu) { pmc_[addr - 0xF0060u] = value; return; }
    switch (addr) {
    case 0xFFF37u: krm_ = value; break;
    case 0xFFF38u: egp0_ = value; break;
    case 0xFFF39u: egn0_ = value; break;
    case 0xFFF3Au: egp1_ = value; break;
    case 0xFFF3Bu: egn1_ = value; break;
    case 0xF0070u: nfen0_ = value; break;
    case 0xF0071u: nfen1_ = value; break;
    case 0xF0072u: nfen2_ = value; break;
    case 0xF0073u: isc_ = value; break;
    case 0xF0074u: tis0_ = value; break;
    case 0xF0076u: adpc_ = value; break;
    case 0xF0077u: pior_ = value; break;
    default: break;
    }
}

// ============================================================================
// Rl78Tau (TAU0 / TAU1)
// ============================================================================

Rl78Tau::Rl78Tau(uint8_t unit_idx, Rl78Intc *intc,
                 const std::array<uint8_t, 8> &irq_nums, uint8_t num_channels)
    : unit_(unit_idx),
      num_channels_((num_channels >= 1u && num_channels <= 8u) ? num_channels : 8u),
      intc_(intc),
      irq_nums_(irq_nums) {
    Reset();
}

void Rl78Tau::Reset() {
    tcr_.fill(0xFFFFu);
    tdr_.fill(0x0000u);
    tmr_.fill(0x0000u);
    tsr_.fill(0x0000u);
    acc_.fill(0);
    te_ = tps_ = to_ = toe_ = tol_ = tom_ = 0;
}

bool Rl78Tau::DecodeAddr(uint32_t addr, RegKind *kind_out, uint8_t *ch_out, bool *hi_out) const {
    *ch_out = 0;
    *hi_out = false;
    if (unit_ == 0) {
        if (addr >= 0xFFF18u && addr <= 0xFFF1Bu) {
            *kind_out = RegKind::Tdr;
            *ch_out = static_cast<uint8_t>((addr - 0xFFF18u) / 2u);
            *hi_out = ((addr & 1u) != 0);
            return *ch_out < num_channels_;
        }
        if (addr >= 0xFFF64u && addr <= 0xFFF6Fu) {
            *kind_out = RegKind::Tdr;
            *ch_out = static_cast<uint8_t>(2u + (addr - 0xFFF64u) / 2u);
            *hi_out = ((addr & 1u) != 0);
            return *ch_out < num_channels_;
        }
    } else {
        const uint32_t tdr_end = 0xFFF70u + static_cast<uint32_t>(num_channels_) * 2u;
        if (addr >= 0xFFF70u && addr < tdr_end) {
            *kind_out = RegKind::Tdr;
            *ch_out = static_cast<uint8_t>((addr - 0xFFF70u) / 2u);
            *hi_out = ((addr & 1u) != 0);
            return true;
        }
    }

    const uint32_t base2 = (unit_ == 0) ? 0xF0180u : 0xF01C0u;
    const uint32_t stride = static_cast<uint32_t>(num_channels_) * 2u;
    const uint32_t reg_block_size = stride * 3u + 0x10u;
    if (addr < base2 || addr >= base2 + reg_block_size) {
        return false;
    }
    const uint32_t off = addr - base2;
    *hi_out = ((off & 1u) != 0);
    if (off < stride) {
        *kind_out = RegKind::Tcr;
        *ch_out = static_cast<uint8_t>(off / 2u);
        return true;
    }
    if (off < stride * 2u) {
        *kind_out = RegKind::Tmr;
        *ch_out = static_cast<uint8_t>((off - stride) / 2u);
        return true;
    }
    if (off < stride * 3u) {
        *kind_out = RegKind::Tsr;
        *ch_out = static_cast<uint8_t>((off - stride * 2u) / 2u);
        return true;
    }
    switch ((off - stride * 3u) & ~1u) {
    case 0x00u: *kind_out = RegKind::Te;  return true;
    case 0x02u: *kind_out = RegKind::Ts;  return true;
    case 0x04u: *kind_out = RegKind::Tt;  return true;
    case 0x06u: *kind_out = RegKind::Tps; return true;
    case 0x08u: *kind_out = RegKind::To;  return true;
    case 0x0Au: *kind_out = RegKind::Toe; return true;
    case 0x0Cu: *kind_out = RegKind::Tol; return true;
    case 0x0Eu: *kind_out = RegKind::Tom; return true;
    default: return false;
    }
}

uint8_t Rl78Tau::Read(uint32_t addr) {
    return Peek(addr);
}

void Rl78Tau::Write(uint32_t addr, uint8_t value) {
    RegKind kind = RegKind::Invalid;
    uint8_t ch = 0;
    bool hi = false;
    if (!DecodeAddr(addr, &kind, &ch, &hi)) return;

    if (kind == RegKind::Ts) {
        if (!hi) {
            for (uint8_t c = 0; c < num_channels_; ++c) {
                if ((value & (1u << c)) != 0) {
                    te_ |= static_cast<uint16_t>(1u << c);
                    tcr_[c] = tdr_[c];
                    acc_[c] = 0;
                }
            }
        }
        return;
    }
    if (kind == RegKind::Tt) {
        if (!hi) {
            const uint16_t mask = static_cast<uint16_t>((1u << num_channels_) - 1u);
            te_ &= static_cast<uint16_t>(~(value & mask));
        }
        return;
    }
    Poke(addr, value);
}

uint8_t Rl78Tau::Peek(uint32_t addr) const {
    RegKind kind = RegKind::Invalid;
    uint8_t ch = 0;
    bool hi = false;
    if (!DecodeAddr(addr, &kind, &ch, &hi)) return 0xFFu;
    switch (kind) {
    case RegKind::Tdr: return GetU16Half(tdr_[ch], hi);
    case RegKind::Tcr: return GetU16Half(tcr_[ch], hi);
    case RegKind::Tmr: return GetU16Half(tmr_[ch], hi);
    case RegKind::Tsr: return GetU16Half(tsr_[ch], hi);
    case RegKind::Te:  return GetU16Half(te_, hi);
    case RegKind::Ts:
    case RegKind::Tt:  return 0x00u;
    case RegKind::Tps: return GetU16Half(tps_, hi);
    case RegKind::To:  return GetU16Half(to_, hi);
    case RegKind::Toe: return GetU16Half(toe_, hi);
    case RegKind::Tol: return GetU16Half(tol_, hi);
    case RegKind::Tom: return GetU16Half(tom_, hi);
    default: return 0xFFu;
    }
}

void Rl78Tau::Poke(uint32_t addr, uint8_t value) {
    RegKind kind = RegKind::Invalid;
    uint8_t ch = 0;
    bool hi = false;
    if (!DecodeAddr(addr, &kind, &ch, &hi)) return;
    switch (kind) {
    case RegKind::Tdr: tdr_[ch] = SetU16Half(tdr_[ch], hi, value); break;
    case RegKind::Tcr: tcr_[ch] = SetU16Half(tcr_[ch], hi, value); break;
    case RegKind::Tmr: tmr_[ch] = SetU16Half(tmr_[ch], hi, value); break;
    case RegKind::Tsr: tsr_[ch] = SetU16Half(tsr_[ch], hi, value); break;
    case RegKind::Te:  te_ = SetU16Half(te_, hi, value); break;
    case RegKind::Tps: tps_ = SetU16Half(tps_, hi, value); break;
    case RegKind::To:  to_ = SetU16Half(to_, hi, value); break;
    case RegKind::Toe: toe_ = SetU16Half(toe_, hi, value); break;
    case RegKind::Tol: tol_ = SetU16Half(tol_, hi, value); break;
    case RegKind::Tom: tom_ = SetU16Half(tom_, hi, value); break;
    default: break;
    }
}

uint32_t Rl78Tau::ChannelDivisor(uint8_t ch) const {
    const uint8_t cks = static_cast<uint8_t>((tmr_[ch] >> 14) & 3u);
    const uint8_t prs_nibble = static_cast<uint8_t>((tps_ >> (cks * 4u)) & 0x0Fu);
    return 1u << std::min<uint8_t>(prs_nibble, 15u);
}

void Rl78Tau::Tick(uint32_t, uint32_t prs_cycles, uint32_t, uint32_t, bool, bool) {
    if (prs_cycles == 0 || (te_ & 0x00FFu) == 0) return;

    for (uint8_t ch = 0; ch < num_channels_; ++ch) {
        if ((te_ & (1u << ch)) == 0) continue;
        const uint32_t div = ChannelDivisor(ch);
        acc_[ch] += prs_cycles;
        uint32_t ticks = acc_[ch] / div;
        acc_[ch] %= div;
        while (ticks > 0) {
            if (tcr_[ch] == 0) {
                tcr_[ch] = tdr_[ch];
                if (intc_ && irq_nums_[ch] != 0xFFu) {
                    intc_->RaiseIrq(irq_nums_[ch]);
                }
                to_ ^= static_cast<uint16_t>(1u << ch);
                --ticks;
            } else if (ticks <= tcr_[ch]) {
                tcr_[ch] = static_cast<uint16_t>(tcr_[ch] - ticks);
                ticks = 0;
            } else {
                ticks -= (tcr_[ch] + 1u);
                tcr_[ch] = tdr_[ch];
                if (intc_ && irq_nums_[ch] != 0xFFu) {
                    intc_->RaiseIrq(irq_nums_[ch]);
                }
                to_ ^= static_cast<uint16_t>(1u << ch);
            }
        }
    }
}

// ============================================================================
// Rl78RtcIt
// ============================================================================

void Rl78RtcIt::Reset() {
    itmc_ = 0x0FFFu;
    it_counter_ = 0x0FFFu;
    it_sub_acc_ = 0;
    rtc_regs_.fill(0x00u);
    rtc_regs_[2] = 0x12u;  // HOUR
    rtc_regs_[4] = 0x01u;  // DAY
    rtc_regs_[5] = 0x01u;  // MONTH
    rtc_sub_acc_ = 0;
}

uint8_t Rl78RtcIt::IncBcd(uint8_t bcd) {
    uint8_t lo = (bcd & 0x0Fu) + 1u;
    uint8_t hi = (bcd >> 4) & 0x0Fu;
    if (lo >= 10u) {
        lo = 0;
        ++hi;
    }
    return static_cast<uint8_t>((hi << 4) | lo);
}

uint8_t Rl78RtcIt::Read(uint32_t addr) {
    return Peek(addr);
}

void Rl78RtcIt::Write(uint32_t addr, uint8_t value) {
    Poke(addr, value);
    if (addr == 0xFFF91u && (value & 0x80u) != 0) {
        it_counter_ = itmc_ & 0x0FFFu;
    }
}

uint8_t Rl78RtcIt::Peek(uint32_t addr) const {
    if (addr == 0xFFF90u) return static_cast<uint8_t>(itmc_ & 0xFFu);
    if (addr == 0xFFF91u) return static_cast<uint8_t>((itmc_ >> 8) & 0xFFu);
    if (addr >= 0xFFF92u && addr <= 0xFFF9Eu) return rtc_regs_[addr - 0xFFF92u];
    return 0xFFu;
}

void Rl78RtcIt::Poke(uint32_t addr, uint8_t value) {
    if (addr == 0xFFF90u) { itmc_ = SetU16Half(itmc_, false, value); return; }
    if (addr == 0xFFF91u) { itmc_ = SetU16Half(itmc_, true, value); return; }
    if (addr >= 0xFFF92u && addr <= 0xFFF9Eu) { rtc_regs_[addr - 0xFFF92u] = value; }
}

void Rl78RtcIt::Tick(uint32_t, uint32_t, uint32_t sub_cycles, uint32_t il_cycles, bool, bool) {
    // 12-bit Interval Timer (ITMC bit 15 = RINTE)
    const uint32_t it_ticks = (sub_cycles > 0) ? sub_cycles : il_cycles;
    if ((itmc_ & 0x8000u) != 0 && it_ticks > 0) {
        const uint16_t cmp = itmc_ & 0x0FFFu;
        uint32_t rem = it_ticks;
        while (rem > 0) {
            if (it_counter_ == 0) {
                it_counter_ = cmp;
                if (intc_) intc_->RaiseIrq(IRQ_IT);
                --rem;
            } else if (rem <= it_counter_) {
                it_counter_ = static_cast<uint16_t>(it_counter_ - rem);
                rem = 0;
            } else {
                rem -= (it_counter_ + 1u);
                it_counter_ = cmp;
                if (intc_) intc_->RaiseIrq(IRQ_IT);
            }
        }
    }

    // RTC (RTCC0 @ 0xFFF9D bit 7 = RTCE)
    if ((rtc_regs_[11] & 0x80u) != 0 && sub_cycles > 0) {
        rtc_sub_acc_ += sub_cycles;
        while (rtc_sub_acc_ >= 32768u) {
            rtc_sub_acc_ -= 32768u;
            rtc_regs_[0] = IncBcd(rtc_regs_[0]);  // SEC
            if (rtc_regs_[0] >= 0x60u) {
                rtc_regs_[0] = 0x00u;
                rtc_regs_[1] = IncBcd(rtc_regs_[1]);  // MIN
                if (rtc_regs_[1] >= 0x60u) {
                    rtc_regs_[1] = 0x00u;
                }
            }
            if ((rtc_regs_[11] & 0x07u) != 0 && intc_) {  // constant-period interrupt enabled
                rtc_regs_[12] |= 0x08u;  // RTCC1.RIFG
                intc_->RaiseIrq(IRQ_RTC);
            }
        }
    }
}

// ============================================================================
// Rl78Adc
// ============================================================================

void Rl78Adc::Reset() {
    adm0_ = ads_ = adm1_ = adm2_ = 0;
    adul_ = 0xFFu;
    adll_ = 0x00u;
    adtes_ = 0x00u;
    adcr_ = 0;
    conv_cycles_ = 0;
    channels_.fill(0x0200u);
}

uint8_t Rl78Adc::Read(uint32_t addr) {
    return Peek(addr);
}

void Rl78Adc::Write(uint32_t addr, uint8_t value) {
    Poke(addr, value);
    if (addr == 0xFFF30u && (adm0_ & 0x80u) != 0 && (adm0_ & 0x01u) != 0) {
        conv_cycles_ = 24u;
    }
}

uint8_t Rl78Adc::Peek(uint32_t addr) const {
    switch (addr) {
    case 0xFFF1Eu: return static_cast<uint8_t>(adcr_ & 0xFFu);
    case 0xFFF1Fu: return static_cast<uint8_t>((adcr_ >> 8) & 0xFFu);
    case 0xFFF30u: return adm0_;
    case 0xFFF31u: return ads_;
    case 0xFFF32u: return adm1_;
    case 0xF0010u: return adm2_;
    case 0xF0011u: return adul_;
    case 0xF0012u: return adll_;
    case 0xF0013u: return adtes_;
    default: return 0xFFu;
    }
}

void Rl78Adc::Poke(uint32_t addr, uint8_t value) {
    switch (addr) {
    case 0xFFF1Eu: adcr_ = SetU16Half(adcr_, false, value); break;
    case 0xFFF1Fu: adcr_ = SetU16Half(adcr_, true, value); break;
    case 0xFFF30u: adm0_ = value; break;
    case 0xFFF31u: ads_ = value & 0x1Fu; break;
    case 0xFFF32u: adm1_ = value; break;
    case 0xF0010u: adm2_ = value; break;
    case 0xF0011u: adul_ = value; break;
    case 0xF0012u: adll_ = value; break;
    case 0xF0013u: adtes_ = value; break;
    default: break;
    }
}

void Rl78Adc::Tick(uint32_t, uint32_t prs_cycles, uint32_t, uint32_t, bool, bool) {
    if (conv_cycles_ == 0 || prs_cycles == 0) return;
    if (prs_cycles >= conv_cycles_) {
        conv_cycles_ = 0;
        const uint8_t ch = ads_ & 0x1Fu;
        const uint16_t raw = channels_[ch] & 0x03FFu;
        adcr_ = static_cast<uint16_t>(raw << 6);  // 10-bit left-aligned (ADCRH = bits 9..2)
        adm0_ &= static_cast<uint8_t>(~0x80u);
        if (intc_) intc_->RaiseIrq(IRQ_AD);
    } else {
        conv_cycles_ -= prs_cycles;
    }
}

// ============================================================================
// Rl78Sau
// ============================================================================

Rl78Sau::Rl78Sau(uint8_t unit, Rl78Intc *intc) : unit_(unit), intc_(intc) {
    Reset();
}

void Rl78Sau::Reset() {
    sdr_.fill(0x0000u);
    ssr_.fill(0x0000u);
    smr_.fill(0x0020u);
    scr_.fill(0x0087u);
    se_ = 0;
    sps_ = 0;
    so_ = 0x0F0Fu;
    soe_ = 0;
    sol_ = 0;
    ssc_ = 0;
    tx_timers_.fill(0);
    for (auto &q : tx_fifos_) q.clear();
    for (auto &q : rx_fifos_) q.clear();
}

bool Rl78Sau::DecodeSdr(uint32_t addr, uint8_t *ch_out, bool *hi_out) const {
    *hi_out = ((addr & 1u) != 0);
    if (unit_ == 0) {
        if (addr >= 0xFFF10u && addr <= 0xFFF13u) { *ch_out = static_cast<uint8_t>((addr - 0xFFF10u) / 2u); return true; }
        if (addr >= 0xFFF44u && addr <= 0xFFF47u) { *ch_out = static_cast<uint8_t>(2u + (addr - 0xFFF44u) / 2u); return true; }
    } else {
        if (addr >= 0xFFF48u && addr <= 0xFFF4Bu) { *ch_out = static_cast<uint8_t>((addr - 0xFFF48u) / 2u); return true; }
        if (addr >= 0xFFF14u && addr <= 0xFFF17u) { *ch_out = static_cast<uint8_t>(2u + (addr - 0xFFF14u) / 2u); return true; }
    }
    return false;
}

bool Rl78Sau::DecodeCtrl(uint32_t addr, uint8_t *kind_out, uint8_t *ch_out, bool *hi_out) const {
    const uint32_t base = (unit_ == 0) ? 0xF0100u : 0xF0140u;
    if (addr < base || addr >= base + 0x40u) return false;
    const uint32_t off = addr - base;
    *hi_out = ((off & 1u) != 0);
    if (off < 0x08u) { *kind_out = 0; *ch_out = static_cast<uint8_t>(off / 2u); return true; }         // SSR
    if (off < 0x10u) { *kind_out = 1; *ch_out = static_cast<uint8_t>((off - 0x08u) / 2u); return true; } // SIR
    if (off < 0x18u) { *kind_out = 2; *ch_out = static_cast<uint8_t>((off - 0x10u) / 2u); return true; } // SMR
    if (off < 0x20u) { *kind_out = 3; *ch_out = static_cast<uint8_t>((off - 0x18u) / 2u); return true; } // SCR
    *ch_out = 0;
    *kind_out = static_cast<uint8_t>(4u + ((off - 0x20u) / 2u));  // 4=SE,5=SS,6=ST,7=SPS,8=SO,9=SOE,14=SOL,16=SSC
    return true;
}

uint8_t Rl78Sau::IrqForChannel(uint8_t ch) const {
    if (unit_ == 0) {
        static constexpr uint8_t kU0[4] = { IRQ_ST0, IRQ_SR0, IRQ_ST1, IRQ_SR1 };
        return kU0[ch & 3u];
    }
    static constexpr uint8_t kU1[4] = { IRQ_ST2, IRQ_SR2, IRQ_ST3, IRQ_SR3 };
    return kU1[ch & 3u];
}

void Rl78Sau::PushRxByte(uint8_t ch, uint8_t byte) {
    if (ch >= 4u) return;
    rx_fifos_[ch].push_back(byte);
    sdr_[ch] = static_cast<uint16_t>((sdr_[ch] & 0xFF00u) | byte);
    ssr_[ch] |= 0x0040u;  // BFF / RX ready
    if (intc_) {
        intc_->RaiseIrq(IrqForChannel(ch));
    }
}

bool Rl78Sau::PopTxByte(uint8_t ch, uint8_t *out) {
    if (ch >= 4u || tx_fifos_[ch].empty()) return false;
    *out = tx_fifos_[ch].front();
    tx_fifos_[ch].pop_front();
    return true;
}

std::vector<uint8_t> Rl78Sau::DrainTx(uint8_t ch) {
    std::vector<uint8_t> out;
    if (ch < 4u) {
        out.assign(tx_fifos_[ch].begin(), tx_fifos_[ch].end());
        tx_fifos_[ch].clear();
    }
    return out;
}

uint8_t Rl78Sau::Read(uint32_t addr) {
    uint8_t ch = 0;
    bool hi = false;
    if (DecodeSdr(addr, &ch, &hi)) {
        const uint8_t val = GetU16Half(sdr_[ch], hi);
        if (!hi && !rx_fifos_[ch].empty()) {
            rx_fifos_[ch].pop_front();
            if (!rx_fifos_[ch].empty()) {
                sdr_[ch] = static_cast<uint16_t>((sdr_[ch] & 0xFF00u) | rx_fifos_[ch].front());
            } else {
                ssr_[ch] &= static_cast<uint16_t>(~0x0040u);
            }
        }
        return val;
    }
    return Peek(addr);
}

void Rl78Sau::Write(uint32_t addr, uint8_t value) {
    uint8_t ch = 0, kind = 0;
    bool hi = false;
    if (DecodeSdr(addr, &ch, &hi)) {
        sdr_[ch] = SetU16Half(sdr_[ch], hi, value);
        if (!hi && (se_ & (1u << ch)) != 0) {
            tx_fifos_[ch].push_back(value);
            ssr_[ch] |= 0x0060u;  // TSF | BFF
            tx_timers_[ch] = 32u;
        }
        return;
    }
    if (DecodeCtrl(addr, &kind, &ch, &hi)) {
        switch (kind) {
        case 1:  // SIR
            if (!hi) ssr_[ch] &= static_cast<uint16_t>(~(value & 0x07u));
            return;
        case 5:  // SS
            if (!hi) se_ |= (value & 0x0Fu);
            return;
        case 6:  // ST
            if (!hi) se_ &= static_cast<uint16_t>(~(value & 0x0Fu));
            return;
        }
    }
    Poke(addr, value);
}

uint8_t Rl78Sau::Peek(uint32_t addr) const {
    uint8_t ch = 0, kind = 0;
    bool hi = false;
    if (DecodeSdr(addr, &ch, &hi)) return GetU16Half(sdr_[ch], hi);
    if (DecodeCtrl(addr, &kind, &ch, &hi)) {
        switch (kind) {
        case 0: return GetU16Half(ssr_[ch], hi);
        case 1: return 0x00u;
        case 2: return GetU16Half(smr_[ch], hi);
        case 3: return GetU16Half(scr_[ch], hi);
        case 4: return GetU16Half(se_, hi);
        case 5: case 6: return 0x00u;
        case 7: return GetU16Half(sps_, hi);
        case 8: return GetU16Half(so_, hi);
        case 9: return GetU16Half(soe_, hi);
        case 14: return GetU16Half(sol_, hi);
        case 16: return GetU16Half(ssc_, hi);
        }
    }
    return 0xFFu;
}

void Rl78Sau::Poke(uint32_t addr, uint8_t value) {
    uint8_t ch = 0, kind = 0;
    bool hi = false;
    if (DecodeSdr(addr, &ch, &hi)) { sdr_[ch] = SetU16Half(sdr_[ch], hi, value); return; }
    if (DecodeCtrl(addr, &kind, &ch, &hi)) {
        switch (kind) {
        case 0: ssr_[ch] = SetU16Half(ssr_[ch], hi, value); break;
        case 2: smr_[ch] = SetU16Half(smr_[ch], hi, value); break;
        case 3: scr_[ch] = SetU16Half(scr_[ch], hi, value); break;
        case 4: se_ = SetU16Half(se_, hi, value); break;
        case 7: sps_ = SetU16Half(sps_, hi, value); break;
        case 8: so_ = SetU16Half(so_, hi, value); break;
        case 9: soe_ = SetU16Half(soe_, hi, value); break;
        case 14: sol_ = SetU16Half(sol_, hi, value); break;
        case 16: ssc_ = SetU16Half(ssc_, hi, value); break;
        default: break;
        }
    }
}

void Rl78Sau::Tick(uint32_t, uint32_t prs_cycles, uint32_t, uint32_t, bool, bool) {
    if (prs_cycles == 0) return;
    for (uint8_t ch = 0; ch < 4u; ++ch) {
        if (tx_timers_[ch] == 0) continue;
        if (prs_cycles >= tx_timers_[ch]) {
            tx_timers_[ch] = 0;
            ssr_[ch] &= static_cast<uint16_t>(~0x0060u);
            if (loopback_ && !tx_fifos_[ch].empty()) {
                const uint8_t peer = static_cast<uint8_t>(ch ^ 1u);
                PushRxByte(peer, tx_fifos_[ch].back());
            }
            if (intc_) intc_->RaiseIrq(IrqForChannel(ch));
        } else {
            tx_timers_[ch] -= prs_cycles;
        }
    }
}

// ============================================================================
// Rl78Iica
// ============================================================================

void Rl78Iica::Reset() {
    iica_ = iics_ = iicf_ = iicctl0_ = iicctl1_ = sva_ = 0;
    iicwl_ = iicwh_ = 0xFFu;
    busy_timer_ = 0;
}

uint8_t Rl78Iica::Read(uint32_t addr) {
    return Peek(addr);
}

void Rl78Iica::Write(uint32_t addr, uint8_t value) {
    Poke(addr, value);
    const uint32_t sfr_base = (unit_ == 0) ? 0xFFF50u : 0xFFF54u;
    const uint32_t ctrl_base = (unit_ == 0) ? 0xF0230u : 0xF0238u;
    if (addr == ctrl_base) {
        if (value & 0x02u) {  // STT start trigger
            iics_ = 0x86u;    // MSTS=1, TRC=1, STD=1
            iicf_ |= 0x01u;   // STCF=1 / IICBSY=1
            busy_timer_ = 16u;
        } else if (value & 0x01u) {  // SPT stop trigger
            iics_ &= static_cast<uint8_t>(~0x80u);
            iics_ |= 0x01u;   // SPD=1
            iicf_ &= static_cast<uint8_t>(~0x01u);
            busy_timer_ = 8u;
        }
    } else if (addr == sfr_base) {
        iics_ |= 0x04u;       // ACKD=1
        busy_timer_ = 16u;
    }
}

uint8_t Rl78Iica::Peek(uint32_t addr) const {
    const uint32_t sfr_base = (unit_ == 0) ? 0xFFF50u : 0xFFF54u;
    const uint32_t ctrl_base = (unit_ == 0) ? 0xF0230u : 0xF0238u;
    if (addr == sfr_base + 0u) return iica_;
    if (addr == sfr_base + 1u) return iics_;
    if (addr == sfr_base + 2u) return iicf_;
    if (addr == ctrl_base + 0u) return iicctl0_;
    if (addr == ctrl_base + 1u) return iicctl1_;
    if (addr == ctrl_base + 2u) return iicwl_;
    if (addr == ctrl_base + 3u) return iicwh_;
    if (addr == ctrl_base + 4u) return sva_;
    return 0xFFu;
}

void Rl78Iica::Poke(uint32_t addr, uint8_t value) {
    const uint32_t sfr_base = (unit_ == 0) ? 0xFFF50u : 0xFFF54u;
    const uint32_t ctrl_base = (unit_ == 0) ? 0xF0230u : 0xF0238u;
    if (addr == sfr_base + 0u) iica_ = value;
    else if (addr == sfr_base + 1u) iics_ = value;
    else if (addr == sfr_base + 2u) iicf_ = value;
    else if (addr == ctrl_base + 0u) iicctl0_ = value;
    else if (addr == ctrl_base + 1u) iicctl1_ = value;
    else if (addr == ctrl_base + 2u) iicwl_ = value;
    else if (addr == ctrl_base + 3u) iicwh_ = value;
    else if (addr == ctrl_base + 4u) sva_ = value;
}

void Rl78Iica::Tick(uint32_t, uint32_t prs_cycles, uint32_t, uint32_t, bool, bool) {
    if (busy_timer_ == 0 || prs_cycles == 0) return;
    if (prs_cycles >= busy_timer_) {
        busy_timer_ = 0;
        if (intc_) intc_->RaiseIrq(irq_num_);
    } else {
        busy_timer_ -= prs_cycles;
    }
}

// ============================================================================
// Rl78MulDiv
// ============================================================================

void Rl78MulDiv::Reset() {
    mdb_hi_ = 0;
    mdb_lo_ = 0;
    mdc_ = 0;
    mduc_ = 0;
    div_timer_ = 0;
}

uint8_t Rl78MulDiv::Read(uint32_t addr) {
    return Peek(addr);
}

void Rl78MulDiv::ExecuteOperation(bool trigger_div) {
    if (!cpu_) return;
    const uint16_t mdal = cpu_->GetMACRL();
    const uint16_t mdah = cpu_->GetMACRH();
    const bool divmode = (mduc_ & 0x80u) != 0;
    const bool macmode = (mduc_ & 0x40u) != 0;
    const bool mdsign = (mduc_ & 0x08u) != 0;

    if (!divmode) {
        int32_t prod = 0;
        if (mdsign) {
            prod = static_cast<int32_t>(static_cast<int16_t>(mdal)) *
                   static_cast<int32_t>(static_cast<int16_t>(mdah));
        } else {
            prod = static_cast<int32_t>(static_cast<uint32_t>(mdal) * static_cast<uint32_t>(mdah));
        }
        const uint32_t uprod = static_cast<uint32_t>(prod);
        mdb_lo_ = static_cast<uint16_t>(uprod & 0xFFFFu);
        mdb_hi_ = static_cast<uint16_t>((uprod >> 16) & 0xFFFFu);
        if (macmode) {
            if (mdsign) {
                const int64_t sum = static_cast<int64_t>(static_cast<int32_t>(mdc_)) + prod;
                mdc_ = static_cast<uint32_t>(static_cast<int32_t>(sum));
                if (sum > 0x7FFFFFFFLL || sum < -0x80000000LL) mduc_ |= 0x04u;
                if (static_cast<int32_t>(mdc_) < 0) mduc_ |= 0x02u;
                else mduc_ &= static_cast<uint8_t>(~0x02u);
            } else {
                const uint64_t sum = static_cast<uint64_t>(mdc_) + uprod;
                mdc_ = static_cast<uint32_t>(sum & 0xFFFFFFFFu);
                if (sum > 0xFFFFFFFFULL) mduc_ |= 0x04u;
            }
        }
    } else if (trigger_div) {
        const uint32_t dividend = (static_cast<uint32_t>(mdah) << 16) | mdal;
        const uint32_t divisor = (static_cast<uint32_t>(mdb_hi_) << 16) | mdb_lo_;
        if (divisor == 0) {
            cpu_->SetMACR(0xFFFFFFFFu);
            mdc_ = dividend;
        } else {
            cpu_->SetMACR(dividend / divisor);
            mdc_ = dividend % divisor;
        }
        div_timer_ = 16u;
    }
}

void Rl78MulDiv::Write(uint32_t addr, uint8_t value) {
    Poke(addr, value);
    if (addr == 0xF00E8u) {
        ExecuteOperation((value & 0x01u) != 0);
    } else if (addr == 0xFFFF3u && (mduc_ & 0x80u) == 0) {
        ExecuteOperation(false);
    }
}

uint8_t Rl78MulDiv::Peek(uint32_t addr) const {
    switch (addr) {
    case 0xFFFF4u: return static_cast<uint8_t>(mdb_hi_ & 0xFFu);
    case 0xFFFF5u: return static_cast<uint8_t>((mdb_hi_ >> 8) & 0xFFu);
    case 0xFFFF6u: return static_cast<uint8_t>(mdb_lo_ & 0xFFu);
    case 0xFFFF7u: return static_cast<uint8_t>((mdb_lo_ >> 8) & 0xFFu);
    case 0xF00E0u: return static_cast<uint8_t>(mdc_ & 0xFFu);
    case 0xF00E1u: return static_cast<uint8_t>((mdc_ >> 8) & 0xFFu);
    case 0xF00E2u: return static_cast<uint8_t>((mdc_ >> 16) & 0xFFu);
    case 0xF00E3u: return static_cast<uint8_t>((mdc_ >> 24) & 0xFFu);
    case 0xF00E8u: return mduc_;
    default: return 0xFFu;
    }
}

void Rl78MulDiv::Poke(uint32_t addr, uint8_t value) {
    switch (addr) {
    case 0xFFFF4u: mdb_hi_ = SetU16Half(mdb_hi_, false, value); break;
    case 0xFFFF5u: mdb_hi_ = SetU16Half(mdb_hi_, true, value); break;
    case 0xFFFF6u: mdb_lo_ = SetU16Half(mdb_lo_, false, value); break;
    case 0xFFFF7u: mdb_lo_ = SetU16Half(mdb_lo_, true, value); break;
    case 0xF00E0u: mdc_ = (mdc_ & 0xFFFFFF00u) | value; break;
    case 0xF00E1u: mdc_ = (mdc_ & 0xFFFF00FFu) | (static_cast<uint32_t>(value) << 8); break;
    case 0xF00E2u: mdc_ = (mdc_ & 0xFF00FFFFu) | (static_cast<uint32_t>(value) << 16); break;
    case 0xF00E3u: mdc_ = (mdc_ & 0x00FFFFFFu) | (static_cast<uint32_t>(value) << 24); break;
    case 0xF00E8u: mduc_ = value; break;
    default: break;
    }
}

void Rl78MulDiv::Tick(uint32_t cpu_cycles, uint32_t, uint32_t, uint32_t, bool, bool) {
    if (div_timer_ == 0 || cpu_cycles == 0) return;
    if (cpu_cycles >= div_timer_) {
        div_timer_ = 0;
        mduc_ &= static_cast<uint8_t>(~0x01u);  // clear DIVST
        if (intc_ && (mduc_ & 0x40u) == 0) {
            intc_->RaiseIrq(IRQ_MD);
        }
    } else {
        div_timer_ -= cpu_cycles;
    }
}

// ============================================================================
// Rl78Dma
// ============================================================================

void Rl78Dma::Reset() {
    dsa_.fill(0);
    dra_.fill(0);
    dbc_.fill(0);
    dmc_.fill(0);
    drc_.fill(0);
}

bool Rl78Dma::DecodeAddr(uint32_t addr, uint8_t *ch_out, uint8_t *reg_out, bool *hi_out) const {
    *hi_out = false;
    if (addr >= 0xFFFB0u && addr <= 0xFFFBDu) {
        const uint32_t off = addr - 0xFFFB0u;
        if (off <= 1u) { *reg_out = 0; *ch_out = static_cast<uint8_t>(off); return true; }                 // DSA0..1
        if (off <= 5u) { *reg_out = 1; *ch_out = static_cast<uint8_t>((off - 2u) / 2u); *hi_out = ((off & 1u) != 0); return true; } // DRA
        if (off <= 9u) { *reg_out = 2; *ch_out = static_cast<uint8_t>((off - 6u) / 2u); *hi_out = ((off & 1u) != 0); return true; } // DBC
        if (off <= 0xBu) { *reg_out = 3; *ch_out = static_cast<uint8_t>(off - 0xAu); return true; }       // DMC
        *reg_out = 4; *ch_out = static_cast<uint8_t>(off - 0xCu); return true;                            // DRC
    }
    if (addr >= 0xF0200u && addr <= 0xF020Du) {
        const uint32_t off = addr - 0xF0200u;
        if (off <= 1u) { *reg_out = 0; *ch_out = static_cast<uint8_t>(2u + off); return true; }
        if (off <= 5u) { *reg_out = 1; *ch_out = static_cast<uint8_t>(2u + (off - 2u) / 2u); *hi_out = ((off & 1u) != 0); return true; }
        if (off <= 9u) { *reg_out = 2; *ch_out = static_cast<uint8_t>(2u + (off - 6u) / 2u); *hi_out = ((off & 1u) != 0); return true; }
        if (off <= 0xBu) { *reg_out = 3; *ch_out = static_cast<uint8_t>(2u + (off - 0xAu)); return true; }
        *reg_out = 4; *ch_out = static_cast<uint8_t>(2u + (off - 0xCu)); return true;
    }
    return false;
}

void Rl78Dma::TriggerTransfer(uint8_t ch) {
    if (ch >= 4u || !bus_ || (drc_[ch] & 0x80u) == 0) return;  // DST=1 required
    const bool is_16bit = (dmc_[ch] & 0x40u) != 0;               // DS=1 (16-bit)
    const bool ram_to_sfr = (dmc_[ch] & 0x20u) != 0;             // DRS=1 (RAM -> SFR)
    const uint32_t sfr_addr = Rl78Bus::ResolveSfr(dsa_[ch]);
    const uint32_t ram_addr = Rl78Bus::ResolveNear(dra_[ch]);
    const uint16_t step = is_16bit ? 2u : 1u;

    if (ram_to_sfr) {
        bus_->WriteCpu(sfr_addr, bus_->ReadCpu(ram_addr));
        if (is_16bit) bus_->WriteCpu(sfr_addr + 1u, bus_->ReadCpu(ram_addr + 1u));
    } else {
        bus_->WriteCpu(ram_addr, bus_->ReadCpu(sfr_addr));
        if (is_16bit) bus_->WriteCpu(ram_addr + 1u, bus_->ReadCpu(sfr_addr + 1u));
    }

    dra_[ch] = static_cast<uint16_t>(dra_[ch] + step);
    if (dbc_[ch] > 0) {
        dbc_[ch] = static_cast<uint16_t>(dbc_[ch] - 1u);
    }
    if (dbc_[ch] == 0) {
        drc_[ch] &= static_cast<uint8_t>(~0x80u);  // clear DST on completion
        if (intc_) {
            static constexpr uint8_t kDmaIrqs[4] = { IRQ_DMA0, IRQ_DMA1, IRQ_DMA2, IRQ_DMA3 };
            intc_->RaiseIrq(kDmaIrqs[ch]);
        }
    }
}

uint8_t Rl78Dma::Read(uint32_t addr) {
    return Peek(addr);
}

void Rl78Dma::Write(uint32_t addr, uint8_t value) {
    uint8_t ch = 0, reg = 0;
    bool hi = false;
    if (!DecodeAddr(addr, &ch, &reg, &hi)) return;
    if (reg == 3 && (value & 0x80u) != 0) {  // STG bit 7
        Poke(addr, value & 0x7Fu);
        TriggerTransfer(ch);
        return;
    }
    Poke(addr, value);
}

uint8_t Rl78Dma::Peek(uint32_t addr) const {
    uint8_t ch = 0, reg = 0;
    bool hi = false;
    if (!DecodeAddr(addr, &ch, &reg, &hi)) return 0xFFu;
    switch (reg) {
    case 0: return dsa_[ch];
    case 1: return GetU16Half(dra_[ch], hi);
    case 2: return GetU16Half(dbc_[ch], hi);
    case 3: return dmc_[ch];
    case 4: return drc_[ch];
    default: return 0xFFu;
    }
}

void Rl78Dma::Poke(uint32_t addr, uint8_t value) {
    uint8_t ch = 0, reg = 0;
    bool hi = false;
    if (!DecodeAddr(addr, &ch, &reg, &hi)) return;
    switch (reg) {
    case 0: dsa_[ch] = value; break;
    case 1: dra_[ch] = SetU16Half(dra_[ch], hi, value); break;
    case 2: dbc_[ch] = SetU16Half(dbc_[ch], hi, value); break;
    case 3: dmc_[ch] = value; break;
    case 4: drc_[ch] = value; break;
    }
}

// ============================================================================
// Rl78FlashCtrl (BECTL, PFCMD, FLPMC, FLRST, FSL ROM & Mailbox)
// ============================================================================

void Rl78FlashCtrl::Reset() {
    bectl_ = 0x00u;
    pfcmd_ = 0x00u;
    flpmc_ = 0x08u;
    flrst_ = 0x00u;
    pfcmd_stage_ = 0;
    pfcmd_target_addr_ = 0;
    pfcmd_pending_val_ = 0;
    pfcmd_error_ = false;
    mailbox_.fill(0x00u);
    SyncBootFlagFromBus();
}

void Rl78FlashCtrl::InstallRomStub() {
    if (!bus_) {
        return;
    }
    const uint32_t flash_end = bus_->CodeFlashEnd();
    uint16_t max_page_word = 0x03FFu;
    if (flash_end >= 256u) {
        const uint32_t pages = (flash_end / 256u) - 1u;
        max_page_word = static_cast<uint16_t>((pages > 0x0EFFu) ? 0x0EFFu : pages);
    }
    bus_->InstallFslRomStub(max_page_word);
}

void Rl78FlashCtrl::SyncBootFlagFromBus() {
    const uint8_t boot_bit = (bus_ && bus_->IsBootSwapped()) ? 0x01u : 0x00u;
    bectl_ = static_cast<uint8_t>((bectl_ & ~0x01u) | boot_bit);
}

uint8_t Rl78FlashCtrl::GetBectl() const {
    const uint8_t boot_bit = (bus_ && bus_->IsBootSwapped()) ? 0x01u : 0x00u;
    return static_cast<uint8_t>((bectl_ & ~0x01u) | boot_bit);
}

uint8_t Rl78FlashCtrl::Read(uint32_t addr) {
    return Peek(addr);
}

uint8_t Rl78FlashCtrl::Peek(uint32_t addr) const {
    addr &= Rl78Bus::kAddressMask;
    if (addr == kBectlAddress) return GetBectl();
    if (addr == kPfcmdAddress) return pfcmd_;
    if (addr == kFlpmcAddress) return flpmc_;
    if (addr == kFlrstAddress) return flrst_;
    if (addr >= kFslMailboxStart && addr <= kFslMailboxEnd) {
        return mailbox_[addr - kFslMailboxStart];
    }
    return 0xFFu;
}

void Rl78FlashCtrl::Write(uint32_t addr, uint8_t value) {
    addr &= Rl78Bus::kAddressMask;
    if (addr == kBectlAddress) {
        const uint8_t boot_bit = (bus_ && bus_->IsBootSwapped()) ? 0x01u : 0x00u;
        bectl_ = static_cast<uint8_t>((value & ~0x01u) | boot_bit);
        return;
    }
    if (addr == kPfcmdAddress) {
        pfcmd_ = value;
        if (value == 0xA5u) {
            pfcmd_stage_ = 1u;
            pfcmd_target_addr_ = 0u;
            pfcmd_pending_val_ = 0u;
        } else {
            pfcmd_stage_ = 0u;
            pfcmd_error_ = true;
        }
        return;
    }
    if (addr == kFlpmcAddress || addr == kFlrstAddress) {
        if (pfcmd_stage_ == 1u) {
            pfcmd_stage_ = 2u;
            pfcmd_target_addr_ = addr;
            pfcmd_pending_val_ = value;
            return;
        }
        if (pfcmd_stage_ == 2u && addr == pfcmd_target_addr_ &&
            value == static_cast<uint8_t>(~pfcmd_pending_val_)) {
            pfcmd_stage_ = 3u;
            return;
        }
        if (pfcmd_stage_ == 3u && addr == pfcmd_target_addr_ &&
            value == pfcmd_pending_val_) {
            if (addr == kFlpmcAddress) {
                flpmc_ = value;
            } else {
                flrst_ = value;
            }
            pfcmd_stage_ = 0u;
            pfcmd_error_ = false;
            return;
        }
        pfcmd_stage_ = 0u;
        pfcmd_error_ = true;
        return;
    }
    if (addr >= kFslMailboxStart && addr <= kFslMailboxEnd) {
        mailbox_[addr - kFslMailboxStart] = value;
    }
}

void Rl78FlashCtrl::Poke(uint32_t addr, uint8_t value) {
    addr &= Rl78Bus::kAddressMask;
    if (addr == kBectlAddress) {
        const uint8_t boot_bit = (bus_ && bus_->IsBootSwapped()) ? 0x01u : 0x00u;
        bectl_ = static_cast<uint8_t>((value & ~0x01u) | boot_bit);
    } else if (addr == kPfcmdAddress) {
        pfcmd_ = value;
    } else if (addr == kFlpmcAddress) {
        flpmc_ = value;
    } else if (addr == kFlrstAddress) {
        flrst_ = value;
    } else if (addr >= kFslMailboxStart && addr <= kFslMailboxEnd) {
        mailbox_[addr - kFslMailboxStart] = value;
    }
}

uint32_t Rl78FlashCtrl::DecodeBlockIndex() const {
    uint32_t block = mailbox_[3];
    // SK0RT02N200GV120 temporarily swaps block_hi (0..3) into mailbox_[4] before call
    if (mailbox_[4] <= 3u) {
        block |= (static_cast<uint32_t>(mailbox_[4]) << 8u);
    }
    return block;
}

uint8_t Rl78FlashCtrl::HandleFslCommand(uint8_t cmd) {
    if (!bus_) {
        return kFslErrParameter;
    }
    switch (cmd) {
    case 0x00u:  // FSL_Init
        return kFslOk;

    case 0x08u: {  // FSL_BlankCheck
        const uint32_t block = DecodeBlockIndex();
        const uint32_t max_blocks = bus_->CodeFlashEnd() / Rl78Bus::kFlashBlockSize;
        if (block >= max_blocks) {
            return kFslErrParameter;
        }
        return bus_->BlankCheckFlashBlock(block) ? kFslOk : kFslErrBlankCheck;
    }

    case 0x03u: {  // FSL_Erase
        if (!flmd0_high_) {
            return kFslErrProtection;
        }
        const uint32_t block = DecodeBlockIndex();
        if (!bus_->EraseFlashBlock(block)) {
            return kFslErrParameter;
        }
        ++erased_blocks_;
        return kFslOk;
    }

    case 0x04u:
    case 0x17u: {  // FSL_Write
        if (!flmd0_high_) {
            return kFslErrProtection;
        }
        const uint32_t flash_addr =
            (static_cast<uint32_t>(mailbox_[0]) |
             (static_cast<uint32_t>(mailbox_[1]) << 8u) |
             (static_cast<uint32_t>(mailbox_[2]) << 16u)) &
            Rl78Bus::kAddressMask;
        const uint32_t word_count = mailbox_[3];
        if (word_count == 0 || word_count > 0x40u || (flash_addr & 3u) != 0) {
            return kFslErrParameter;
        }
        const size_t byte_count = static_cast<size_t>(word_count) * 4u;
        const uint16_t src_near16 =
            static_cast<uint16_t>(mailbox_[4] | (static_cast<uint16_t>(mailbox_[5]) << 8u));
        std::array<uint8_t, 256> buf{};
        for (size_t i = 0; i < byte_count; ++i) {
            const uint32_t src_addr = Rl78Bus::kNearBase | ((src_near16 + i) & 0xFFFFu);
            buf[i] = bus_->PeekByte(src_addr);
        }
        if (!bus_->ProgramFlashBytes(flash_addr, buf.data(), byte_count)) {
            return kFslErrParameter;
        }
        programmed_bytes_ += static_cast<uint32_t>(byte_count);
        return kFslOk;
    }

    case 0x06u: {  // FSL_IVerify
        const uint32_t block = DecodeBlockIndex();
        const uint32_t max_blocks = bus_->CodeFlashEnd() / Rl78Bus::kFlashBlockSize;
        return (block < max_blocks) ? kFslOk : kFslErrParameter;
    }

    case 0x09u: {  // FSL_GetBootFlag / security status
        const uint16_t dst_near16 =
            static_cast<uint16_t>(mailbox_[4] | (static_cast<uint16_t>(mailbox_[5]) << 8u));
        const uint8_t boot_flag = bus_->IsBootSwapped() ? 1u : 0u;
        if (dst_near16 != 0u) {
            const uint32_t dst_addr = Rl78Bus::kNearBase | dst_near16;
            if (dst_addr >= bus_->RamStart() && dst_addr <= Rl78Bus::kHighSpeedRamEnd) {
                bus_->PokeByte(dst_addr, boot_flag);
            }
        }
        return kFslOk;
    }

    case 0x0Au:  // FSL_InvertBootFlag
        if (!flmd0_high_) {
            return kFslErrProtection;
        }
        bus_->SwapBootClusters();
        SyncBootFlagFromBus();
        return kFslOk;

    default:
        return kFslErrParameter;
    }
}

void Rl78FlashCtrl::ExecuteFslEntry() {
    if (!bus_) {
        return;
    }
    const uint8_t cmd = bus_->PeekByte(0xFFEE2u);  // RB3.C
    const uint8_t status = HandleFslCommand(cmd);
    last_fsl_cmd_ = cmd;
    last_fsl_status_ = status;
    ++fsl_call_count_;
    bus_->PokeByte(0xFFEE3u, status);  // RB3.B
}

}  // namespace rl78
