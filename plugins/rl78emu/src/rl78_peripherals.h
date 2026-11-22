#pragma once

#include <array>
#include <cstdint>
#include <deque>
#include <string>
#include <vector>

#include "cpu.h"
#include "memory.h"

namespace rl78 {

// ============================================================================
// Interrupt Controller (RL78/G13: IF0..IF3L, MK0..MK3L, PR00..PR03L, PR10..PR13L)
// ============================================================================

enum Rl78IrqIndex : uint8_t {
    IRQ_WDTI = 0,
    IRQ_LVI,
    IRQ_P0, IRQ_P1, IRQ_P2, IRQ_P3, IRQ_P4, IRQ_P5,
    IRQ_ST2, IRQ_SR2, IRQ_SRE2,
    IRQ_DMA0, IRQ_DMA1,
    IRQ_ST0, IRQ_SR0, IRQ_SRE0,
    IRQ_ST1, IRQ_SR1, IRQ_SRE1,
    IRQ_IICA0,
    IRQ_TM00, IRQ_TM01, IRQ_TM02, IRQ_TM03,
    IRQ_AD, IRQ_RTC, IRQ_IT, IRQ_KR,
    IRQ_ST3, IRQ_SR3,
    IRQ_TM13, IRQ_TM04, IRQ_TM05, IRQ_TM06, IRQ_TM07,
    IRQ_P6, IRQ_P7, IRQ_P8, IRQ_P9, IRQ_P10, IRQ_P11,
    IRQ_TM10, IRQ_TM11, IRQ_TM12, IRQ_SRE3,
    IRQ_MD, IRQ_IICA1, IRQ_FL,
    IRQ_DMA2, IRQ_DMA3,
    IRQ_TM14, IRQ_TM15, IRQ_TM16, IRQ_TM17,
    IRQ_COUNT
};

struct IrqSourceDef {
    uint8_t index;
    uint8_t reg_slot;   // 0=0L, 1=0H, 2=1L, 3=1H, 4=2L, 5=2H, 6=3L
    uint8_t bit_mask;
    uint16_t vector_addr;
    const char *name;
};

class Rl78Intc final : public InterruptControllerBase {
public:
    Rl78Intc();

    uint8_t Read(uint32_t addr) override;
    void Write(uint32_t addr, uint8_t value) override;
    uint8_t Peek(uint32_t addr) const override;
    void Poke(uint32_t addr, uint8_t value) override;
    void Reset() override;

    PendingInterrupt EvaluatePending() const override;
    bool HasUnmaskedPending() const override;
    void Acknowledge(uint8_t source_index) override;

    void RaiseIrq(uint8_t source_index);
    void ClearIrq(uint8_t source_index);
    int FindIrqByName(const char *name) const;
    const std::vector<IrqSourceDef> &Sources() const { return sources_; }

    uint8_t GetIfReg(uint8_t slot) const { return (slot < 7u) ? if_regs_[slot] : 0; }
    uint8_t GetMkReg(uint8_t slot) const { return (slot < 7u) ? mk_regs_[slot] : 0xFFu; }
    uint8_t GetPr0Reg(uint8_t slot) const { return (slot < 7u) ? pr0_regs_[slot] : 0xFFu; }
    uint8_t GetPr1Reg(uint8_t slot) const { return (slot < 7u) ? pr1_regs_[slot] : 0xFFu; }

private:
    static bool DecodeRegAddr(uint32_t addr, uint8_t *bank_out, uint8_t *slot_out);

    std::vector<IrqSourceDef> sources_;
    std::array<uint8_t, 7> if_regs_{};
    std::array<uint8_t, 7> mk_regs_{};
    std::array<uint8_t, 7> pr0_regs_{};
    std::array<uint8_t, 7> pr1_regs_{};
};

// ============================================================================
// Clock Generator & System Control (CMC..OSMC, DFLCTL, RESF, LVI, CRCIN, BCDADJ)
// ============================================================================

class Rl78Clock final : public PeripheralDevice, public Rl78ClockSource {
public:
    explicit Rl78Clock(Rl78Bus *bus) : bus_(bus) {}

    uint8_t Read(uint32_t addr) override;
    void Write(uint32_t addr, uint8_t value) override;
    uint8_t Peek(uint32_t addr) const override;
    void Poke(uint32_t addr, uint8_t value) override;
    void Reset() override;
    void Tick(uint32_t cpu_cycles, uint32_t prs_cycles, uint32_t sub_cycles,
              uint32_t il_cycles, bool in_halt, bool in_stop) override;

    void OnEnterStop() override;
    void OnExitStop() override;
    void ComputeSubClocks(uint32_t cpu_cycles,
                          bool in_halt,
                          bool in_stop,
                          uint32_t *prs_cycles_out,
                          uint32_t *sub_cycles_out,
                          uint32_t *il_cycles_out) override;

    static constexpr uint8_t RESF_IAWRF = 0x80u;

    void SetResetFlag(uint8_t mask) { resf_ |= mask; }
    void LatchResetCause(uint8_t mask) override { resf_ |= mask; }
    void ClearResetFlags() { resf_ = 0; }

    uint8_t GetCmc() const { return cmc_; }
    uint8_t GetCsc() const { return csc_; }
    uint8_t GetOstc() const { return ostc_; }
    uint8_t GetOsts() const { return osts_; }
    uint8_t GetCkc() const;
    uint8_t GetPer0() const { return per0_; }
    uint8_t GetOsmc() const { return osmc_; }
    uint8_t GetResf() const { return resf_; }
    uint8_t GetLvim() const { return lvim_; }
    uint8_t GetLvis() const { return lvis_; }
    uint8_t GetDflctl() const { return dflctl_; }

    bool IsHocoStopped() const { return (csc_ & 0x01u) != 0; }
    bool IsSubStopped() const { return (csc_ & 0x40u) != 0; }
    bool IsMainStopped() const { return (csc_ & 0x80u) != 0; }
    bool IsSubClockSelected() const { return (ckc_ & 0x40u) != 0; }

private:
    void UpdateOstc();

    Rl78Bus *bus_ = nullptr;
    uint8_t cmc_ = 0x00u;
    uint8_t csc_ = 0xC0u;
    uint8_t ostc_ = 0x00u;
    uint8_t osts_ = 0x07u;
    uint8_t ckc_ = 0x00u;
    uint8_t cks0_ = 0x00u;
    uint8_t cks1_ = 0x00u;
    uint8_t resf_ = 0x00u;
    uint8_t lvim_ = 0x00u;
    uint8_t lvis_ = 0x00u;
    uint8_t crcin_ = 0x00u;
    uint8_t dflctl_ = 0x00u;
    uint8_t hiotrm_ = 0x20u;
    uint8_t hocodiv_ = 0x00u;
    uint8_t per0_ = 0x00u;
    uint8_t osmc_ = 0x00u;
    uint8_t rmc_ = 0x00u;
    uint8_t rpectl_ = 0x00u;
    uint8_t iawctl_ = 0x00u;
    uint8_t gdidis_ = 0x00u;

    uint32_t sub_acc_ = 0;
    uint32_t il_acc_ = 0;
    uint32_t ostc_timer_ = 0;
};

// ============================================================================
// Watchdog Timer (0xFFFAB WDTE + Option Byte 0x000C0)
// ============================================================================

class Rl78Wdt final : public PeripheralDevice {
public:
    Rl78Wdt(Rl78Bus *bus, Rl78Cpu *cpu, Rl78Clock *clk, Rl78Intc *intc)
        : bus_(bus), cpu_(cpu), clk_(clk), intc_(intc) {}

    uint8_t Read(uint32_t addr) override;
    void Write(uint32_t addr, uint8_t value) override;
    uint8_t Peek(uint32_t addr) const override;
    void Poke(uint32_t addr, uint8_t value) override;
    void Reset() override;
    void Tick(uint32_t cpu_cycles, uint32_t prs_cycles, uint32_t sub_cycles,
              uint32_t il_cycles, bool in_halt, bool in_stop) override;

    bool IsEnabled() const { return wdton_; }
    uint32_t GetCounter() const { return counter_; }
    uint32_t GetOverflowPeriod() const { return overflow_period_; }
    uint8_t GetOptionByte() const { return option_byte_; }
    bool halt_on_reset = true;

private:
    void TriggerReset();

    Rl78Bus *bus_ = nullptr;
    Rl78Cpu *cpu_ = nullptr;
    Rl78Clock *clk_ = nullptr;
    Rl78Intc *intc_ = nullptr;

    uint8_t option_byte_ = 0x00u;
    bool wdton_ = false;
    bool halt_run_ = false;
    uint8_t wdcs_ = 7u;
    uint8_t window_ = 3u;
    bool wdtint_ = false;
    bool int_fired_ = false;
    uint32_t counter_ = 0;
    uint32_t overflow_period_ = (1u << 16);
};

// ============================================================================
// GPIO Ports & Edge/Key Interrupts (P0..P15, PM*, PU*, PIM*, POM*, PMC*, EGP/EGN/KRM)
// ============================================================================

class Rl78Ports final : public PeripheralDevice {
public:
    explicit Rl78Ports(Rl78Intc *intc) : intc_(intc) {}

    uint8_t Read(uint32_t addr) override;
    void Write(uint32_t addr, uint8_t value) override;
    uint8_t Peek(uint32_t addr) const override;
    void Poke(uint32_t addr, uint8_t value) override;
    void Reset() override;

    void SetExternalInput(uint8_t port, uint8_t pin, bool high);
    void SetExternalPortByte(uint8_t port, uint8_t value);
    uint8_t GetPinState(uint8_t port) const;
    uint8_t GetLatch(uint8_t port) const { return (port < 16u) ? latch_[port] : 0; }
    uint8_t GetMode(uint8_t port) const { return (port < 16u) ? mode_[port] : 0xFFu; }
    uint8_t GetExternalInput(uint8_t port) const { return (port < 16u) ? ext_in_[port] : 0xFFu; }

private:
    void CheckEdgeIntp(uint8_t port, uint8_t pin, bool old_high, bool new_high);

    Rl78Intc *intc_ = nullptr;
    std::array<uint8_t, 16> latch_{};
    std::array<uint8_t, 16> mode_{};
    std::array<uint8_t, 16> pullup_{};
    std::array<uint8_t, 16> pim_{};
    std::array<uint8_t, 16> pom_{};
    std::array<uint8_t, 16> pmc_{};
    std::array<uint8_t, 16> ext_in_{};
    uint8_t nfen0_ = 0;
    uint8_t nfen1_ = 0;
    uint8_t nfen2_ = 0;
    uint8_t isc_ = 0;
    uint8_t tis0_ = 0;
    uint8_t adpc_ = 0;
    uint8_t pior_ = 0;
    uint8_t krm_ = 0;
    uint8_t egp0_ = 0;
    uint8_t egn0_ = 0;
    uint8_t egp1_ = 0;
    uint8_t egn1_ = 0;
};

// ============================================================================
// Timer Array Unit (TAU0 8-ch / TAU1 4-ch or 8-ch: 16-bit Channels)
// ============================================================================

class Rl78Tau final : public PeripheralDevice {
public:
    Rl78Tau(uint8_t unit_idx, Rl78Intc *intc,
            const std::array<uint8_t, 8> &irq_nums,
            uint8_t num_channels = 8u);

    uint8_t Read(uint32_t addr) override;
    void Write(uint32_t addr, uint8_t value) override;
    uint8_t Peek(uint32_t addr) const override;
    void Poke(uint32_t addr, uint8_t value) override;
    void Reset() override;
    void Tick(uint32_t cpu_cycles, uint32_t prs_cycles, uint32_t sub_cycles,
              uint32_t il_cycles, bool in_halt, bool in_stop) override;

    uint8_t NumChannels() const { return num_channels_; }
    uint16_t GetCounter(uint8_t ch) const { return (ch < num_channels_) ? tcr_[ch] : 0; }
    uint16_t GetData(uint8_t ch) const { return (ch < num_channels_) ? tdr_[ch] : 0; }
    uint16_t GetMode(uint8_t ch) const { return (ch < num_channels_) ? tmr_[ch] : 0; }
    uint16_t GetEnableMask() const { return te_; }
    uint16_t GetTps() const { return tps_; }

private:
    enum class RegKind : uint8_t {
        Invalid = 0,
        Tdr,
        Tcr,
        Tmr,
        Tsr,
        Te,
        Ts,
        Tt,
        Tps,
        To,
        Toe,
        Tol,
        Tom,
    };

    bool DecodeAddr(uint32_t addr, RegKind *kind_out, uint8_t *ch_out, bool *hi_out) const;
    uint32_t ChannelDivisor(uint8_t ch) const;

    uint8_t unit_ = 0;
    uint8_t num_channels_ = 8u;
    Rl78Intc *intc_ = nullptr;
    std::array<uint8_t, 8> irq_nums_{};

    std::array<uint16_t, 8> tcr_{};
    std::array<uint16_t, 8> tdr_{};
    std::array<uint16_t, 8> tmr_{};
    std::array<uint16_t, 8> tsr_{};
    std::array<uint32_t, 8> acc_{};
    uint16_t te_ = 0;
    uint16_t tps_ = 0;
    uint16_t to_ = 0;
    uint16_t toe_ = 0;
    uint16_t tol_ = 0;
    uint16_t tom_ = 0;
};

// ============================================================================
// 12-bit Interval Timer & Real-Time Clock (ITMC 0xFFF90..0xFFF91, RTC 0xFFF92..0xFFF9E)
// ============================================================================

class Rl78RtcIt final : public PeripheralDevice {
public:
    explicit Rl78RtcIt(Rl78Intc *intc) : intc_(intc) {}

    uint8_t Read(uint32_t addr) override;
    void Write(uint32_t addr, uint8_t value) override;
    uint8_t Peek(uint32_t addr) const override;
    void Poke(uint32_t addr, uint8_t value) override;
    void Reset() override;
    void Tick(uint32_t cpu_cycles, uint32_t prs_cycles, uint32_t sub_cycles,
              uint32_t il_cycles, bool in_halt, bool in_stop) override;

    uint16_t GetItmc() const { return itmc_; }
    uint16_t GetItCounter() const { return it_counter_; }

private:
    static uint8_t IncBcd(uint8_t bcd);

    Rl78Intc *intc_ = nullptr;
    uint16_t itmc_ = 0x0FFFu;
    uint16_t it_counter_ = 0;
    uint32_t it_sub_acc_ = 0;

    std::array<uint8_t, 13> rtc_regs_{};  // 0xFFF92..0xFFF9E (SEC..RTCC1)
    uint32_t rtc_sub_acc_ = 0;
};

// ============================================================================
// 10-bit SAR A/D Converter (ADM0..2, ADS, ADUL, ADLL, ADTES, ADCR)
// ============================================================================

class Rl78Adc final : public PeripheralDevice {
public:
    explicit Rl78Adc(Rl78Intc *intc) : intc_(intc) {}

    uint8_t Read(uint32_t addr) override;
    void Write(uint32_t addr, uint8_t value) override;
    uint8_t Peek(uint32_t addr) const override;
    void Poke(uint32_t addr, uint8_t value) override;
    void Reset() override;
    void Tick(uint32_t cpu_cycles, uint32_t prs_cycles, uint32_t sub_cycles,
              uint32_t il_cycles, bool in_halt, bool in_stop) override;

    void SetChannelVoltage(uint8_t ch, uint16_t val_10bit) {
        if (ch < channels_.size()) {
            channels_[ch] = static_cast<uint16_t>(val_10bit & 0x03FFu);
        }
    }
    uint16_t GetChannelVoltage(uint8_t ch) const {
        return (ch < channels_.size()) ? channels_[ch] : 0;
    }
    uint16_t GetAdcr() const { return adcr_; }
    uint8_t GetAdm0() const { return adm0_; }
    uint8_t GetAds() const { return ads_; }

private:
    Rl78Intc *intc_ = nullptr;
    uint8_t adm0_ = 0;
    uint8_t ads_ = 0;
    uint8_t adm1_ = 0;
    uint8_t adm2_ = 0;
    uint8_t adul_ = 0xFFu;
    uint8_t adll_ = 0x00u;
    uint8_t adtes_ = 0x00u;
    uint16_t adcr_ = 0;
    uint32_t conv_cycles_ = 0;
    std::array<uint16_t, 32> channels_{};
};

// ============================================================================
// Serial Array Unit (SAU0 & SAU1) + IICA0/1
// ============================================================================

class Rl78Sau final : public PeripheralDevice {
public:
    Rl78Sau(uint8_t unit, Rl78Intc *intc);

    uint8_t Read(uint32_t addr) override;
    void Write(uint32_t addr, uint8_t value) override;
    uint8_t Peek(uint32_t addr) const override;
    void Poke(uint32_t addr, uint8_t value) override;
    void Reset() override;
    void Tick(uint32_t cpu_cycles, uint32_t prs_cycles, uint32_t sub_cycles,
              uint32_t il_cycles, bool in_halt, bool in_stop) override;

    void PushRxByte(uint8_t ch, uint8_t byte);
    bool PopTxByte(uint8_t ch, uint8_t *out);
    std::vector<uint8_t> DrainTx(uint8_t ch);
    void SetLoopback(bool en) { loopback_ = en; }
    bool IsLoopback() const { return loopback_; }

    uint16_t GetSdr(uint8_t ch) const { return (ch < 4u) ? sdr_[ch] : 0; }
    uint16_t GetSe() const { return se_; }
    uint16_t GetSsr(uint8_t ch) const { return (ch < 4u) ? ssr_[ch] : 0; }

private:
    bool DecodeSdr(uint32_t addr, uint8_t *ch_out, bool *hi_out) const;
    bool DecodeCtrl(uint32_t addr, uint8_t *kind_out, uint8_t *ch_out, bool *hi_out) const;
    uint8_t IrqForChannel(uint8_t ch) const;

    uint8_t unit_ = 0;
    Rl78Intc *intc_ = nullptr;
    bool loopback_ = false;

    std::array<uint16_t, 4> sdr_{};
    std::array<uint16_t, 4> ssr_{};
    std::array<uint16_t, 4> smr_{};
    std::array<uint16_t, 4> scr_{};
    uint16_t se_ = 0;
    uint16_t sps_ = 0;
    uint16_t so_ = 0x0F0Fu;
    uint16_t soe_ = 0;
    uint16_t sol_ = 0;
    uint16_t ssc_ = 0;

    std::array<uint32_t, 4> tx_timers_{};
    std::array<std::deque<uint8_t>, 4> tx_fifos_;
    std::array<std::deque<uint8_t>, 4> rx_fifos_;
};

class Rl78Iica final : public PeripheralDevice {
public:
    Rl78Iica(uint8_t unit, Rl78Intc *intc, uint8_t irq_num)
        : unit_(unit), intc_(intc), irq_num_(irq_num) {}

    uint8_t Read(uint32_t addr) override;
    void Write(uint32_t addr, uint8_t value) override;
    uint8_t Peek(uint32_t addr) const override;
    void Poke(uint32_t addr, uint8_t value) override;
    void Reset() override;
    void Tick(uint32_t cpu_cycles, uint32_t prs_cycles, uint32_t sub_cycles,
              uint32_t il_cycles, bool in_halt, bool in_stop) override;

private:
    uint8_t unit_ = 0;
    Rl78Intc *intc_ = nullptr;
    uint8_t irq_num_ = 0;

    uint8_t iica_ = 0;
    uint8_t iics_ = 0;
    uint8_t iicf_ = 0;
    uint8_t iicctl0_ = 0;
    uint8_t iicctl1_ = 0;
    uint8_t iicwl_ = 0xFFu;
    uint8_t iicwh_ = 0xFFu;
    uint8_t sva_ = 0;
    uint32_t busy_timer_ = 0;
};

// ============================================================================
// G13 Hardware Multiplier / Divider SFRs (MDBH/MDBL, MDCL/MDCH, MDUC; shares MDAL/MDAH)
// ============================================================================

class Rl78MulDiv final : public PeripheralDevice {
public:
    Rl78MulDiv(Rl78Cpu *cpu, Rl78Intc *intc) : cpu_(cpu), intc_(intc) {}

    uint8_t Read(uint32_t addr) override;
    void Write(uint32_t addr, uint8_t value) override;
    uint8_t Peek(uint32_t addr) const override;
    void Poke(uint32_t addr, uint8_t value) override;
    void Reset() override;
    void Tick(uint32_t cpu_cycles, uint32_t prs_cycles, uint32_t sub_cycles,
              uint32_t il_cycles, bool in_halt, bool in_stop) override;

private:
    void ExecuteOperation(bool trigger_div);

    Rl78Cpu *cpu_ = nullptr;
    Rl78Intc *intc_ = nullptr;
    uint16_t mdb_hi_ = 0;  // MDBH @ 0xFFFF4
    uint16_t mdb_lo_ = 0;  // MDBL @ 0xFFFF6
    uint32_t mdc_ = 0;     // MDCL/MDCH @ 0xF00E0..0xF00E3
    uint8_t mduc_ = 0;     // MDUC @ 0xF00E8
    uint32_t div_timer_ = 0;
};

// ============================================================================
// DMA Controller (Channels 0..3)
// ============================================================================

class Rl78Dma final : public PeripheralDevice {
public:
    Rl78Dma(Rl78Bus *bus, Rl78Intc *intc) : bus_(bus), intc_(intc) {}

    uint8_t Read(uint32_t addr) override;
    void Write(uint32_t addr, uint8_t value) override;
    uint8_t Peek(uint32_t addr) const override;
    void Poke(uint32_t addr, uint8_t value) override;
    void Reset() override;

    void TriggerTransfer(uint8_t ch);

private:
    bool DecodeAddr(uint32_t addr, uint8_t *ch_out, uint8_t *reg_out, bool *hi_out) const;

    Rl78Bus *bus_ = nullptr;
    Rl78Intc *intc_ = nullptr;
    std::array<uint8_t, 4> dsa_{};
    std::array<uint16_t, 4> dra_{};
    std::array<uint16_t, 4> dbc_{};
    std::array<uint8_t, 4> dmc_{};
    std::array<uint8_t, 4> drc_{};
};

// ============================================================================
// Flash Self-Programming Controller (BECTL, PFCMD, FLPMC, FLRST, FSL ROM/Mailbox)
// ============================================================================

class Rl78FlashCtrl final : public FlashControllerBase {
public:
    static constexpr uint32_t kBectlAddress       = 0xFFFBEu;
    static constexpr uint32_t kPfcmdAddress       = 0xFFFC0u;
    static constexpr uint32_t kFlpmcAddress       = 0xFFFC4u;
    static constexpr uint32_t kFlrstAddress       = 0xF00C0u;
    static constexpr uint32_t kFslMailboxStart    = 0xF0800u;
    static constexpr uint32_t kFslMailboxEnd      = 0xF080Fu;
    static constexpr uint32_t kFslSizeInfoAddress = 0x0EFFD0u;
    static constexpr uint32_t kFslRomEntryAddress = 0x0EFFF8u;

    static constexpr uint8_t kFslOk            = 0x00u;
    static constexpr uint8_t kFslErrParameter  = 0x05u;
    static constexpr uint8_t kFslErrProtection = 0x10u;
    static constexpr uint8_t kFslErrVerify     = 0x1Au;
    static constexpr uint8_t kFslErrBlankCheck = 0x1Bu;

    explicit Rl78FlashCtrl(Rl78Bus *bus) : bus_(bus) {}

    uint8_t Read(uint32_t addr) override;
    void Write(uint32_t addr, uint8_t value) override;
    uint8_t Peek(uint32_t addr) const override;
    void Poke(uint32_t addr, uint8_t value) override;
    void Reset() override;

    uint32_t RomEntryAddress() const override { return kFslRomEntryAddress; }
    void ExecuteFslEntry() override;

    void InstallRomStub();
    void SyncBootFlagFromBus();
    void SetFlmd0High(bool high) { flmd0_high_ = high; }
    bool IsFlmd0High() const { return flmd0_high_; }

    uint8_t GetBectl() const;
    uint8_t GetPfcmd() const { return pfcmd_; }
    uint8_t GetFlpmc() const { return flpmc_; }
    uint8_t GetFlrst() const { return flrst_; }
    uint8_t GetMailboxByte(size_t idx) const { return (idx < mailbox_.size()) ? mailbox_[idx] : 0xFFu; }
    uint8_t LastFslCmd() const { return last_fsl_cmd_; }
    uint8_t LastFslStatus() const { return last_fsl_status_; }
    uint32_t ErasedBlocks() const { return erased_blocks_; }
    uint32_t ProgrammedBytes() const { return programmed_bytes_; }
    uint32_t FslCallCount() const { return fsl_call_count_; }

private:
    uint8_t HandleFslCommand(uint8_t cmd);
    uint32_t DecodeBlockIndex() const;

    Rl78Bus *bus_ = nullptr;
    uint8_t bectl_ = 0x00u;
    uint8_t pfcmd_ = 0x00u;
    uint8_t flpmc_ = 0x08u;
    uint8_t flrst_ = 0x00u;
    bool flmd0_high_ = true;

    uint8_t pfcmd_stage_ = 0;
    uint32_t pfcmd_target_addr_ = 0;
    uint8_t pfcmd_pending_val_ = 0;
    bool pfcmd_error_ = false;

    std::array<uint8_t, 16> mailbox_{};
    uint8_t last_fsl_cmd_ = 0;
    uint8_t last_fsl_status_ = 0;
    uint32_t erased_blocks_ = 0;
    uint32_t programmed_bytes_ = 0;
    uint32_t fsl_call_count_ = 0;
};

}  // namespace rl78
