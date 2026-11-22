#include "machine.h"

#include <cctype>
#include <cstdio>
#include <cstdlib>
#include <sstream>

namespace rl78 {

namespace {

std::string Trim(const std::string &s) {
    size_t start = 0;
    while (start < s.size() && std::isspace(static_cast<unsigned char>(s[start]))) ++start;
    size_t end = s.size();
    while (end > start && std::isspace(static_cast<unsigned char>(s[end - 1]))) --end;
    return s.substr(start, end - start);
}

std::vector<std::string> SplitArgs(const std::string &s) {
    std::vector<std::string> out;
    std::istringstream iss(s);
    std::string tok;
    while (iss >> tok) {
        out.push_back(tok);
    }
    return out;
}

const char *RunStateName(RunState st) {
    switch (st) {
    case RunState::Running: return "RUNNING";
    case RunState::Halted:  return "HALTED";
    case RunState::Stopped: return "STOPPED";
    }
    return "?";
}

const char *CoreName(CoreProfile core) {
    switch (core) {
    case CoreProfile::S1: return "RL78-S1";
    case CoreProfile::S2: return "RL78-S2";
    case CoreProfile::S3: return "RL78-S3";
    }
    return "?";
}

bool EqIgnoreCase(const char *a, const char *b) {
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

bool ReadBinaryFile(const char *path, std::vector<uint8_t> *out) {
    if (!path || !*path || !out) return false;
    std::FILE *fp = std::fopen(path, "rb");
    if (!fp) return false;
    std::fseek(fp, 0, SEEK_END);
    const long fsz = std::ftell(fp);
    std::fseek(fp, 0, SEEK_SET);
    if (fsz < 0) {
        std::fclose(fp);
        return false;
    }
    out->resize(static_cast<size_t>(fsz));
    if (fsz > 0) {
        if (std::fread(out->data(), 1, out->size(), fp) != out->size()) {
            std::fclose(fp);
            out->clear();
            return false;
        }
    }
    std::fclose(fp);
    return true;
}

}  // namespace

Rl78Machine::Rl78Machine()
    : clock(&bus),
      wdt(&bus, &cpu, &clock, &intc),
      ports(&intc),
      tau0(0, &intc, { IRQ_TM00, IRQ_TM01, IRQ_TM02, IRQ_TM03, IRQ_TM04, IRQ_TM05, IRQ_TM06, IRQ_TM07 }, 8u),
      tau1(1, &intc, { IRQ_TM10, IRQ_TM11, IRQ_TM12, IRQ_TM13, 0xFFu, 0xFFu, 0xFFu, 0xFFu }, 4u),
      rtc_it(&intc),
      adc(&intc),
      sau0(0, &intc),
      sau1(1, &intc),
      iica0(0, &intc, IRQ_IICA0),
      iica1(1, &intc, IRQ_IICA1),
      muldiv(&cpu, &intc),
      dma(&bus, &intc),
      flash(&bus) {
    Configure(CoreProfile::S3, 0x080000u, 0x002000u, Rl78Bus::kDefaultRamStart);
}

void Rl78Machine::Configure(CoreProfile core,
                            uint32_t code_flash_end,
                            uint32_t data_flash_size,
                            uint32_t ram_start) {
    core_ = core;
    bus.ClearAllDevices();
    bus.ConfigureLayout(core, code_flash_end, data_flash_size, ram_start);
    WirePeripherals();
}

void Rl78Machine::WirePeripherals() {
    cpu.AttachBus(&bus);  // maps MACRL/H, SP, PSW, CS, ES, PMC, MEM
    cpu.AttachIntc(&intc);
    cpu.AttachClock(&clock);
    cpu.AttachFlash(&flash);

    // INTC
    bus.MapSfrRange(0xFFFD0u, 0xFFFDFu, &intc);
    bus.MapSfrRange(0xFFFE0u, 0xFFFEFu, &intc);

    // Clock & System
    bus.MapSfrRange(0xFFFA0u, 0xFFFAAu, &clock);
    bus.MapSfr(0xFFFACu, &clock);
    bus.MapSfr(0xF0078u, &clock);
    bus.MapSfr(0xF007Du, &clock);
    bus.MapSfr(0xF0090u, &clock);
    bus.MapSfr(0xF00A0u, &clock);
    bus.MapSfr(0xF00A8u, &clock);
    bus.MapSfr(0xF00F0u, &clock);
    bus.MapSfrRange(0xF00F3u, 0xF00F5u, &clock);
    bus.MapSfr(0xF00FEu, &clock);

    // WDT
    bus.MapSfr(0xFFFABu, &wdt);

    // Ports & External edges
    bus.MapSfrRange(0xFFF00u, 0xFFF0Fu, &ports);
    bus.MapSfrRange(0xFFF20u, 0xFFF2Fu, &ports);
    bus.MapSfrRange(0xFFF37u, 0xFFF3Bu, &ports);
    bus.MapSfrRange(0xF0030u, 0xF0077u, &ports);

    // TAU0 & TAU1
    bus.MapSfrRange(0xFFF18u, 0xFFF1Bu, &tau0);
    bus.MapSfrRange(0xFFF64u, 0xFFF6Fu, &tau0);
    bus.MapSfrRange(0xF0180u, 0xF01BFu, &tau0);
    bus.MapSfrRange(0xFFF70u, 0xFFF7Fu, &tau1);
    bus.MapSfrRange(0xF01C0u, 0xF01FFu, &tau1);

    // Interval Timer & RTC
    bus.MapSfrRange(0xFFF90u, 0xFFF9Eu, &rtc_it);

    // ADC
    bus.MapSfrRange(0xFFF1Eu, 0xFFF1Fu, &adc);
    bus.MapSfrRange(0xFFF30u, 0xFFF32u, &adc);
    bus.MapSfrRange(0xF0010u, 0xF0013u, &adc);

    // SAU0 & SAU1
    bus.MapSfrRange(0xFFF10u, 0xFFF13u, &sau0);
    bus.MapSfrRange(0xFFF44u, 0xFFF47u, &sau0);
    bus.MapSfrRange(0xF0100u, 0xF013Fu, &sau0);
    bus.MapSfrRange(0xFFF14u, 0xFFF17u, &sau1);
    bus.MapSfrRange(0xFFF48u, 0xFFF4Bu, &sau1);
    bus.MapSfrRange(0xF0140u, 0xF017Fu, &sau1);

    // IICA0 & IICA1
    bus.MapSfrRange(0xFFF50u, 0xFFF52u, &iica0);
    bus.MapSfrRange(0xF0230u, 0xF0234u, &iica0);
    bus.MapSfrRange(0xFFF54u, 0xFFF56u, &iica1);
    bus.MapSfrRange(0xF0238u, 0xF023Cu, &iica1);

    // Multiplier / Divider (shares MDAL/H @ 0xFFFF0..3 with CPU MACR)
    bus.MapSfrRange(0xFFFF4u, 0xFFFF7u, &muldiv);
    bus.MapSfrRange(0xF00E0u, 0xF00E3u, &muldiv);
    bus.MapSfr(0xF00E8u, &muldiv);

    // DMA
    bus.MapSfrRange(0xFFFB0u, 0xFFFBDu, &dma);
    bus.MapSfrRange(0xF0200u, 0xF020Du, &dma);

    // Flash Self-Programming & Boot Cluster Swap (BECTL, PFCMD, FLPMC, FLRST, FSL mailbox)
    bus.MapSfr(Rl78FlashCtrl::kBectlAddress, &flash);
    bus.MapSfr(Rl78FlashCtrl::kPfcmdAddress, &flash);
    bus.MapSfr(Rl78FlashCtrl::kFlpmcAddress, &flash);
    bus.MapSfr(Rl78FlashCtrl::kFlrstAddress, &flash);
    bus.MapSfrRange(Rl78FlashCtrl::kFslMailboxStart, Rl78FlashCtrl::kFslMailboxEnd, &flash);
}

void Rl78Machine::Reset(int32_t entry_override) {
    clock.ClearResetFlags();
    flash.InstallRomStub();
    bus.ResetDevices();
    if (entry_override >= 0) {
        cpu.ResetTo(static_cast<uint32_t>(entry_override));
    } else {
        cpu.Reset();
    }
}

bool Rl78Machine::LoadRomBytes(const uint8_t *data, size_t size, uint32_t base_addr) {
    if (!bus.LoadRom(data, size, base_addr)) return false;
    flash.InstallRomStub();
    flash.SyncBootFlagFromBus();
    return true;
}

bool Rl78Machine::LoadRomFile(const char *path, uint32_t base_addr) {
    std::vector<uint8_t> buf;
    if (!ReadBinaryFile(path, &buf)) return false;
    if (!bus.LoadRom(buf.data(), buf.size(), base_addr)) return false;
    flash.InstallRomStub();
    flash.SyncBootFlagFromBus();
    return true;
}

bool Rl78Machine::LoadDataFlashBytes(const uint8_t *data, size_t size, uint32_t offset) {
    return bus.LoadDataFlash(data, size, offset);
}

bool Rl78Machine::LoadDataFlashFile(const char *path, uint32_t offset) {
    std::vector<uint8_t> buf;
    if (!ReadBinaryFile(path, &buf)) return false;
    return bus.LoadDataFlash(buf.data(), buf.size(), offset);
}

StopInfo Rl78Machine::Step(bool ignore_bpt_at_pc) {
    return cpu.Step(ignore_bpt_at_pc);
}

StopInfo Rl78Machine::RunSteps(uint64_t max_steps,
                               bool ignore_bpt_at_first_pc,
                               const std::atomic<bool> *cancel) {
    uint64_t count = 0;
    while (max_steps == 0 || count < max_steps) {
        if (cancel && cancel->load()) {
            return StopInfo{StopReason::None, cpu.GetPC(), 0, false};
        }
        const bool ignore = (count == 0) && ignore_bpt_at_first_pc;
        const StopInfo stop = cpu.Step(ignore);
        ++count;
        if (stop.reason != StopReason::None) {
            return stop;
        }
    }
    return StopInfo{StopReason::None, cpu.GetPC(), 0, false};
}

std::string Rl78Machine::FormatStatus() const {
    const uint8_t psw = cpu.GetPSW();
    char buf[512];
    std::snprintf(buf, sizeof(buf),
        "[%s] PC=%05X SP=%04X PSW=%02X [IE:%d Z:%d RBS:%d AC:%d ISP:%d CY:%d] %s\n"
        "AX=%04X BC=%04X DE=%04X HL=%04X | CS=%X ES=%X PMC=%02X(MAA=%d) | MACR=%08X | Cycles=%llu Insns=%llu",
        CoreName(core_),
        cpu.GetPC(), cpu.GetSP(), psw,
        (psw & PSW_IE) ? 1 : 0,
        (psw & PSW_Z) ? 1 : 0,
        cpu.GetRB(),
        (psw & PSW_AC) ? 1 : 0,
        cpu.GetISP(),
        (psw & PSW_CY) ? 1 : 0,
        RunStateName(cpu.GetRunState()),
        cpu.ReadRegPair(RP_AX),
        cpu.ReadRegPair(RP_BC),
        cpu.ReadRegPair(RP_DE),
        cpu.ReadRegPair(RP_HL),
        cpu.GetCS(), cpu.GetES(), cpu.GetPMC(), bus.GetMirrorAreaAlt() ? 1 : 0,
        cpu.GetMACR(),
        static_cast<unsigned long long>(cpu.TotalCycles()),
        static_cast<unsigned long long>(cpu.InstructionCount()));
    return buf;
}

std::string Rl78Machine::FormatBanks() const {
    std::ostringstream oss;
    const uint8_t cur = cpu.GetRB();
    for (uint8_t b = 0; b < 4u; ++b) {
        char line[128];
        std::snprintf(line, sizeof(line),
            "%c RB%u (@%05X): AX=%04X BC=%04X DE=%04X HL=%04X\n",
            (b == cur) ? '*' : ' ',
            b,
            static_cast<unsigned>(Rl78Cpu::AddressOfReg(0, b) & ~7u),
            cpu.ReadRegPairBank(RP_AX, b),
            cpu.ReadRegPairBank(RP_BC, b),
            cpu.ReadRegPairBank(RP_DE, b),
            cpu.ReadRegPairBank(RP_HL, b));
        oss << line;
    }
    return oss.str();
}

std::string Rl78Machine::FormatIntc() const {
    std::ostringstream oss;
    char hdr[192];
    std::snprintf(hdr, sizeof(hdr),
        "IF=[%02X %02X %02X %02X %02X %02X %02X] MK=[%02X %02X %02X %02X %02X %02X %02X]\n"
        "PR0=[%02X %02X %02X %02X %02X %02X %02X] PR1=[%02X %02X %02X %02X %02X %02X %02X]\n",
        intc.GetIfReg(0), intc.GetIfReg(1), intc.GetIfReg(2), intc.GetIfReg(3), intc.GetIfReg(4), intc.GetIfReg(5), intc.GetIfReg(6),
        intc.GetMkReg(0), intc.GetMkReg(1), intc.GetMkReg(2), intc.GetMkReg(3), intc.GetMkReg(4), intc.GetMkReg(5), intc.GetMkReg(6),
        intc.GetPr0Reg(0), intc.GetPr0Reg(1), intc.GetPr0Reg(2), intc.GetPr0Reg(3), intc.GetPr0Reg(4), intc.GetPr0Reg(5), intc.GetPr0Reg(6),
        intc.GetPr1Reg(0), intc.GetPr1Reg(1), intc.GetPr1Reg(2), intc.GetPr1Reg(3), intc.GetPr1Reg(4), intc.GetPr1Reg(5), intc.GetPr1Reg(6));
    oss << hdr;
    const PendingInterrupt pend = intc.EvaluatePending();
    if (pend.pending) {
        char pline[128];
        std::snprintf(pline, sizeof(pline), "Next unmasked IRQ: idx=%u vec=0x%04X prio=%u\n",
                      pend.source_index, pend.vector_address, pend.priority);
        oss << pline;
    } else {
        oss << "Next unmasked IRQ: none\n";
    }
    return oss.str();
}

std::string Rl78Machine::FormatClock() const {
    char buf[256];
    std::snprintf(buf, sizeof(buf),
        "CMC=%02X CSC=%02X OSTC=%02X OSTS=%02X CKC=%02X PER0=%02X OSMC=%02X\n"
        "RESF=%02X LVIM=%02X LVIS=%02X DFLCTL=%02X WDTE=%02X (cnt=%u/%u)",
        clock.GetCmc(), clock.GetCsc(), clock.GetOstc(), clock.GetOsts(),
        clock.GetCkc(), clock.GetPer0(), clock.GetOsmc(),
        clock.GetResf(), clock.GetLvim(), clock.GetLvis(), clock.GetDflctl(),
        wdt.Peek(0xFFFABu), wdt.GetCounter(), wdt.GetOverflowPeriod());
    return buf;
}

std::string Rl78Machine::FormatTimers() const {
    std::ostringstream oss;
    auto dump_tau = [&](const char *name, uint8_t unit_idx, const Rl78Tau &tau) {
        char hdr[96];
        std::snprintf(hdr, sizeof(hdr), "%s (%u ch): TE%u=%04X TPS%u=%04X\n",
                      name, tau.NumChannels(), unit_idx, tau.GetEnableMask(), unit_idx, tau.GetTps());
        oss << hdr;
        for (uint8_t ch = 0; ch < tau.NumChannels(); ++ch) {
            char line[96];
            std::snprintf(line, sizeof(line), "  CH%u: en=%d TCR=%04X TDR=%04X TMR=%04X\n",
                          ch, (tau.GetEnableMask() & (1u << ch)) ? 1 : 0,
                          tau.GetCounter(ch), tau.GetData(ch), tau.GetMode(ch));
            oss << line;
        }
    };
    dump_tau("TAU0", 0u, tau0);
    dump_tau("TAU1", 1u, tau1);
    char hdr[160];
    std::snprintf(hdr, sizeof(hdr),
                  "ITMC=%04X (cnt=%03X) | RTC: RTCC0=%02X RTCC1=%02X %02X:%02X:%02X\n",
                  rtc_it.GetItmc(), rtc_it.GetItCounter(),
                  rtc_it.Peek(0xFFF9Du), rtc_it.Peek(0xFFF9Eu),
                  rtc_it.Peek(0xFFF94u), rtc_it.Peek(0xFFF93u), rtc_it.Peek(0xFFF92u));
    oss << hdr;
    return oss.str();
}

std::string Rl78Machine::FormatPorts() const {
    std::ostringstream oss;
    for (uint8_t p = 0; p <= 15u; ++p) {
        char line[64];
        std::snprintf(line, sizeof(line), "P%-2u=%02X (PM=%02X EXT=%02X)%s",
                      p, ports.GetPinState(p), ports.GetMode(p), ports.GetExternalInput(p),
                      ((p % 2u) == 1u) ? "\n" : " | ");
        oss << line;
    }
    return oss.str();
}

std::string Rl78Machine::FormatSau() const {
    std::ostringstream oss;
    char l0[128];
    std::snprintf(l0, sizeof(l0), "SAU0 SE=%02X loopback=%s | SDR=[%04X %04X %04X %04X]\n",
                  sau0.GetSe() & 0x0Fu, sau0.IsLoopback() ? "on" : "off",
                  sau0.GetSdr(0), sau0.GetSdr(1), sau0.GetSdr(2), sau0.GetSdr(3));
    oss << l0;
    std::snprintf(l0, sizeof(l0), "SAU1 SE=%02X loopback=%s | SDR=[%04X %04X %04X %04X]\n",
                  sau1.GetSe() & 0x0Fu, sau1.IsLoopback() ? "on" : "off",
                  sau1.GetSdr(0), sau1.GetSdr(1), sau1.GetSdr(2), sau1.GetSdr(3));
    oss << l0;
    return oss.str();
}

std::string Rl78Machine::FormatAdc() const {
    char buf[128];
    std::snprintf(buf, sizeof(buf), "ADM0=%02X ADS=%02X ADCR=%04X (AN%u raw=%03X)",
                  adc.GetAdm0(), adc.GetAds(), adc.GetAdcr(),
                  adc.GetAds() & 0x1Fu, adc.GetChannelVoltage(adc.GetAds() & 0x1Fu));
    return buf;
}

std::string Rl78Machine::FormatDma() const {
    std::ostringstream oss;
    for (uint8_t c = 0; c < 4u; ++c) {
        const uint32_t dsa_a = (c < 2u) ? (0xFFFB0u + c) : (0xF0200u + (c - 2u));
        const uint32_t dra_l = (c < 2u) ? (0xFFFB2u + c * 2u) : (0xF0202u + (c - 2u) * 2u);
        const uint32_t dbc_l = (c < 2u) ? (0xFFFB6u + c * 2u) : (0xF0206u + (c - 2u) * 2u);
        const uint32_t dmc_a = (c < 2u) ? (0xFFFBAu + c) : (0xF020Au + (c - 2u));
        const uint32_t drc_a = (c < 2u) ? (0xFFFBCu + c) : (0xF020Cu + (c - 2u));
        const uint16_t dra_v = static_cast<uint16_t>(dma.Peek(dra_l)) | (static_cast<uint16_t>(dma.Peek(dra_l + 1u)) << 8);
        const uint16_t dbc_v = static_cast<uint16_t>(dma.Peek(dbc_l)) | (static_cast<uint16_t>(dma.Peek(dbc_l + 1u)) << 8);
        char line[128];
        std::snprintf(line, sizeof(line), "DMA%u: DSA=%02X DRA=%04X DBC=%04X DMC=%02X DRC=%02X\n",
                      c, dma.Peek(dsa_a), dra_v, dbc_v, dma.Peek(dmc_a), dma.Peek(drc_a));
        oss << line;
    }
    return oss.str();
}

std::string Rl78Machine::FormatFlash() const {
    const uint16_t vec0 = static_cast<uint16_t>(bus.PeekByte(0x00000u)) |
                          (static_cast<uint16_t>(bus.PeekByte(0x00001u)) << 8);
    const uint16_t vec1 = static_cast<uint16_t>(bus.PeekByte(0x01000u)) |
                          (static_cast<uint16_t>(bus.PeekByte(0x01001u)) << 8);
    const uint16_t fsl_limit = static_cast<uint16_t>(bus.PeekByte(Rl78FlashCtrl::kFslSizeInfoAddress)) |
                               (static_cast<uint16_t>(bus.PeekByte(Rl78FlashCtrl::kFslSizeInfoAddress + 1u)) << 8);
    std::ostringstream oss;
    char buf[512];
    std::snprintf(buf, sizeof(buf),
                  "BootSwap: %s\n"
                  "Vec[0x0000]=%04X  Vec[0x1000]=%04X  SwapCount=%u  FlashMutations=%u\n"
                  "BECTL=%02X  PFCMD=%02X  FLPMC=%02X  FLRST=%02X  FLMD0=%u\n"
                  "FSL Calls=%u  LastCmd=%02X  LastStatus=%02X  ErasedBlocks=%u  ProgrammedBytes=%u\n"
                  "FSL ROM Stub: 0x0EFFD0=%04X  0x0EFFF8=%02X\n",
                  bus.IsBootSwapped() ? "SWAPPED (Cluster1@0x0000 / Updater)"
                                      : "NORMAL  (Cluster0@0x0000 / Main)",
                  vec0, vec1, bus.BootSwapCount(), bus.FlashMutationCount(),
                  flash.GetBectl(), flash.GetPfcmd(), flash.GetFlpmc(), flash.GetFlrst(),
                  flash.IsFlmd0High() ? 1u : 0u,
                  flash.FslCallCount(), flash.LastFslCmd(), flash.LastFslStatus(),
                  flash.ErasedBlocks(), flash.ProgrammedBytes(),
                  fsl_limit, bus.PeekByte(Rl78FlashCtrl::kFslRomEntryAddress));
    oss << buf;
    return oss.str();
}

std::string Rl78Machine::FormatMemoryMap() const {
    std::ostringstream oss;
    for (const auto &reg : bus.GetRegions()) {
        char line[128];
        const uint32_t end = reg.start + reg.size - 1u;
        std::snprintf(line, sizeof(line), "%05X..%05X (%6u bytes) %-12s %c%c%c%s\n",
                      reg.start, end, reg.size, reg.name.c_str(),
                      (reg.perm & MEM_PERM_READ) ? 'R' : '-',
                      (reg.perm & MEM_PERM_WRITE) ? 'W' : '-',
                      (reg.perm & MEM_PERM_EXEC) ? 'X' : '-',
                      reg.is_device ? " [MMIO]" : "");
        oss << line;
    }
    return oss.str();
}

bool Rl78Machine::ExecuteCommand(const std::string &cmdline, std::string &out) {
    const std::string trimmed = Trim(cmdline);
    if (trimmed.empty() || EqIgnoreCase(trimmed.c_str(), "help") || trimmed == "?") {
        out =
            "rl78emu commands:\n"
            "  status                - CPU/SP/PSW/CS/ES/PMC/cycle summary\n"
            "  banks                 - Dump all 4 GPR register banks (RB0..RB3)\n"
            "  intc                  - Dump INTC IF/MK/PR0/PR1 & pending IRQ\n"
            "  clock                 - Dump clock, DFLCTL, LVI, RESF, and WDT state\n"
            "  timers                - Dump TAU0/TAU1 channels, ITMC, and RTC state\n"
            "  ports                 - Dump GPIO ports P0..P15\n"
            "  sau                   - Dump SAU0/SAU1 UART/CSI state\n"
            "  adc                   - Dump ADC state\n"
            "  dma                   - Dump DMA0..3 state\n"
            "  flash [subcmd]        - Flash/boot state (status|swap|boot <0|1|main|updater|start0|start1>|flmd0 <0|1>|erase <blk>)\n"
            "  map                   - Show 20-bit memory map\n"
            "  disasm [addr] [count] - Disassemble RL78 instructions\n"
            "  step [n]              - Execute n instructions (default 1)\n"
            "  reset [pc]            - Reset target (optionally to pc)\n"
            "  irq <name|idx>        - Inject hardware IRQ (e.g. irq INTIT)\n"
            "  pin <port> <pin> <0|1>- Set external GPIO input level\n"
            "  adcch <ch> <val>      - Set 10-bit ADC channel input (0..1023)\n"
            "  uartrx <0|1> <ch> <hx>- Inject UART RX byte (unit 0..1, ch 0..3)\n"
            "  uarttx [0|1] [ch]     - Drain captured SAU TX FIFO bytes\n"
            "  maa <0|1>             - Set PMC.MAA mirror select (0=0xxxx, 1=1xxxx)\n";
        return true;
    }

    const auto args = SplitArgs(trimmed);
    const std::string &cmd = args[0];

    if (EqIgnoreCase(cmd.c_str(), "status")) { out = FormatStatus(); return true; }
    if (EqIgnoreCase(cmd.c_str(), "banks"))  { out = FormatBanks(); return true; }
    if (EqIgnoreCase(cmd.c_str(), "intc"))   { out = FormatIntc(); return true; }
    if (EqIgnoreCase(cmd.c_str(), "clock"))  { out = FormatClock(); return true; }
    if (EqIgnoreCase(cmd.c_str(), "timers")) { out = FormatTimers(); return true; }
    if (EqIgnoreCase(cmd.c_str(), "ports"))  { out = FormatPorts(); return true; }
    if (EqIgnoreCase(cmd.c_str(), "sau"))    { out = FormatSau(); return true; }
    if (EqIgnoreCase(cmd.c_str(), "adc"))    { out = FormatAdc(); return true; }
    if (EqIgnoreCase(cmd.c_str(), "dma"))    { out = FormatDma(); return true; }
    if (EqIgnoreCase(cmd.c_str(), "flash")) {
        if (args.size() == 1 || EqIgnoreCase(args[1].c_str(), "status")) {
            out = FormatFlash();
            return true;
        }
        if (EqIgnoreCase(args[1].c_str(), "swap")) {
            bus.SwapBootClusters();
            flash.SyncBootFlagFromBus();
            out = FormatFlash();
            return true;
        }
        if (EqIgnoreCase(args[1].c_str(), "boot") && args.size() >= 3) {
            const std::string &target = args[2];
            if (target == "0" || EqIgnoreCase(target.c_str(), "main") ||
                EqIgnoreCase(target.c_str(), "start0")) {
                bus.SetBootSwapped(false);
            } else if (target == "1" || EqIgnoreCase(target.c_str(), "updater") ||
                       EqIgnoreCase(target.c_str(), "start1")) {
                bus.SetBootSwapped(true);
            } else {
                out = "Usage: flash boot <0|1|main|updater|start0|start1>";
                return false;
            }
            flash.SyncBootFlagFromBus();
            out = FormatFlash();
            return true;
        }
        if (EqIgnoreCase(args[1].c_str(), "flmd0") && args.size() >= 3) {
            const bool high = (std::strtoul(args[2].c_str(), nullptr, 0) != 0);
            flash.SetFlmd0High(high);
            out = FormatFlash();
            return true;
        }
        if (EqIgnoreCase(args[1].c_str(), "erase") && args.size() >= 3) {
            const uint32_t blk = static_cast<uint32_t>(std::strtoul(args[2].c_str(), nullptr, 0));
            if (!bus.EraseFlashBlock(blk)) {
                out = "Erase failed: block out of range";
                return false;
            }
            char hdr[64];
            std::snprintf(hdr, sizeof(hdr), "Erased 1KB flash block 0x%X\n", blk);
            out = hdr + FormatFlash();
            return true;
        }
        out = "Usage: flash [status|swap|boot <0|1|main|updater|start0|start1>|flmd0 <0|1>|erase <block>]";
        return false;
    }
    if (EqIgnoreCase(cmd.c_str(), "map"))    { out = FormatMemoryMap(); return true; }

    if (EqIgnoreCase(cmd.c_str(), "reset")) {
        int32_t entry = -1;
        if (args.size() >= 2) {
            entry = static_cast<int32_t>(std::strtoul(args[1].c_str(), nullptr, 0) & Rl78Bus::kAddressMask);
        }
        Reset(entry);
        out = FormatStatus();
        return true;
    }

    if (EqIgnoreCase(cmd.c_str(), "step")) {
        const uint64_t n = (args.size() >= 2) ? std::strtoull(args[1].c_str(), nullptr, 0) : 1u;
        const StopInfo st = RunSteps(n ? n : 1u, true);
        char hdr[64];
        std::snprintf(hdr, sizeof(hdr), "StopReason=%u PC=%05X\n",
                      static_cast<unsigned>(st.reason), st.pc);
        out = hdr + FormatStatus();
        return true;
    }

    if (EqIgnoreCase(cmd.c_str(), "disasm")) {
        uint32_t addr = cpu.GetPC();
        int count = 8;
        if (args.size() >= 2) addr = static_cast<uint32_t>(std::strtoul(args[1].c_str(), nullptr, 0) & Rl78Bus::kAddressMask);
        if (args.size() >= 3) count = std::max(1, std::min(64, std::atoi(args[2].c_str())));
        std::ostringstream oss;
        for (int i = 0; i < count; ++i) {
            const DecodedInsn di = DisassembleAt(bus, addr);
            char line[160];
            std::snprintf(line, sizeof(line), "%c %05X: %s\n",
                          (addr == cpu.GetPC()) ? '>' : ' ', addr, di.FormatWithBytes().c_str());
            oss << line;
            addr = (addr + (di.length ? di.length : 1u)) & Rl78Bus::kAddressMask;
        }
        out = oss.str();
        return true;
    }

    if (EqIgnoreCase(cmd.c_str(), "irq") && args.size() >= 2) {
        int idx = intc.FindIrqByName(args[1].c_str());
        if (idx < 0 && std::isdigit(static_cast<unsigned char>(args[1][0]))) {
            idx = std::atoi(args[1].c_str());
        }
        if (idx < 0 || idx >= IRQ_COUNT) {
            out = "Unknown IRQ source: " + args[1];
            return false;
        }
        intc.RaiseIrq(static_cast<uint8_t>(idx));
        char buf[64];
        std::snprintf(buf, sizeof(buf), "Raised IRQ %d", idx);
        out = buf;
        return true;
    }

    if (EqIgnoreCase(cmd.c_str(), "pin") && args.size() >= 4) {
        const int port = std::atoi(args[1].c_str());
        const int pin = std::atoi(args[2].c_str());
        const int val = std::atoi(args[3].c_str());
        if (port < 0 || port >= 16 || pin < 0 || pin >= 8) {
            out = "Invalid port/pin (port 0..15, pin 0..7)";
            return false;
        }
        ports.SetExternalInput(static_cast<uint8_t>(port), static_cast<uint8_t>(pin), val != 0);
        char buf[64];
        std::snprintf(buf, sizeof(buf), "P%d.%d = %d", port, pin, val ? 1 : 0);
        out = buf;
        return true;
    }

    if (EqIgnoreCase(cmd.c_str(), "adcch") && args.size() >= 3) {
        const uint8_t ch = static_cast<uint8_t>(std::strtoul(args[1].c_str(), nullptr, 0));
        const uint16_t val = static_cast<uint16_t>(std::strtoul(args[2].c_str(), nullptr, 0));
        adc.SetChannelVoltage(ch, val);
        char buf[64];
        std::snprintf(buf, sizeof(buf), "ADC AN%u = %u", ch, val & 0x03FFu);
        out = buf;
        return true;
    }

    if (EqIgnoreCase(cmd.c_str(), "uartrx") && args.size() >= 4) {
        const int unit = std::atoi(args[1].c_str());
        const uint8_t ch = static_cast<uint8_t>(std::strtoul(args[2].c_str(), nullptr, 0) & 3u);
        const uint8_t b = static_cast<uint8_t>(std::strtoul(args[3].c_str(), nullptr, 16));
        Rl78Sau &s = (unit == 1) ? sau1 : sau0;
        s.PushRxByte(ch, b);
        char buf[64];
        std::snprintf(buf, sizeof(buf), "Injected SAU%d ch%u RX byte 0x%02X", (unit == 1) ? 1 : 0, ch, b);
        out = buf;
        return true;
    }

    if (EqIgnoreCase(cmd.c_str(), "uarttx")) {
        const int unit = (args.size() >= 2) ? std::atoi(args[1].c_str()) : 0;
        const uint8_t ch = (args.size() >= 3) ? static_cast<uint8_t>(std::strtoul(args[2].c_str(), nullptr, 0) & 3u) : 0u;
        Rl78Sau &s = (unit == 1) ? sau1 : sau0;
        const auto tx = s.DrainTx(ch);
        std::ostringstream oss;
        oss << "TX (" << tx.size() << " bytes):";
        for (uint8_t b : tx) {
            char hex[8];
            std::snprintf(hex, sizeof(hex), " %02X", b);
            oss << hex;
        }
        out = oss.str();
        return true;
    }

    if (EqIgnoreCase(cmd.c_str(), "maa") && args.size() >= 2) {
        const uint8_t maa = static_cast<uint8_t>(std::strtoul(args[1].c_str(), nullptr, 0) & 1u);
        cpu.SetPMC(maa);
        char buf[64];
        std::snprintf(buf, sizeof(buf), "PMC.MAA = %u (Mirror -> %s)", maa, maa ? "0x10000" : "0x00000");
        out = buf;
        return true;
    }

    out = "Unknown command: " + trimmed + " (type 'help' for list)";
    return false;
}

}  // namespace rl78
