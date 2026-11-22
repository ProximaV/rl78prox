#include <cstdint>
#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

#include "debugger.h"
#include "disasm.h"
#include "machine.h"

namespace {

int g_failures = 0;

void CheckTrue(bool cond, const char *expr, const char *file, int line) {
    if (!cond) {
        std::fprintf(stderr, "[FAIL] %s:%d: expected true: %s\n", file, line, expr);
        ++g_failures;
    }
}

void CheckEqU64(uint64_t actual, uint64_t expected, const char *a_expr, const char *e_expr,
                const char *file, int line) {
    if (actual != expected) {
        std::fprintf(stderr, "[FAIL] %s:%d: %s (0x%llX / %llu) != %s (0x%llX / %llu)\n",
                     file, line,
                     a_expr, static_cast<unsigned long long>(actual), static_cast<unsigned long long>(actual),
                     e_expr, static_cast<unsigned long long>(expected), static_cast<unsigned long long>(expected));
        ++g_failures;
    }
}

#define EXPECT_TRUE(cond) CheckTrue((cond), #cond, __FILE__, __LINE__)
#define EXPECT_EQ(a, e) CheckEqU64(static_cast<uint64_t>(a), static_cast<uint64_t>(e), #a, #e, __FILE__, __LINE__)
#define EXPECT_STREQ(a, e) CheckTrue((a) == (e), #a " == " #e, __FILE__, __LINE__)

rl78::Rl78Machine MakeMachine(rl78::CoreProfile core = rl78::CoreProfile::S3) {
    rl78::Rl78Machine m;
    m.Configure(core, 0x080000u, 0x002000u, 0x0F7F00u);
    m.bus.ClearMemory();
    m.Reset(0x01000u);
    return m;
}

void WriteBytes(rl78::Rl78Machine &m, uint32_t addr, std::initializer_list<uint8_t> bytes) {
    std::vector<uint8_t> buf(bytes);
    m.bus.WriteDebug(addr, buf.size(), buf.data());
}

void TestResetBanksPswAndMirror() {
    auto m = MakeMachine();
    EXPECT_EQ(m.cpu.GetPSW(), 0x06u);  // ISP=3, IE=0, RB=0
    EXPECT_EQ(m.cpu.GetISP(), 3u);
    EXPECT_EQ(m.cpu.GetES(), 0x0Fu);
    EXPECT_EQ(m.cpu.GetCS(), 0x00u);
    EXPECT_EQ(m.cpu.GetRB(), 0u);
    EXPECT_EQ(m.cpu.GetSP(), 0x0000u);

    // SP LSB is hardwired to 0.
    m.cpu.SetSP(0xFE21u);
    EXPECT_EQ(m.cpu.GetSP(), 0xFE20u);

    // Bank switching via SEL RB0..3 (0x61 CF/DF/EF/FF) + MOV A, #imm
    WriteBytes(m, 0x01000u, {
        0x61, 0xCF, 0x51, 0x11,  // sel rb0; mov A, #11h -> RB0 (0xFFEF9)
        0x61, 0xDF, 0x51, 0x22,  // sel rb1; mov A, #22h -> RB1 (0xFFEF1)
        0x61, 0xEF, 0x51, 0x33,  // sel rb2; mov A, #33h -> RB2 (0xFFEE9)
        0x61, 0xFF, 0x51, 0x44,  // sel rb3; mov A, #44h -> RB3 (0xFFEE1)
    });
    for (int i = 0; i < 8; ++i) m.Step();
    EXPECT_EQ(m.cpu.GetRB(), 3u);
    EXPECT_EQ(m.bus.PeekByte(0xFFEF9u), 0x11u);
    EXPECT_EQ(m.bus.PeekByte(0xFFEF1u), 0x22u);
    EXPECT_EQ(m.bus.PeekByte(0xFFEE9u), 0x33u);
    EXPECT_EQ(m.bus.PeekByte(0xFFEE1u), 0x44u);
    EXPECT_EQ(m.cpu.ReadRegBank(rl78::REG_A, 0), 0x11u);
    EXPECT_EQ(m.cpu.ReadRegBank(rl78::REG_A, 1), 0x22u);
    EXPECT_EQ(m.cpu.ReadRegBank(rl78::REG_A, 2), 0x33u);
    EXPECT_EQ(m.cpu.ReadRegBank(rl78::REG_A, 3), 0x44u);

    // Mirror Area PMC.MAA (0x04000 vs 0x14000 visible at 0xF4000)
    WriteBytes(m, 0x04000u, { 0x5Au });
    WriteBytes(m, 0x14000u, { 0xA5u });
    EXPECT_EQ(m.bus.ReadCpu(0xF4000u), 0x5Au);
    m.bus.WriteCpu(rl78::kPmcAddress, 0x01u);  // MAA = 1
    EXPECT_EQ(m.bus.ReadCpu(0xF4000u), 0xA5u);

    // saddr wraparound: saddr < 0x20 -> 0xFFF00+off, saddr >= 0x20 -> 0xFFE00+off
    EXPECT_EQ(rl78::Rl78Bus::ResolveSaddr(0x00u), 0xFFF00u);
    EXPECT_EQ(rl78::Rl78Bus::ResolveSaddr(0x1Fu), 0xFFF1Fu);
    EXPECT_EQ(rl78::Rl78Bus::ResolveSaddr(0x20u), 0xFFE20u);
    EXPECT_EQ(rl78::Rl78Bus::ResolveSaddr(0xFFu), 0xFFEFFu);
}

void TestAluShiftsAndS3Math() {
    auto m = MakeMachine(rl78::CoreProfile::S3);

    // MULU X (0xD6): A=0x12, X=0x34 -> AX=0x03A8
    WriteBytes(m, 0x01000u, {
        0x30, 0x34, 0x12,  // movw ax, #0x1234
        0xD6,              // mulu x
        0x31, 0x3E,        // shrw ax, #3 (0x03A8 >> 3 = 0x0075, bit2..0 = 000 -> last shifted out bit2 = 0)
        0x31, 0x4B,        // sar a, #4? wait: 0x31 4B is sar a, #4
    });
    m.Step();
    EXPECT_EQ(m.cpu.ReadRegPair(rl78::RP_AX), 0x1234u);
    m.Step();
    EXPECT_EQ(m.cpu.ReadRegPair(rl78::RP_AX), 0x03A8u);
    m.Step();
    EXPECT_EQ(m.cpu.ReadRegPair(rl78::RP_AX), 0x0075u);
    EXPECT_TRUE(!m.cpu.GetCY());

    // SAR A, #4: A=0x8C -> 0xF8, CY=1
    m.cpu.SetPC(0x01100u);
    m.cpu.WriteReg(rl78::REG_A, 0x8Cu);
    m.cpu.SetCY(false);
    WriteBytes(m, 0x01100u, { 0x31, 0x4Bu });
    m.Step();
    EXPECT_EQ(m.cpu.ReadReg(rl78::REG_A), 0xF8u);
    EXPECT_TRUE(m.cpu.GetCY());

    // S3 extended math: MULHU, MULH, DIVHU, DIVWU, MACHU, MACH
    m.cpu.SetPC(0x01200u);
    WriteBytes(m, 0x01200u, {
        0x30, 0x00, 0xC0,        // movw ax, #0xC000
        0x32, 0x00, 0x10,        // movw bc, #0x1000
        0xCE, 0xFB, 0x01,        // mulhu -> BC:AX = 0x0C00_0000
        0x30, 0x00, 0xC0,        // movw ax, #0xC000 (-16384)
        0x32, 0x00, 0x10,        // movw bc, #0x1000 (+4096)
        0xCE, 0xFB, 0x02,        // mulh -> BC:AX = 0xFC00_0000
        0x30, 0x81, 0x80,        // movw ax, #0x8081
        0x34, 0x02, 0x00,        // movw de, #0x0002
        0xCE, 0xFB, 0x03,        // divhu -> AX=0x4040, DE=0x0001
        0x30, 0x81, 0x80,        // movw ax, #0x8081
        0x32, 0x80, 0x80,        // movw bc, #0x8080 -> BCAX = 0x80808081
        0x34, 0x02, 0x00,        // movw de, #0x0002
        0x36, 0x00, 0x00,        // movw hl, #0x0000 -> HLDE = 0x00000002
        0xCE, 0xFB, 0x0B,        // divwu -> BCAX=0x40404040, HLDE=0x00000001
    });
    for (int i = 0; i < 3; ++i) m.Step();
    EXPECT_EQ(m.cpu.ReadRegPair(rl78::RP_AX), 0x0000u);
    EXPECT_EQ(m.cpu.ReadRegPair(rl78::RP_BC), 0x0C00u);
    for (int i = 0; i < 3; ++i) m.Step();
    EXPECT_EQ(m.cpu.ReadRegPair(rl78::RP_AX), 0x0000u);
    EXPECT_EQ(m.cpu.ReadRegPair(rl78::RP_BC), 0xFC00u);
    for (int i = 0; i < 3; ++i) m.Step();
    EXPECT_EQ(m.cpu.ReadRegPair(rl78::RP_AX), 0x4040u);
    EXPECT_EQ(m.cpu.ReadRegPair(rl78::RP_DE), 0x0001u);
    for (int i = 0; i < 5; ++i) m.Step();
    EXPECT_EQ(m.cpu.ReadRegPair(rl78::RP_AX), 0x4040u);
    EXPECT_EQ(m.cpu.ReadRegPair(rl78::RP_BC), 0x4040u);
    EXPECT_EQ(m.cpu.ReadRegPair(rl78::RP_DE), 0x0001u);
    EXPECT_EQ(m.cpu.ReadRegPair(rl78::RP_HL), 0x0000u);

    // DIVHU by zero -> DE=old AX, AX=0xFFFF
    m.cpu.SetPC(0x01300u);
    m.cpu.WriteRegPair(rl78::RP_AX, 0x1234u);
    m.cpu.WriteRegPair(rl78::RP_DE, 0x0000u);
    WriteBytes(m, 0x01300u, { 0xCE, 0xFB, 0x03 });
    m.Step();
    EXPECT_EQ(m.cpu.ReadRegPair(rl78::RP_AX), 0xFFFFu);
    EXPECT_EQ(m.cpu.ReadRegPair(rl78::RP_DE), 0x1234u);

    // MACHU & MACH accumulate + overflow/negative flags
    m.cpu.SetPC(0x01320u);
    m.cpu.SetMACR(0xF8000000u);
    m.cpu.WriteRegPair(rl78::RP_AX, 0xC000u);
    m.cpu.WriteRegPair(rl78::RP_BC, 0x1000u);
    WriteBytes(m, 0x01320u, {
        0xCE, 0xFB, 0x05,  // machu: 0xF800_0000 + 0x0C00_0000 = 0x1_0400_0000 -> MACR=0x04000000, CY=1, AC=0
        0xCE, 0xFB, 0x06,  // mach: 0x0400_0000 + (-0x4000 * 0x1000 = -0x0400_0000) = 0 -> MACR=0, CY=0, AC=0
        0xCE, 0xFB, 0x06,  // mach: 0 + (-0x0400_0000) = 0xFC00_0000 -> CY=0, AC=1 (negative)
    });
    m.Step();
    EXPECT_EQ(m.cpu.GetMACR(), 0x04000000u);
    EXPECT_TRUE(m.cpu.GetCY());
    EXPECT_TRUE((m.cpu.GetPSW() & rl78::PSW_AC) == 0);
    m.Step();
    EXPECT_EQ(m.cpu.GetMACR(), 0x00000000u);
    EXPECT_TRUE(!m.cpu.GetCY());
    EXPECT_TRUE((m.cpu.GetPSW() & rl78::PSW_AC) == 0);
    m.Step();
    EXPECT_EQ(m.cpu.GetMACR(), 0xFC000000u);
    EXPECT_TRUE(!m.cpu.GetCY());
    EXPECT_TRUE((m.cpu.GetPSW() & rl78::PSW_AC) != 0);

    // CMP0 sets Z and clears AC & CY
    m.cpu.SetPC(0x01340u);
    m.cpu.SetPSW(rl78::PSW_RESET | rl78::PSW_CY | rl78::PSW_AC);
    m.cpu.WriteReg(rl78::REG_A, 0x00u);
    WriteBytes(m, 0x01340u, { 0xD1 });  // cmp0 a
    m.Step();
    EXPECT_TRUE((m.cpu.GetPSW() & rl78::PSW_Z) != 0);
    EXPECT_TRUE((m.cpu.GetPSW() & rl78::PSW_AC) == 0);
    EXPECT_TRUE(!m.cpu.GetCY());
}

void TestEsPrefixCallsSkipsAndPushPsw() {
    auto m = MakeMachine();
    m.cpu.SetSP(0xFE20u);

    // Far read using ES: prefix in bank 2 (0x21234)
    WriteBytes(m, 0x21234u, { 0x77u, 0x88u });
    // Skip SKZ over ES:-prefixed MOV A, !addr16 (4 bytes!)
    WriteBytes(m, 0x01400u, {
        0x41, 0x02,              // mov es, #0x02
        0x11, 0x8F, 0x34, 0x12,  // mov a, es:!0x1234 -> A=0x77
        0x50, 0x00,              // mov x, #0
        0xD0,                    // cmp0 x -> Z=1
        0x61, 0xE8,              // skz (true -> skip next 4-byte ES: instruction!)
        0x11, 0x5F, 0x35, 0x12,  // SKIPPED: and a, es:!0x1235
        0x61, 0xDD,              // push psw -> writes [SP-2]=0x00, [SP-1]=PSW
        0x61, 0xCD,              // pop psw
        0xFC, 0x00, 0x50, 0x02,  // call !!0x25000 (pushes 4-byte return addr, ES ignored on call)
    });
    WriteBytes(m, 0x25000u, {
        0xD7,                    // ret (pops 4-byte PC)
    });

    m.cpu.SetPC(0x01400u);
    m.Step();  // mov es, #2
    EXPECT_EQ(m.cpu.GetES(), 2u);
    m.Step();  // mov a, es:!0x1234
    EXPECT_EQ(m.cpu.ReadReg(rl78::REG_A), 0x77u);
    m.Step();  // mov x, #0
    m.Step();  // cmp0 x -> Z=1
    const uint32_t expected_after_skip = 0x0140Fu;
    m.Step();  // skz -> skips 11 5F 35 12 (4 bytes)!
    EXPECT_EQ(m.cpu.GetPC(), expected_after_skip);
    EXPECT_EQ(m.cpu.ReadReg(rl78::REG_A), 0x77u);

    const uint8_t psw_before = m.cpu.GetPSW();
    m.Step();  // push psw
    EXPECT_EQ(m.cpu.GetSP(), 0xFE1Eu);
    EXPECT_EQ(m.bus.PeekByte(0xFFE1Eu), 0x00u);
    EXPECT_EQ(m.bus.PeekByte(0xFFE1Fu), psw_before);
    m.Step();  // pop psw
    EXPECT_EQ(m.cpu.GetSP(), 0xFE20u);

    m.Step();  // call !!0x25000 (from 0x01413, len 4 -> ret addr = 0x01417)
    EXPECT_EQ(m.cpu.GetPC(), 0x25000u);
    EXPECT_EQ(m.cpu.GetSP(), 0xFE1Cu);
    EXPECT_EQ(m.bus.PeekByte(0xFFE1Cu), 0x17u);
    EXPECT_EQ(m.bus.PeekByte(0xFFE1Du), 0x14u);
    EXPECT_EQ(m.bus.PeekByte(0xFFE1Eu), 0x00u);
    EXPECT_EQ(m.bus.PeekByte(0xFFE1Fu), 0x00u);
    m.Step();  // ret
    EXPECT_EQ(m.cpu.GetPC(), 0x01417u);
    EXPECT_EQ(m.cpu.GetSP(), 0xFE20u);

    // Reject invalid ES: prefix (e.g. ES: before NOP 0x11 0x00)
    m.cpu.SetPC(0x01500u);
    WriteBytes(m, 0x01500u, { 0x11, 0x00 });
    const auto st = m.Step();
    EXPECT_EQ(static_cast<int>(st.reason), static_cast<int>(rl78::StopReason::InvalidInsn));
}

void TestFourLevelInterruptsAndPeripherals() {
    auto m = MakeMachine();
    m.cpu.SetSP(0xFE40u);

    // Install vectors for INTIT (0x0038 -> prio 2) and INTTM00 (0x002C -> prio 0)
    WriteBytes(m, 0x00038u, { 0x00, 0x30 });  // 0x03000
    WriteBytes(m, 0x0002Cu, { 0x00, 0x31 });  // 0x03100

    // Configure INTIT @ prio 2 (PR11L.2=1, PR01L.2=0 -> 10b = 2) and INTTM00 @ prio 0 (00b = 0)
    m.bus.PokeByte(0xFFFE6u, 0xEFu);  // MK1L: unmask TM00 (bit 4 = 0)
    m.bus.PokeByte(0xFFFE7u, 0xFBu);  // MK1H: unmask IT (bit 2 = 0)
    m.bus.PokeByte(0xFFFEAu, 0xEFu);  // PR01L: TM00 PR0=0
    m.bus.PokeByte(0xFFFEEu, 0xEFu);  // PR11L: TM00 PR1=0 -> prio 0
    m.bus.PokeByte(0xFFFEBu, 0xFBu);  // PR01H: IT PR0=0
    m.bus.PokeByte(0xFFFEFu, 0xFFu);  // PR11H: IT PR1=1 -> prio 2

    // Main code: EI; HALT; NOP
    WriteBytes(m, 0x01000u, {
        0x71, 0x7A, 0xFA,  // ei (sets IE=1 + 1-insn hold!)
        0x61, 0xED,        // halt
        0x00,              // nop
    });
    // INTIT ISR at 0x03000: EI; NOP; RETI
    WriteBytes(m, 0x03000u, {
        0x71, 0x7A, 0xFA,  // ei (with ISP=1 from prio 2!)
        0x00,              // nop (higher prio 0 pre-empts here if pending)
        0x61, 0xFC,        // reti
    });
    // INTTM00 ISR at 0x03100: INC X; RETI
    WriteBytes(m, 0x03100u, {
        0x80,              // inc x
        0x61, 0xFC,        // reti
    });

    m.cpu.SetPC(0x01000u);
    m.intc.RaiseIrq(rl78::IRQ_IT);
    m.Step();  // ei -> 1-instruction interrupt hold prevents immediate entry on ei itself
    EXPECT_EQ(m.cpu.GetPC(), 0x01003u);
    m.Step();  // halt -> executes halt, THEN enters INTIT (0x03000) with ISP = 1!
    EXPECT_EQ(m.cpu.GetPC(), 0x03000u);
    EXPECT_EQ(m.cpu.GetISP(), 1u);
    EXPECT_EQ(m.cpu.GetSP(), 0xFE3Cu);

    // Inside INTIT (ISP=1): enable interrupts, then raise INTTM00 (prio 0 <= ISP 1) -> preempts!
    m.Step();  // ei inside INTIT
    m.intc.RaiseIrq(rl78::IRQ_TM00);
    m.Step();  // nop -> enters INTTM00 at 0x03100!
    EXPECT_EQ(m.cpu.GetPC(), 0x03100u);
    m.Step();  // inc x -> X=1
    m.Step();  // reti -> back to 0x03004 (INTIT), ISP=1
    EXPECT_EQ(m.cpu.GetPC(), 0x03004u);
    EXPECT_EQ(m.cpu.ReadReg(rl78::REG_X), 1u);
    m.Step();  // reti -> back to 0x01005, ISP=3!
    EXPECT_EQ(m.cpu.GetPC(), 0x01005u);
    EXPECT_EQ(m.cpu.GetISP(), 3u);

    // Hardware peripherals: TAU0 ch0, SAU0 UART loopback, ADC, MDUC, DMA
    m.sau0.SetLoopback(true);
    m.bus.WriteCpu(0xF0122u, 0x03u);  // SS0 = 0x03 (enable ch0 TX & ch1 RX)
    m.bus.WriteCpu(0xFFF10u, 0x5Au);  // SDR00 TX = 0x5A
    m.bus.TickDevices(0, 64, 0, 0, false, false);
    EXPECT_EQ(m.bus.ReadCpu(0xFFF12u), 0x5Au);  // SDR01 RX received 0x5A via loopback

    // ADC channel 3 = 0x2AB -> ADCR = 0x2AB << 6 = 0xAAC0
    m.adc.SetChannelVoltage(3, 0x02ABu);
    m.bus.WriteCpu(0xFFF31u, 0x03u);  // ADS = ch 3
    m.bus.WriteCpu(0xFFF30u, 0x81u);  // ADM0: ADCS=1 | ADCE=1
    m.bus.TickDevices(0, 40, 0, 0, false, false);
    const uint16_t adcr = static_cast<uint16_t>(m.bus.PeekByte(0xFFF1Eu)) |
                          (static_cast<uint16_t>(m.bus.PeekByte(0xFFF1Fu)) << 8);
    EXPECT_EQ(adcr, 0xAAC0u);

    // DMA ch0 copy 2 bytes from SFR (0xFFF00 P0) to RAM (0xFFE50)
    m.ports.SetExternalPortByte(0, 0x3Cu);
    m.bus.WriteCpu(0xFFFB0u, 0x00u);  // DSA0 = 0x00 (0xFFF00 = P0)
    m.bus.WriteCpu(0xFFFB2u, 0x50u);  // DRA0L
    m.bus.WriteCpu(0xFFFB3u, 0xFEu);  // DRA0H -> 0xFFE50
    m.bus.WriteCpu(0xFFFB6u, 0x01u);  // DBC0L = 1
    m.bus.WriteCpu(0xFFFB7u, 0x00u);
    m.bus.WriteCpu(0xFFFBCu, 0x80u);  // DRC0 DST = 1
    m.bus.WriteCpu(0xFFFBAu, 0x80u);  // DMC0 STG = 1 trigger
    EXPECT_EQ(m.bus.PeekByte(0xFFE50u), 0x3Cu);
}

void TestDisasmAndGdbRsp() {
    auto m = MakeMachine();
    WriteBytes(m, 0x12340u, { 0x11, 0x8F, 0x78, 0x56 });  // mov a, es:!0x5678
    const auto d1 = rl78::DisassembleAt(m.bus, 0x12340u);
    EXPECT_TRUE(d1.valid);
    EXPECT_EQ(d1.length, 4u);
    EXPECT_TRUE(d1.has_es);
    EXPECT_STREQ(d1.mnemonic, "mov");

    rl78::Debugger dbg(&m, 23946);
    EXPECT_STREQ(dbg.ProcessPacket("qAttached"), "1");
    EXPECT_TRUE(dbg.ProcessPacket("qXfer:features:read:target.xml:0,1000").find("rl78") != std::string::npos);

    m.cpu.SetPC(0x12345u);
    EXPECT_STREQ(dbg.ProcessPacket("p0"), "45230100");
    EXPECT_STREQ(dbg.ProcessPacket("Z0,12340,1"), "OK");
    EXPECT_TRUE(m.cpu.HasBreakpoint(0x12340u));
    EXPECT_STREQ(dbg.ProcessPacket("z0,12340,1"), "OK");
    EXPECT_TRUE(!m.cpu.HasBreakpoint(0x12340u));
}

void TestFlashSelfProgrammingAndBootSwap() {
    auto m = MakeMachine();
    EXPECT_EQ(m.bus.PeekByte(0x0EFFF8u), 0xD7u);
    EXPECT_EQ(m.bus.PeekByte(0x0EFFD0u), 0xFFu);
    EXPECT_EQ(m.bus.PeekByte(0x0EFFD1u), 0x07u);  // 512 KB -> 0x07FF

    // PFCMD protection test on FLPMC (0xFFFC4) and FLRST (0xF00C0)
    EXPECT_EQ(m.flash.GetFlpmc(), 0x08u);
    m.bus.WriteCpu(0xFFFC4u, 0x1Du);  // rejected without PFCMD unlock
    EXPECT_EQ(m.flash.GetFlpmc(), 0x08u);
    m.bus.WriteCpu(0xFFFC0u, 0xA5u);
    m.bus.WriteCpu(0xFFFC4u, 0x1Du);
    m.bus.WriteCpu(0xFFFC4u, 0x00u);  // broken complement
    m.bus.WriteCpu(0xFFFC4u, 0x1Du);
    EXPECT_EQ(m.flash.GetFlpmc(), 0x08u);

    m.bus.WriteCpu(0xFFFC0u, 0xA5u);
    m.bus.WriteCpu(0xFFFC4u, 0x1Du);
    m.bus.WriteCpu(0xFFFC4u, static_cast<uint8_t>(~0x1Du));
    m.bus.WriteCpu(0xFFFC4u, 0x1Du);
    EXPECT_EQ(m.flash.GetFlpmc(), 0x1Du);

    m.bus.WriteCpu(0xF00C0u, 0x80u);  // rejected without PFCMD unlock
    EXPECT_EQ(m.flash.GetFlrst(), 0x00u);
    m.bus.WriteCpu(0xFFFC0u, 0xA5u);
    m.bus.WriteCpu(0xF00C0u, 0x80u);
    m.bus.WriteCpu(0xF00C0u, static_cast<uint8_t>(~0x80u));
    m.bus.WriteCpu(0xF00C0u, 0x80u);
    EXPECT_EQ(m.flash.GetFlrst(), 0x80u);

    // Dual boot clusters + payload + FSL ROM calls executed by real RL78 code
    WriteBytes(m, 0x00000u, { 0x00, 0x03 });  // Cluster 0 reset vector = 0x0300
    WriteBytes(m, 0x01000u, { 0x00, 0x25 });  // Cluster 1 reset vector = 0x2500
    WriteBytes(m, 0x04000u, { 0xAA, 0x55, 0xAA, 0x55 });  // block 0x10 non-blank

    for (uint8_t i = 0; i < 16u; ++i) {
        m.bus.PokeByte(0xFD510u + i, static_cast<uint8_t>(0xA0u + i));
    }

    // Program at 0x02500 (target of Cluster 1 after boot swap + BRK1 reset)
    WriteBytes(m, 0x02500u, { 0x51, 0x42 });  // mov a, #42h

    // Helper code at 0x02000 calling FSL ROM at 0x0EFFF8 for 0x00,0x08,0x03,0x04,0x09,0x0A + BRK1
    WriteBytes(m, 0x02000u, {
        0x61, 0xFF,                         // sel rb3
        0xCF, 0x04, 0x08, 0x10,             // mov !0xF0804, #0x10 (FD510 lo)
        0xCF, 0x05, 0x08, 0xD5,             // mov !0xF0805, #0xD5 (FD510 hi)
        0x52, 0x00,                         // mov c, #0x00 (FSL_Init)
        0xFC, 0xF8, 0xFF, 0x0E,             // call !!0x0EFFF8
        0xCF, 0x03, 0x08, 0x10,             // mov !0xF0803, #0x10 (block 0x10)
        0xCF, 0x04, 0x08, 0x00,             // mov !0xF0804, #0x00 (block_hi = 0)
        0x52, 0x08,                         // mov c, #0x08 (FSL_BlankCheck -> 0x1B)
        0xFC, 0xF8, 0xFF, 0x0E,             // call !!0x0EFFF8
        0x52, 0x03,                         // mov c, #0x03 (FSL_Erase block 0x10)
        0xFC, 0xF8, 0xFF, 0x0E,             // call !!0x0EFFF8
        0x52, 0x08,                         // mov c, #0x08 (FSL_BlankCheck -> 0x00)
        0xFC, 0xF8, 0xFF, 0x0E,             // call !!0x0EFFF8
        0xCF, 0x00, 0x08, 0x00,             // mov !0xF0800, #0x00
        0xCF, 0x01, 0x08, 0x40,             // mov !0xF0801, #0x40
        0xCF, 0x02, 0x08, 0x00,             // mov !0xF0802, #0x00 -> addr 0x004000
        0xCF, 0x03, 0x08, 0x04,             // mov !0xF0803, #0x04 (4 words = 16 bytes)
        0xCF, 0x04, 0x08, 0x10,             // mov !0xF0804, #0x10
        0xCF, 0x05, 0x08, 0xD5,             // mov !0xF0805, #0xD5 (src FD510)
        0x52, 0x04,                         // mov c, #0x04 (FSL_Write)
        0xFC, 0xF8, 0xFF, 0x0E,             // call !!0x0EFFF8
        0x52, 0x09,                         // mov c, #0x09 (FSL_GetBootFlag)
        0xFC, 0xF8, 0xFF, 0x0E,             // call !!0x0EFFF8
        0x52, 0x0A,                         // mov c, #0x0A (FSL_InvertBootFlag)
        0xFC, 0xF8, 0xFF, 0x0E,             // call !!0x0EFFF8
        0xFF                                // brk1 -> reset to swapped [0x00000]=0x2500
    });

    m.Reset(0x02000u);
    m.cpu.SetSP(0xFF00u);
    m.cpu.SetPMC(0x01u);
    m.cpu.stop_on_brk = false;

    // Run BlankCheck(non-blank) right after first call!!0x0EFFF8 + MOV + BlankCheck(call)
    m.cpu.AddBreakpoint(0x0201Eu);  // right after BlankCheck(block 0x10) returns
    m.RunSteps(100);
    EXPECT_EQ(m.cpu.GetPC(), 0x0201Eu);
    EXPECT_EQ(m.bus.PeekByte(0xFFEE3u), rl78::Rl78FlashCtrl::kFslErrBlankCheck);
    m.cpu.RemoveBreakpoint(0x0201Eu);

    // Run through Erase, second BlankCheck, Write, GetBootFlag, InvertBootFlag, and BRK1 reset
    bool reached_swapped_entry = false;
    for (int i = 0; i < 200; ++i) {
        m.Step(true);
        if (m.cpu.GetPC() == 0x02500u) {
            reached_swapped_entry = true;
            break;
        }
    }
    EXPECT_TRUE(reached_swapped_entry);
    EXPECT_TRUE(m.bus.IsBootSwapped());
    EXPECT_EQ(m.flash.GetBectl() & 0x01u, 0x01u);
    EXPECT_EQ(m.bus.PeekByte(0x00000u), 0x00u);
    EXPECT_EQ(m.bus.PeekByte(0x00001u), 0x25u);
    EXPECT_EQ(m.bus.PeekByte(0x01000u), 0x00u);
    EXPECT_EQ(m.bus.PeekByte(0x01001u), 0x03u);
    EXPECT_EQ(m.clock.GetResf(), 0x80u);  // RESF.IAWRF set by BRK1
    EXPECT_EQ(m.cpu.GetPSW(), 0x06u);
    EXPECT_EQ(m.cpu.GetES(), 0x0Fu);
    EXPECT_EQ(m.cpu.GetPMC(), 0x00u);
    EXPECT_EQ(m.flash.ErasedBlocks(), 1u);
    EXPECT_EQ(m.flash.ProgrammedBytes(), 16u);
    EXPECT_EQ(m.flash.FslCallCount(), 7u);
    for (uint8_t i = 0; i < 16u; ++i) {
        EXPECT_EQ(m.bus.PeekByte(0x04000u + i), static_cast<uint8_t>(0xA0u + i));
        EXPECT_EQ(m.bus.PeekByte(0xFD510u + i), (i == 0) ? 0x00u : static_cast<uint8_t>(0xA0u + i));
    }

    // Execute mov a, #42h at swapped entry 0x02500
    m.Step(true);
    EXPECT_EQ(m.cpu.ReadRegBank(rl78::REG_A, 0), 0x42u);

    std::string out;
    EXPECT_TRUE(m.ExecuteCommand("flash", out));
    EXPECT_TRUE(out.find("SWAPPED") != std::string::npos);
    EXPECT_TRUE(m.ExecuteCommand("flash swap", out));
    EXPECT_TRUE(!m.bus.IsBootSwapped());
    EXPECT_TRUE(out.find("NORMAL") != std::string::npos);
}

void TestTau1TickWakeAndPreemptiveSwitch() {
    auto m = MakeMachine();

    // Vector 0x0056 (INTTM10 / IF2H.1) -> ISR @ 0x03200
    WriteBytes(m, 0x00056u, { 0x00, 0x32 });

    // Pre-build a suspended Task 2 frame on Stack B (SP = 0xFD00 -> 0xFEFD00):
    // Resume PC = 0x02200, PSW = 0x86 (IE=1, ISP=3, RBS=0).
    m.bus.PokeByte(0xFE502u, 0x00u);
    m.bus.PokeByte(0xFE503u, 0xFDu);  // Task 2 saved SP = 0xFD00
    m.bus.PokeByte(0xFE500u, 0x00u);  // tick counter
    m.bus.PokeByte(0xFE504u, 0x00u);  // Task 2 sentinel
    m.bus.PokeByte(0xFFD00u, 0x00u);
    m.bus.PokeByte(0xFFD01u, 0x22u);
    m.bus.PokeByte(0xFFD02u, 0x00u);
    m.bus.PokeByte(0xFFD03u, 0x86u);

    // Task 1 @ 0x01000: configure 4-ch TAU1 ch0, start TS1.0, EI, then loop HALT
    WriteBytes(m, 0x01000u, {
        0x71, 0x10, 0xF0, 0x00,  // set1 !PER0.1
        0xCF, 0xDE, 0x01, 0xF0,  // mov !TPS1 (0xF01DE), #0xF0
        0xF6,                    // clrw ax
        0xBF, 0xC8, 0x01,        // movw !TMR10 (0xF01C8), ax
        0xCB, 0x70, 0x40, 0x00,  // movw TDR10 (0xFFF70), #0x0040
        0x71, 0x1B, 0xD1,        // clr1 IF2H.1
        0x71, 0x1B, 0xD5,        // clr1 MK2H.1
        0xE5, 0xDA, 0x01,        // oneb !TS1 (0xF01DA)
        0x71, 0x7A, 0xFA,        // ei
        0x61, 0xED,              // halt (@ 0x0101C)
        0xEF, 0xFC,              // br $-4
    });

    // Verify disassembler resolves 4-channel TAU1 SFR names cleanly
    const auto d_tps = rl78::DisassembleAt(m.bus, 0x01004u);
    EXPECT_TRUE(d_tps.operands.find("TPS1") != std::string::npos);
    const auto d_ts = rl78::DisassembleAt(m.bus, 0x01016u);
    EXPECT_TRUE(d_ts.operands.find("TS1") != std::string::npos);

    // INTTM10 ISR @ 0x03200: increment tick counter, swap SP to Task 2 frame, RETI
    WriteBytes(m, 0x03200u, {
        0xA0, 0x00, 0xE5,        // inc !0xFE500
        0xAF, 0x02, 0xE5,        // movw ax, !0xFE502
        0xBE, 0xF8,              // movw SP, ax
        0x61, 0xFC,              // reti
    });

    // Task 2 @ 0x02200: write sentinel 0xA5 to 0xFE504, stop TAU1 ch0 via TT1 (0xF01DC), BRK
    WriteBytes(m, 0x02200u, {
        0xCF, 0x04, 0xE5, 0xA5,  // mov !0xFE504, #0xA5
        0x71, 0x00, 0xDC, 0x01,  // set1 !TT1.0 (0xF01DC)
        0xFF,                    // brk
    });

    m.cpu.SetSP(0xFE40u);
    m.cpu.SetPC(0x01000u);
    const auto stop = m.RunSteps(500);
    EXPECT_EQ(static_cast<int>(stop.reason), static_cast<int>(rl78::StopReason::BreakInsn));
    EXPECT_EQ(m.bus.PeekByte(0xFE500u), 1u);
    EXPECT_EQ(m.bus.PeekByte(0xFE504u), 0xA5u);
    EXPECT_EQ(m.tau1.GetEnableMask(), 0x0000u);
    EXPECT_EQ(m.tau1.GetTps(), 0x00F0u);

    std::string out;
    EXPECT_TRUE(m.ExecuteCommand("timers", out));
    EXPECT_TRUE(out.find("TAU1 (4 ch):") != std::string::npos);
    EXPECT_TRUE(out.find("RTC:") != std::string::npos);
}

}  // namespace

int main() {
    TestResetBanksPswAndMirror();
    TestAluShiftsAndS3Math();
    TestEsPrefixCallsSkipsAndPushPsw();
    TestFourLevelInterruptsAndPeripherals();
    TestDisasmAndGdbRsp();
    TestFlashSelfProgrammingAndBootSwap();
    TestTau1TickWakeAndPreemptiveSwitch();

    if (g_failures == 0) {
        std::printf("[PASS] All rl78emu C++ tests passed.\n");
        return 0;
    }
    std::fprintf(stderr, "[FAIL] %d assertion(s) failed.\n", g_failures);
    return 1;
}
