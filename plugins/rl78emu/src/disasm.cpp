#include "disasm.h"

#include <cstdio>
#include <cstring>

namespace rl78 {

namespace {

const char *const kReg8Names[8] = { "x", "a", "c", "b", "e", "d", "l", "h" };
const char *const kReg16Names[4] = { "ax", "bc", "de", "hl" };
const char *const kAluNames[9] = { "add", "addc", "sub", "subc", "cmp", "and", "or", "xor", "xch" };

struct SfrEntry {
    uint32_t addr;
    const char *name;
};

const SfrEntry kSfrNames[] = {
    // 2nd SFR (0xF0000..0xF07FF)
    { 0xF0010u, "ADM2" }, { 0xF0011u, "ADUL" }, { 0xF0012u, "ADLL" }, { 0xF0013u, "ADTES" },
    { 0xF0030u, "PU0" },  { 0xF0031u, "PU1" },  { 0xF0033u, "PU3" },  { 0xF0034u, "PU4" },
    { 0xF0035u, "PU5" },  { 0xF0036u, "PU6" },  { 0xF0037u, "PU7" },  { 0xF0038u, "PU8" },
    { 0xF003Cu, "PU12" }, { 0xF003Eu, "PU14" },
    { 0xF0040u, "PIM0" }, { 0xF0041u, "PIM1" }, { 0xF0044u, "PIM4" }, { 0xF0045u, "PIM5" },
    { 0xF0050u, "POM0" }, { 0xF0051u, "POM1" }, { 0xF0054u, "POM4" }, { 0xF0055u, "POM5" },
    { 0xF0060u, "PMC0" }, { 0xF0063u, "PMC3" }, { 0xF006Au, "PMC10" }, { 0xF006Cu, "PMC12" }, { 0xF006Eu, "PMC14" },
    { 0xF0070u, "NFEN0" }, { 0xF0071u, "NFEN1" }, { 0xF0072u, "NFEN2" },
    { 0xF0073u, "ISC" },  { 0xF0074u, "TIS0" }, { 0xF0076u, "ADPC" }, { 0xF0077u, "PIOR" },
    { 0xF0078u, "IAWCTL" }, { 0xF007Du, "GDIDIS" },
    { 0xF0090u, "DFLCTL" },
    { 0xF00A0u, "HIOTRM" }, { 0xF00A8u, "HOCODIV" },
    { 0xF00C0u, "FLRST" },
    { 0xF00E0u, "MDCL" }, { 0xF00E2u, "MDCH" }, { 0xF00E8u, "MDUC" },
    { 0xF00F0u, "PER0" }, { 0xF00F3u, "OSMC" }, { 0xF00F4u, "RMC" }, { 0xF00F5u, "RPECTL" }, { 0xF00FEu, "BCDADJ" },
    { 0xF0100u, "SSR00" }, { 0xF0102u, "SSR01" }, { 0xF0104u, "SSR02" }, { 0xF0106u, "SSR03" },
    { 0xF0108u, "SIR00" }, { 0xF010Au, "SIR01" }, { 0xF010Cu, "SIR02" }, { 0xF010Eu, "SIR03" },
    { 0xF0110u, "SMR00" }, { 0xF0112u, "SMR01" }, { 0xF0114u, "SMR02" }, { 0xF0116u, "SMR03" },
    { 0xF0118u, "SCR00" }, { 0xF011Au, "SCR01" }, { 0xF011Cu, "SCR02" }, { 0xF011Eu, "SCR03" },
    { 0xF0120u, "SE0" },   { 0xF0122u, "SS0" },   { 0xF0124u, "ST0" },   { 0xF0126u, "SPS0" },
    { 0xF0128u, "SO0" },   { 0xF012Au, "SOE0" },  { 0xF0134u, "SOL0" },  { 0xF0138u, "SSC0" },
    { 0xF0140u, "SSR10" }, { 0xF0142u, "SSR11" }, { 0xF0144u, "SSR12" }, { 0xF0146u, "SSR13" },
    { 0xF0148u, "SIR10" }, { 0xF014Au, "SIR11" }, { 0xF014Cu, "SIR12" }, { 0xF014Eu, "SIR13" },
    { 0xF0150u, "SMR10" }, { 0xF0152u, "SMR11" }, { 0xF0154u, "SMR12" }, { 0xF0156u, "SMR13" },
    { 0xF0158u, "SCR10" }, { 0xF015Au, "SCR11" }, { 0xF015Cu, "SCR12" }, { 0xF015Eu, "SCR13" },
    { 0xF0160u, "SE1" },   { 0xF0162u, "SS1" },   { 0xF0164u, "ST1" },   { 0xF0166u, "SPS1" },
    { 0xF0168u, "SO1" },   { 0xF016Au, "SOE1" },  { 0xF0174u, "SOL1" },
    { 0xF0180u, "TCR00" }, { 0xF0182u, "TCR01" }, { 0xF0184u, "TCR02" }, { 0xF0186u, "TCR03" },
    { 0xF0188u, "TCR04" }, { 0xF018Au, "TCR05" }, { 0xF018Cu, "TCR06" }, { 0xF018Eu, "TCR07" },
    { 0xF0190u, "TMR00" }, { 0xF0192u, "TMR01" }, { 0xF0194u, "TMR02" }, { 0xF0196u, "TMR03" },
    { 0xF0198u, "TMR04" }, { 0xF019Au, "TMR05" }, { 0xF019Cu, "TMR06" }, { 0xF019Eu, "TMR07" },
    { 0xF01A0u, "TSR00" }, { 0xF01A2u, "TSR01" }, { 0xF01A4u, "TSR02" }, { 0xF01A6u, "TSR03" },
    { 0xF01A8u, "TSR04" }, { 0xF01AAu, "TSR05" }, { 0xF01ACu, "TSR06" }, { 0xF01AEu, "TSR07" },
    { 0xF01B0u, "TE0" },   { 0xF01B2u, "TS0" },   { 0xF01B4u, "TT0" },   { 0xF01B6u, "TPS0" },
    { 0xF01B8u, "TO0" },   { 0xF01BAu, "TOE0" },  { 0xF01BCu, "TOL0" },  { 0xF01BEu, "TOM0" },
    { 0xF0200u, "DSA2" },  { 0xF0201u, "DSA3" },  { 0xF0202u, "DRA2" },  { 0xF0204u, "DRA3" },
    { 0xF0206u, "DBC2" },  { 0xF0208u, "DBC3" },  { 0xF020Au, "DMC2" },  { 0xF020Bu, "DMC3" },
    { 0xF020Cu, "DRC2" },  { 0xF020Du, "DRC3" },
    { 0xF0230u, "IICCTL00" }, { 0xF0231u, "IICCTL01" }, { 0xF0232u, "IICWL0" }, { 0xF0233u, "IICWH0" }, { 0xF0234u, "SVA0" },

    // 1st SFR (0xFFF00..0xFFFFF)
    { 0xFFF00u, "P0" },    { 0xFFF01u, "P1" },    { 0xFFF02u, "P2" },    { 0xFFF03u, "P3" },
    { 0xFFF04u, "P4" },    { 0xFFF05u, "P5" },    { 0xFFF06u, "P6" },    { 0xFFF07u, "P7" },
    { 0xFFF08u, "P8" },    { 0xFFF09u, "P9" },    { 0xFFF0Au, "P10" },   { 0xFFF0Bu, "P11" },
    { 0xFFF0Cu, "P12" },   { 0xFFF0Du, "P13" },   { 0xFFF0Eu, "P14" },   { 0xFFF0Fu, "P15" },
    { 0xFFF10u, "SDR00" }, { 0xFFF12u, "SDR01" }, { 0xFFF14u, "SDR12" }, { 0xFFF16u, "SDR13" },
    { 0xFFF18u, "TDR00" }, { 0xFFF1Au, "TDR01" }, { 0xFFF1Eu, "ADCR" },  { 0xFFF1Fu, "ADCRH" },
    { 0xFFF20u, "PM0" },   { 0xFFF21u, "PM1" },   { 0xFFF22u, "PM2" },   { 0xFFF23u, "PM3" },
    { 0xFFF24u, "PM4" },   { 0xFFF25u, "PM5" },   { 0xFFF26u, "PM6" },   { 0xFFF27u, "PM7" },
    { 0xFFF28u, "PM8" },   { 0xFFF29u, "PM9" },   { 0xFFF2Au, "PM10" },  { 0xFFF2Bu, "PM11" },
    { 0xFFF2Cu, "PM12" },  { 0xFFF2Eu, "PM14" },  { 0xFFF2Fu, "PM15" },
    { 0xFFF30u, "ADM0" },  { 0xFFF31u, "ADS" },   { 0xFFF32u, "ADM1" },
    { 0xFFF37u, "KRM" },   { 0xFFF38u, "EGP0" },  { 0xFFF39u, "EGN0" },  { 0xFFF3Au, "EGP1" }, { 0xFFF3Bu, "EGN1" },
    { 0xFFF44u, "SDR02" }, { 0xFFF46u, "SDR03" }, { 0xFFF48u, "SDR10" }, { 0xFFF4Au, "SDR11" },
    { 0xFFF50u, "IICA0" }, { 0xFFF51u, "IICS0" }, { 0xFFF52u, "IICF0" },
    { 0xFFF64u, "TDR02" }, { 0xFFF66u, "TDR03" }, { 0xFFF68u, "TDR04" },
    { 0xFFF6Au, "TDR05" }, { 0xFFF6Cu, "TDR06" }, { 0xFFF6Eu, "TDR07" },
    { 0xFFF90u, "ITMC" },  { 0xFFF92u, "SEC" },   { 0xFFF93u, "MIN" },   { 0xFFF94u, "HOUR" },
    { 0xFFF95u, "WEEK" },  { 0xFFF96u, "DAY" },   { 0xFFF97u, "MONTH" }, { 0xFFF98u, "YEAR" },
    { 0xFFF99u, "SUBCUD" },{ 0xFFF9Au, "ALARMWM" },{ 0xFFF9Bu, "ALARMWH" },{ 0xFFF9Cu, "ALARMWW" },
    { 0xFFF9Du, "RTCC0" }, { 0xFFF9Eu, "RTCC1" },
    { 0xFFFA0u, "CMC" },   { 0xFFFA1u, "CSC" },   { 0xFFFA2u, "OSTC" },  { 0xFFFA3u, "OSTS" },
    { 0xFFFA4u, "CKC" },   { 0xFFFA5u, "CKS0" },  { 0xFFFA6u, "CKS1" },
    { 0xFFFA8u, "RESF" },  { 0xFFFA9u, "LVIM" },  { 0xFFFAAu, "LVIS" },  { 0xFFFABu, "WDTE" }, { 0xFFFACu, "CRCIN" },
    { 0xFFFB0u, "DSA0" },  { 0xFFFB1u, "DSA1" },  { 0xFFFB2u, "DRA0" },  { 0xFFFB4u, "DRA1" },
    { 0xFFFB6u, "DBC0" },  { 0xFFFB8u, "DBC1" },  { 0xFFFBAu, "DMC0" },  { 0xFFFBBu, "DMC1" },
    { 0xFFFBCu, "DRC0" },  { 0xFFFBDu, "DRC1" },
    { 0xFFFBEu, "BECTL" }, { 0xFFFC0u, "PFCMD" }, { 0xFFFC4u, "FLPMC" },
    { 0xFFFD0u, "IF2L" },  { 0xFFFD1u, "IF2H" },  { 0xFFFD2u, "IF3L" },
    { 0xFFFD4u, "MK2L" },  { 0xFFFD5u, "MK2H" },  { 0xFFFD6u, "MK3L" },
    { 0xFFFD8u, "PR02L" }, { 0xFFFD9u, "PR02H" }, { 0xFFFDAu, "PR03L" },
    { 0xFFFDCu, "PR12L" }, { 0xFFFDDu, "PR12H" }, { 0xFFFDEu, "PR13L" },
    { 0xFFFE0u, "IF0L" },  { 0xFFFE1u, "IF0H" },  { 0xFFFE2u, "IF1L" },  { 0xFFFE3u, "IF1H" },
    { 0xFFFE4u, "MK0L" },  { 0xFFFE5u, "MK0H" },  { 0xFFFE6u, "MK1L" },  { 0xFFFE7u, "MK1H" },
    { 0xFFFE8u, "PR00L" }, { 0xFFFE9u, "PR00H" }, { 0xFFFEAu, "PR01L" }, { 0xFFFEBu, "PR01H" },
    { 0xFFFECu, "PR10L" }, { 0xFFFEDu, "PR10H" }, { 0xFFFEEu, "PR11L" }, { 0xFFFEFu, "PR11H" },
    { 0xFFFF0u, "MDAL" },  { 0xFFFF2u, "MDAH" },  { 0xFFFF4u, "MDBH" },  { 0xFFFF6u, "MDBL" },
    { 0xFFFF8u, "SP" },    { 0xFFFFAu, "PSW" },   { 0xFFFFCu, "CS" },    { 0xFFFFDu, "ES" },
    { 0xFFFFEu, "PMC" },   { 0xFFFFFu, "MEM" },
};

std::string Hex2(uint8_t v) {
    char buf[16];
    std::snprintf(buf, sizeof(buf), "0x%02X", v);
    return buf;
}

std::string Hex4(uint16_t v) {
    char buf[16];
    std::snprintf(buf, sizeof(buf), "0x%04X", v);
    return buf;
}

std::string Hex5(uint32_t v) {
    char buf[16];
    std::snprintf(buf, sizeof(buf), "0x%05X", v & Rl78Bus::kAddressMask);
    return buf;
}

std::string FmtSfr(uint8_t sfr_off) {
    const uint32_t addr = Rl78Bus::ResolveSfr(sfr_off);
    if (const char *name = LookupSfrName(addr)) {
        return name;
    }
    return Hex5(addr);
}

std::string FmtSaddr(uint8_t saddr_off) {
    const uint32_t addr = Rl78Bus::ResolveSaddr(saddr_off);
    if (const char *name = LookupSfrName(addr)) {
        return name;
    }
    return Hex5(addr);
}

std::string FmtAddr16Data(uint16_t addr16, bool es) {
    if (es) {
        return "es:!" + Hex4(addr16);
    }
    const uint32_t near_ea = Rl78Bus::ResolveNear(addr16);
    if (const char *name = LookupSfrName(near_ea)) {
        return std::string("!") + name;
    }
    return "!" + Hex4(addr16);
}

struct Reader {
    const Rl78Bus &bus;
    DecodedInsn &out;
    uint32_t cursor;

    uint8_t U8() {
        const uint8_t b = bus.PeekByte(cursor);
        if (out.length < sizeof(out.bytes)) {
            out.bytes[out.length] = b;
        }
        ++out.length;
        cursor = (cursor + 1u) & Rl78Bus::kAddressMask;
        return b;
    }
    uint16_t U16() {
        const uint8_t lo = U8();
        const uint8_t hi = U8();
        return static_cast<uint16_t>(lo) | (static_cast<uint16_t>(hi) << 8);
    }
    uint32_t U20() {
        const uint8_t b0 = U8();
        const uint8_t b1 = U8();
        const uint8_t b2 = U8() & 0x0Fu;
        return static_cast<uint32_t>(b0) |
               (static_cast<uint32_t>(b1) << 8) |
               (static_cast<uint32_t>(b2) << 16);
    }
    uint32_t Rel8() {
        const int8_t d = static_cast<int8_t>(U8());
        return static_cast<uint32_t>(static_cast<int32_t>(cursor) + d) & Rl78Bus::kAddressMask;
    }
    uint32_t Rel16() {
        const int16_t d = static_cast<int16_t>(U16());
        return static_cast<uint32_t>(static_cast<int32_t>(cursor) + d) & Rl78Bus::kAddressMask;
    }
};

std::string EsPrefix(bool es, const std::string &expr) {
    return es ? ("es:" + expr) : expr;
}

}  // namespace

const char *LookupSfrName(uint32_t addr) {
    addr &= Rl78Bus::kAddressMask;
    for (const auto &e : kSfrNames) {
        if (e.addr == addr) {
            return e.name;
        }
    }
    return nullptr;
}

std::string DecodedInsn::Format() const {
    if (!valid) {
        char buf[32];
        std::snprintf(buf, sizeof(buf), "db 0x%02X", bytes[0]);
        return buf;
    }
    if (operands.empty()) {
        return mnemonic;
    }
    return mnemonic + " " + operands;
}

std::string DecodedInsn::FormatWithBytes() const {
    std::string hex;
    for (uint8_t i = 0; i < length; ++i) {
        char b[4];
        std::snprintf(b, sizeof(b), "%02X ", bytes[i]);
        hex += b;
    }
    while (hex.size() < 16) {
        hex.push_back(' ');
    }
    return hex + Format();
}

DecodedInsn DisassembleAt(const Rl78Bus &bus, uint32_t addr) {
    DecodedInsn ins;
    ins.addr = addr & Rl78Bus::kAddressMask;
    Reader r{bus, ins, ins.addr};

    uint8_t code = r.U8();
    if (code == 0x11u) {
        ins.has_es = true;
        code = r.U8();
    }
    const bool es = ins.has_es;
    const uint8_t lo = code & 0x0Fu;
    const uint8_t hi = (code >> 4) & 0x0Fu;

    auto set_tgt = [&](uint32_t tgt, bool branch, bool call, bool stop) {
        ins.has_target = true;
        ins.target_addr = tgt & Rl78Bus::kAddressMask;
        ins.is_branch = branch;
        ins.is_call = call;
        ins.is_stop_flow = stop;
    };

    if (lo >= 0xAu && hi <= 0x7u) {
        ins.mnemonic = kAluNames[hi];
        if (lo == 0xAu) {
            const std::string dst = FmtSaddr(r.U8());
            ins.operands = dst + ", #" + Hex2(r.U8());
        } else {
            std::string rhs;
            switch (lo) {
            case 0xBu: rhs = FmtSaddr(r.U8()); break;
            case 0xCu: rhs = "#" + Hex2(r.U8()); break;
            case 0xDu: rhs = EsPrefix(es, "[hl]"); break;
            case 0xEu: rhs = EsPrefix(es, "[hl+" + Hex2(r.U8()) + "]"); break;
            case 0xFu: rhs = FmtAddr16Data(r.U16(), es); break;
            }
            ins.operands = "a, " + rhs;
        }
        ins.valid = true;
        return ins;
    }

    if (code == 0x31u) {
        const uint8_t c2 = r.U8();
        const uint8_t c2_lo = c2 & 0x0Fu;
        const uint8_t c2_hi = (c2 >> 4) & 0x0Fu;
        if (c2_lo <= 5u) {
            static const char *const kBtNames[6] = { "btclr", "btclr", "bt", "bt", "bf", "bf" };
            ins.mnemonic = kBtNames[c2_lo];
            const uint8_t bit = c2_hi & 7u;
            std::string bstr = "." + std::to_string(bit);
            std::string op0;
            switch (c2 & 0x81u) {
            case 0x00u: op0 = FmtSaddr(r.U8()) + bstr; break;
            case 0x01u: op0 = "a" + bstr; break;
            case 0x80u: op0 = FmtSfr(r.U8()) + bstr; break;
            case 0x81u: op0 = EsPrefix(es, "[hl]") + bstr; break;
            }
            const uint32_t tgt = r.Rel8();
            ins.operands = op0 + ", $" + Hex5(tgt);
            set_tgt(tgt, true, false, false);
            ins.valid = true;
            return ins;
        }
        if (c2_lo >= 7u && c2_lo <= 0xBu && c2_hi >= 1u && c2_hi <= 7u) {
            static const char *const kShNames[5] = { "shl", "shl", "shl", "shr", "sar" };
            static const char *const kShRegs[5] = { "c", "b", "a", "a", "a" };
            ins.mnemonic = kShNames[c2_lo - 7u];
            ins.operands = std::string(kShRegs[c2_lo - 7u]) + ", #" + std::to_string(c2_hi);
            ins.valid = true;
            return ins;
        }
        if (c2_lo >= 0xCu && c2_hi >= 1u) {
            static const char *const kShwNames[4] = { "shlw", "shlw", "shrw", "sarw" };
            static const char *const kShwRegs[4] = { "bc", "ax", "ax", "ax" };
            ins.mnemonic = kShwNames[c2_lo - 0xCu];
            ins.operands = std::string(kShwRegs[c2_lo - 0xCu]) + ", #" + std::to_string(c2_hi);
            ins.valid = true;
            return ins;
        }
        ins.valid = false;
        return ins;
    }

    if (code == 0x61u) {
        const uint8_t c2 = r.U8();
        const uint8_t c2_lo = c2 & 0x0Fu;
        const uint8_t c2_hi = (c2 >> 4) & 0x0Fu;
        if (c2_hi <= 7u && c2_lo <= 7u) {
            ins.mnemonic = kAluNames[c2_hi];
            ins.operands = std::string(kReg8Names[c2_lo]) + ", a";
            ins.valid = true;
            return ins;
        }
        if ((c2_hi <= 7u && c2_lo == 8u) || (c2_hi <= 8u && c2_lo >= 0xAu)) {
            ins.mnemonic = kAluNames[c2_hi];
            ins.operands = std::string("a, ") + kReg8Names[c2_lo & 7u];
            ins.valid = true;
            return ins;
        }
        if (c2_hi >= 8u && c2_lo >= 4u && c2_lo <= 7u) {
            const uint32_t vec = 0x80u | ((c2_lo & 3u) << 4) | ((c2_hi & 7u) << 1);
            ins.mnemonic = "callt";
            ins.operands = "[" + Hex4(static_cast<uint16_t>(vec)) + "]";
            ins.is_call = true;
            const uint16_t tgt = static_cast<uint16_t>(bus.PeekByte(vec)) |
                                 (static_cast<uint16_t>(bus.PeekByte(vec + 1u)) << 8);
            set_tgt(tgt, false, true, false);
            ins.valid = true;
            return ins;
        }
        if ((c2_lo == 0u || c2_lo == 2u) && c2_hi >= 8u) {
            ins.mnemonic = kAluNames[c2_hi & 7u];
            ins.operands = std::string("a, ") + EsPrefix(es, (c2_lo == 0u) ? "[hl+b]" : "[hl+c]");
            ins.valid = true;
            return ins;
        }

        switch (c2) {
        case 0x09u: ins.mnemonic = "addw"; ins.operands = "ax, " + EsPrefix(es, "[hl+" + Hex2(r.U8()) + "]"); break;
        case 0x29u: ins.mnemonic = "subw"; ins.operands = "ax, " + EsPrefix(es, "[hl+" + Hex2(r.U8()) + "]"); break;
        case 0x49u: ins.mnemonic = "cmpw"; ins.operands = "ax, " + EsPrefix(es, "[hl+" + Hex2(r.U8()) + "]"); break;
        case 0x59u: ins.mnemonic = "inc";  ins.operands = EsPrefix(es, "[hl+" + Hex2(r.U8()) + "]"); break;
        case 0x69u: ins.mnemonic = "dec";  ins.operands = EsPrefix(es, "[hl+" + Hex2(r.U8()) + "]"); break;
        case 0x79u: ins.mnemonic = "incw"; ins.operands = EsPrefix(es, "[hl+" + Hex2(r.U8()) + "]"); break;
        case 0x89u: ins.mnemonic = "decw"; ins.operands = EsPrefix(es, "[hl+" + Hex2(r.U8()) + "]"); break;
        case 0xC3u: { const uint32_t t = r.Rel8(); ins.mnemonic = "bh";  ins.operands = "$" + Hex5(t); set_tgt(t, true, false, false); break; }
        case 0xD3u: { const uint32_t t = r.Rel8(); ins.mnemonic = "bnh"; ins.operands = "$" + Hex5(t); set_tgt(t, true, false, false); break; }
        case 0xE3u: ins.mnemonic = "skh";  ins.is_skip = true; break;
        case 0xF3u: ins.mnemonic = "sknh"; ins.is_skip = true; break;
        case 0xC8u: ins.mnemonic = "skc";  ins.is_skip = true; break;
        case 0xD8u: ins.mnemonic = "sknc"; ins.is_skip = true; break;
        case 0xE8u: ins.mnemonic = "skz";  ins.is_skip = true; break;
        case 0xF8u: ins.mnemonic = "sknz"; ins.is_skip = true; break;
        case 0xA8u: ins.mnemonic = "xch";  ins.operands = "a, " + FmtSaddr(r.U8()); break;
        case 0xB8u: ins.mnemonic = "mov";  ins.operands = "es, " + FmtSaddr(r.U8()); break;
        case 0xA9u: ins.mnemonic = "xch";  ins.operands = "a, " + EsPrefix(es, "[hl+c]"); break;
        case 0xB9u: ins.mnemonic = "xch";  ins.operands = "a, " + EsPrefix(es, "[hl+b]"); break;
        case 0xAAu: ins.mnemonic = "xch";  ins.operands = "a, " + FmtAddr16Data(r.U16(), es); break;
        case 0xABu: ins.mnemonic = "xch";  ins.operands = "a, " + FmtSfr(r.U8()); break;
        case 0xACu: ins.mnemonic = "xch";  ins.operands = "a, " + EsPrefix(es, "[hl]"); break;
        case 0xADu: ins.mnemonic = "xch";  ins.operands = "a, " + EsPrefix(es, "[hl+" + Hex2(r.U8()) + "]"); break;
        case 0xAEu: ins.mnemonic = "xch";  ins.operands = "a, " + EsPrefix(es, "[de]"); break;
        case 0xAFu: ins.mnemonic = "xch";  ins.operands = "a, " + EsPrefix(es, "[de+" + Hex2(r.U8()) + "]"); break;
        case 0xC9u: ins.mnemonic = "mov";  ins.operands = "a, " + EsPrefix(es, "[hl+b]"); break;
        case 0xD9u: ins.mnemonic = "mov";  ins.operands = EsPrefix(es, "[hl+b]") + ", a"; break;
        case 0xE9u: ins.mnemonic = "mov";  ins.operands = "a, " + EsPrefix(es, "[hl+c]"); break;
        case 0xF9u: ins.mnemonic = "mov";  ins.operands = EsPrefix(es, "[hl+c]") + ", a"; break;
        case 0xCAu: case 0xDAu: case 0xEAu: case 0xFAu:
            ins.mnemonic = "call"; ins.operands = kReg16Names[c2_hi & 3u]; ins.is_call = true; break;
        case 0xCBu: ins.mnemonic = "br";    ins.operands = "ax"; ins.is_branch = true; ins.is_stop_flow = true; break;
        case 0xDBu: ins.mnemonic = "ror";   ins.operands = "a, #1"; break;
        case 0xEBu: ins.mnemonic = "rol";   ins.operands = "a, #1"; break;
        case 0xFBu: ins.mnemonic = "rorc";  ins.operands = "a, #1"; break;
        case 0xCCu: ins.mnemonic = "brk";   ins.is_stop_flow = true; break;
        case 0xDCu: ins.mnemonic = "rolc";  ins.operands = "a, #1"; break;
        case 0xECu: ins.mnemonic = "retb";  ins.is_stop_flow = true; break;
        case 0xFCu: ins.mnemonic = "reti";  ins.is_stop_flow = true; break;
        case 0xCDu: ins.mnemonic = "pop";   ins.operands = "psw"; break;
        case 0xDDu: ins.mnemonic = "push";  ins.operands = "psw"; break;
        case 0xEDu: ins.mnemonic = "halt";  break;
        case 0xFDu: ins.mnemonic = "stop";  break;
        case 0xCEu: ins.mnemonic = "movs";  ins.operands = EsPrefix(es, "[hl+" + Hex2(r.U8()) + "]") + ", x"; break;
        case 0xDEu: ins.mnemonic = "cmps";  ins.operands = "x, " + EsPrefix(es, "[hl+" + Hex2(r.U8()) + "]"); break;
        case 0xEEu: ins.mnemonic = "rolwc"; ins.operands = "ax, #1"; break;
        case 0xFEu: ins.mnemonic = "rolwc"; ins.operands = "bc, #1"; break;
        case 0xCFu: ins.mnemonic = "sel";   ins.operands = "rb0"; break;
        case 0xDFu: ins.mnemonic = "sel";   ins.operands = "rb1"; break;
        case 0xEFu: ins.mnemonic = "sel";   ins.operands = "rb2"; break;
        case 0xFFu: ins.mnemonic = "sel";   ins.operands = "rb3"; break;
        default: ins.valid = false; return ins;
        }
        ins.valid = true;
        return ins;
    }

    if (code == 0x71u) {
        const uint8_t c2 = r.U8();
        const uint8_t c2_lo = c2 & 0x0Fu;
        const uint8_t c2_hi = (c2 >> 4) & 0x0Fu;
        if (c2_hi >= 8u && c2_lo == 0u) {
            if (c2_hi == 8u) { ins.mnemonic = "set1"; ins.operands = "cy"; ins.valid = true; return ins; }
            if (c2_hi == 0xCu) { ins.mnemonic = "not1"; ins.operands = "cy"; ins.valid = true; return ins; }
            ins.valid = false;
            return ins;
        }
        if (c2_hi >= 8u && c2_lo == 8u) {
            if (c2_hi == 8u) { ins.mnemonic = "clr1"; ins.operands = "cy"; ins.valid = true; return ins; }
            ins.valid = false;
            return ins;
        }
        static const char *const kBitNames[16] = {
            "set1", "mov1", "set1", "clr1", "mov1", "and1", "or1", "xor1",
            "clr1", "mov1", "set1", "clr1", "mov1", "and1", "or1", "xor1"
        };
        const std::string bstr = "." + std::to_string(c2_hi & 7u);
        ins.mnemonic = kBitNames[c2_lo];
        switch (c2 & 0x8Fu) {
        case 0x00u: case 0x08u: ins.operands = FmtAddr16Data(r.U16(), es) + bstr; break;
        case 0x01u: ins.operands = FmtSaddr(r.U8()) + bstr + ", cy"; break;
        case 0x02u: case 0x03u: ins.operands = FmtSaddr(r.U8()) + bstr; break;
        case 0x04u: case 0x05u: case 0x06u: case 0x07u:
            ins.operands = "cy, " + FmtSaddr(r.U8()) + bstr; break;
        case 0x81u: ins.operands = EsPrefix(es, "[hl]") + bstr + ", cy"; break;
        case 0x82u: case 0x83u: ins.operands = EsPrefix(es, "[hl]") + bstr; break;
        case 0x84u: case 0x85u: case 0x86u: case 0x87u:
            ins.operands = "cy, " + EsPrefix(es, "[hl]") + bstr; break;
        case 0x09u: ins.operands = FmtSfr(r.U8()) + bstr + ", cy"; break;
        case 0x0Au: case 0x0Bu: {
            const uint8_t sfr = r.U8();
            if ((c2_hi & 7u) == 7u && sfr == 0xFAu) {
                ins.mnemonic = (c2_lo == 0x0Au) ? "ei" : "di";
                ins.operands.clear();
            } else {
                ins.operands = FmtSfr(sfr) + bstr;
            }
            break;
        }
        case 0x0Cu: case 0x0Du: case 0x0Eu: case 0x0Fu:
            ins.operands = "cy, " + FmtSfr(r.U8()) + bstr; break;
        case 0x89u: ins.operands = "a" + bstr + ", cy"; break;
        case 0x8Au: case 0x8Bu: ins.operands = "a" + bstr; break;
        case 0x8Cu: case 0x8Du: case 0x8Eu: case 0x8Fu:
            ins.operands = "cy, a" + bstr; break;
        default: ins.valid = false; return ins;
        }
        ins.valid = true;
        return ins;
    }

    switch (code) {
    case 0x00u: ins.mnemonic = "nop"; break;
    case 0x01u: ins.mnemonic = "addw"; ins.operands = "ax, ax"; break;
    case 0x02u: ins.mnemonic = "addw"; ins.operands = "ax, " + FmtAddr16Data(r.U16(), es); break;
    case 0x03u: ins.mnemonic = "addw"; ins.operands = "ax, bc"; break;
    case 0x04u: ins.mnemonic = "addw"; ins.operands = "ax, #" + Hex4(r.U16()); break;
    case 0x05u: ins.mnemonic = "addw"; ins.operands = "ax, de"; break;
    case 0x06u: ins.mnemonic = "addw"; ins.operands = "ax, " + FmtSaddr(r.U8()); break;
    case 0x07u: ins.mnemonic = "addw"; ins.operands = "ax, hl"; break;
    case 0x08u: ins.mnemonic = "xch";  ins.operands = "a, x"; break;
    case 0x09u: ins.mnemonic = "mov";  ins.operands = "a, " + EsPrefix(es, Hex4(r.U16()) + "[b]"); break;
    case 0x10u: ins.mnemonic = "addw"; ins.operands = "sp, #" + Hex2(r.U8()); break;
    case 0x12u: ins.mnemonic = "movw"; ins.operands = "bc, ax"; break;
    case 0x13u: ins.mnemonic = "movw"; ins.operands = "ax, bc"; break;
    case 0x14u: ins.mnemonic = "movw"; ins.operands = "de, ax"; break;
    case 0x15u: ins.mnemonic = "movw"; ins.operands = "ax, de"; break;
    case 0x16u: ins.mnemonic = "movw"; ins.operands = "hl, ax"; break;
    case 0x17u: ins.mnemonic = "movw"; ins.operands = "ax, hl"; break;
    case 0x18u: ins.mnemonic = "mov";  ins.operands = EsPrefix(es, Hex4(r.U16()) + "[b]") + ", a"; break;
    case 0x19u: { const std::string w = EsPrefix(es, Hex4(r.U16()) + "[b]"); ins.mnemonic = "mov"; ins.operands = w + ", #" + Hex2(r.U8()); break; }
    case 0x20u: ins.mnemonic = "subw"; ins.operands = "sp, #" + Hex2(r.U8()); break;
    case 0x22u: ins.mnemonic = "subw"; ins.operands = "ax, " + FmtAddr16Data(r.U16(), es); break;
    case 0x23u: ins.mnemonic = "subw"; ins.operands = "ax, bc"; break;
    case 0x24u: ins.mnemonic = "subw"; ins.operands = "ax, #" + Hex4(r.U16()); break;
    case 0x25u: ins.mnemonic = "subw"; ins.operands = "ax, de"; break;
    case 0x26u: ins.mnemonic = "subw"; ins.operands = "ax, " + FmtSaddr(r.U8()); break;
    case 0x27u: ins.mnemonic = "subw"; ins.operands = "ax, hl"; break;
    case 0x28u: ins.mnemonic = "mov";  ins.operands = EsPrefix(es, Hex4(r.U16()) + "[c]") + ", a"; break;
    case 0x29u: ins.mnemonic = "mov";  ins.operands = "a, " + EsPrefix(es, Hex4(r.U16()) + "[c]"); break;
    case 0x30u: ins.mnemonic = "movw"; ins.operands = "ax, #" + Hex4(r.U16()); break;
    case 0x32u: ins.mnemonic = "movw"; ins.operands = "bc, #" + Hex4(r.U16()); break;
    case 0x33u: ins.mnemonic = "xchw"; ins.operands = "ax, bc"; break;
    case 0x34u: ins.mnemonic = "movw"; ins.operands = "de, #" + Hex4(r.U16()); break;
    case 0x35u: ins.mnemonic = "xchw"; ins.operands = "ax, de"; break;
    case 0x36u: ins.mnemonic = "movw"; ins.operands = "hl, #" + Hex4(r.U16()); break;
    case 0x37u: ins.mnemonic = "xchw"; ins.operands = "ax, hl"; break;
    case 0x38u: { const std::string w = EsPrefix(es, Hex4(r.U16()) + "[c]"); ins.mnemonic = "mov"; ins.operands = w + ", #" + Hex2(r.U8()); break; }
    case 0x39u: { const std::string w = EsPrefix(es, Hex4(r.U16()) + "[bc]"); ins.mnemonic = "mov"; ins.operands = w + ", #" + Hex2(r.U8()); break; }
    case 0x40u: { const std::string d = FmtAddr16Data(r.U16(), es); ins.mnemonic = "cmp"; ins.operands = d + ", #" + Hex2(r.U8()); break; }
    case 0x41u: ins.mnemonic = "mov";  ins.operands = "es, #" + Hex2(r.U8()); break;
    case 0x42u: ins.mnemonic = "cmpw"; ins.operands = "ax, " + FmtAddr16Data(r.U16(), es); break;
    case 0x43u: ins.mnemonic = "cmpw"; ins.operands = "ax, bc"; break;
    case 0x44u: ins.mnemonic = "cmpw"; ins.operands = "ax, #" + Hex4(r.U16()); break;
    case 0x45u: ins.mnemonic = "cmpw"; ins.operands = "ax, de"; break;
    case 0x46u: ins.mnemonic = "cmpw"; ins.operands = "ax, " + FmtSaddr(r.U8()); break;
    case 0x47u: ins.mnemonic = "cmpw"; ins.operands = "ax, hl"; break;
    case 0x48u: ins.mnemonic = "mov";  ins.operands = EsPrefix(es, Hex4(r.U16()) + "[bc]") + ", a"; break;
    case 0x49u: ins.mnemonic = "mov";  ins.operands = "a, " + EsPrefix(es, Hex4(r.U16()) + "[bc]"); break;
    case 0x50u: case 0x51u: case 0x52u: case 0x53u:
    case 0x54u: case 0x55u: case 0x56u: case 0x57u:
        ins.mnemonic = "mov"; ins.operands = std::string(kReg8Names[lo]) + ", #" + Hex2(r.U8()); break;
    case 0x58u: ins.mnemonic = "movw"; ins.operands = EsPrefix(es, Hex4(r.U16()) + "[b]") + ", ax"; break;
    case 0x59u: ins.mnemonic = "movw"; ins.operands = "ax, " + EsPrefix(es, Hex4(r.U16()) + "[b]"); break;
    case 0x60u: case 0x62u: case 0x63u:
    case 0x64u: case 0x65u: case 0x66u: case 0x67u:
        ins.mnemonic = "mov"; ins.operands = std::string("a, ") + kReg8Names[lo]; break;
    case 0x68u: ins.mnemonic = "movw"; ins.operands = EsPrefix(es, Hex4(r.U16()) + "[c]") + ", ax"; break;
    case 0x69u: ins.mnemonic = "movw"; ins.operands = "ax, " + EsPrefix(es, Hex4(r.U16()) + "[c]"); break;
    case 0x70u: case 0x72u: case 0x73u:
    case 0x74u: case 0x75u: case 0x76u: case 0x77u:
        ins.mnemonic = "mov"; ins.operands = std::string(kReg8Names[lo]) + ", a"; break;
    case 0x78u: ins.mnemonic = "movw"; ins.operands = EsPrefix(es, Hex4(r.U16()) + "[bc]") + ", ax"; break;
    case 0x79u: ins.mnemonic = "movw"; ins.operands = "ax, " + EsPrefix(es, Hex4(r.U16()) + "[bc]"); break;
    case 0x80u: case 0x81u: case 0x82u: case 0x83u:
    case 0x84u: case 0x85u: case 0x86u: case 0x87u:
        ins.mnemonic = "inc"; ins.operands = kReg8Names[lo]; break;
    case 0x88u: ins.mnemonic = "mov"; ins.operands = "a, [sp+" + Hex2(r.U8()) + "]"; break;
    case 0x89u: ins.mnemonic = "mov"; ins.operands = "a, " + EsPrefix(es, "[de]"); break;
    case 0x8Au: ins.mnemonic = "mov"; ins.operands = "a, " + EsPrefix(es, "[de+" + Hex2(r.U8()) + "]"); break;
    case 0x8Bu: ins.mnemonic = "mov"; ins.operands = "a, " + EsPrefix(es, "[hl]"); break;
    case 0x8Cu: ins.mnemonic = "mov"; ins.operands = "a, " + EsPrefix(es, "[hl+" + Hex2(r.U8()) + "]"); break;
    case 0x8Du: ins.mnemonic = "mov"; ins.operands = "a, " + FmtSaddr(r.U8()); break;
    case 0x8Eu: ins.mnemonic = "mov"; ins.operands = "a, " + FmtSfr(r.U8()); break;
    case 0x8Fu: ins.mnemonic = "mov"; ins.operands = "a, " + FmtAddr16Data(r.U16(), es); break;
    case 0x90u: case 0x91u: case 0x92u: case 0x93u:
    case 0x94u: case 0x95u: case 0x96u: case 0x97u:
        ins.mnemonic = "dec"; ins.operands = kReg8Names[lo]; break;
    case 0x98u: ins.mnemonic = "mov"; ins.operands = "[sp+" + Hex2(r.U8()) + "], a"; break;
    case 0x99u: ins.mnemonic = "mov"; ins.operands = EsPrefix(es, "[de]") + ", a"; break;
    case 0x9Au: ins.mnemonic = "mov"; ins.operands = EsPrefix(es, "[de+" + Hex2(r.U8()) + "]") + ", a"; break;
    case 0x9Bu: ins.mnemonic = "mov"; ins.operands = EsPrefix(es, "[hl]") + ", a"; break;
    case 0x9Cu: ins.mnemonic = "mov"; ins.operands = EsPrefix(es, "[hl+" + Hex2(r.U8()) + "]") + ", a"; break;
    case 0x9Du: ins.mnemonic = "mov"; ins.operands = FmtSaddr(r.U8()) + ", a"; break;
    case 0x9Eu: ins.mnemonic = "mov"; ins.operands = FmtSfr(r.U8()) + ", a"; break;
    case 0x9Fu: ins.mnemonic = "mov"; ins.operands = FmtAddr16Data(r.U16(), es) + ", a"; break;
    case 0xA0u: ins.mnemonic = "inc";  ins.operands = FmtAddr16Data(r.U16(), es); break;
    case 0xB0u: ins.mnemonic = "dec";  ins.operands = FmtAddr16Data(r.U16(), es); break;
    case 0xA1u: ins.mnemonic = "incw"; ins.operands = "ax"; break;
    case 0xB1u: ins.mnemonic = "decw"; ins.operands = "ax"; break;
    case 0xA2u: ins.mnemonic = "incw"; ins.operands = FmtAddr16Data(r.U16(), es); break;
    case 0xB2u: ins.mnemonic = "decw"; ins.operands = FmtAddr16Data(r.U16(), es); break;
    case 0xA3u: ins.mnemonic = "incw"; ins.operands = "bc"; break;
    case 0xB3u: ins.mnemonic = "decw"; ins.operands = "bc"; break;
    case 0xA4u: ins.mnemonic = "inc";  ins.operands = FmtSaddr(r.U8()); break;
    case 0xB4u: ins.mnemonic = "dec";  ins.operands = FmtSaddr(r.U8()); break;
    case 0xA5u: ins.mnemonic = "incw"; ins.operands = "de"; break;
    case 0xB5u: ins.mnemonic = "decw"; ins.operands = "de"; break;
    case 0xA6u: ins.mnemonic = "incw"; ins.operands = FmtSaddr(r.U8()); break;
    case 0xB6u: ins.mnemonic = "decw"; ins.operands = FmtSaddr(r.U8()); break;
    case 0xA7u: ins.mnemonic = "incw"; ins.operands = "hl"; break;
    case 0xB7u: ins.mnemonic = "decw"; ins.operands = "hl"; break;
    case 0xA8u: ins.mnemonic = "movw"; ins.operands = "ax, [sp+" + Hex2(r.U8()) + "]"; break;
    case 0xB8u: ins.mnemonic = "movw"; ins.operands = "[sp+" + Hex2(r.U8()) + "], ax"; break;
    case 0xA9u: ins.mnemonic = "movw"; ins.operands = "ax, " + EsPrefix(es, "[de]"); break;
    case 0xB9u: ins.mnemonic = "movw"; ins.operands = EsPrefix(es, "[de]") + ", ax"; break;
    case 0xAAu: ins.mnemonic = "movw"; ins.operands = "ax, " + EsPrefix(es, "[de+" + Hex2(r.U8()) + "]"); break;
    case 0xBAu: ins.mnemonic = "movw"; ins.operands = EsPrefix(es, "[de+" + Hex2(r.U8()) + "]") + ", ax"; break;
    case 0xABu: ins.mnemonic = "movw"; ins.operands = "ax, " + EsPrefix(es, "[hl]"); break;
    case 0xBBu: ins.mnemonic = "movw"; ins.operands = EsPrefix(es, "[hl]") + ", ax"; break;
    case 0xACu: ins.mnemonic = "movw"; ins.operands = "ax, " + EsPrefix(es, "[hl+" + Hex2(r.U8()) + "]"); break;
    case 0xBCu: ins.mnemonic = "movw"; ins.operands = EsPrefix(es, "[hl+" + Hex2(r.U8()) + "]") + ", ax"; break;
    case 0xADu: ins.mnemonic = "movw"; ins.operands = "ax, " + FmtSaddr(r.U8()); break;
    case 0xBDu: ins.mnemonic = "movw"; ins.operands = FmtSaddr(r.U8()) + ", ax"; break;
    case 0xAEu: ins.mnemonic = "movw"; ins.operands = "ax, " + FmtSfr(r.U8()); break;
    case 0xBEu: ins.mnemonic = "movw"; ins.operands = FmtSfr(r.U8()) + ", ax"; break;
    case 0xAFu: ins.mnemonic = "movw"; ins.operands = "ax, " + FmtAddr16Data(r.U16(), es); break;
    case 0xBFu: ins.mnemonic = "movw"; ins.operands = FmtAddr16Data(r.U16(), es) + ", ax"; break;
    case 0xC0u: case 0xC2u: case 0xC4u: case 0xC6u:
        ins.mnemonic = "pop"; ins.operands = kReg16Names[lo >> 1]; break;
    case 0xC1u: case 0xC3u: case 0xC5u: case 0xC7u:
        ins.mnemonic = "push"; ins.operands = kReg16Names[lo >> 1]; break;
    case 0xC8u: { const std::string w = "[sp+" + Hex2(r.U8()) + "]"; ins.mnemonic = "mov"; ins.operands = w + ", #" + Hex2(r.U8()); break; }
    case 0xC9u: { const std::string w = FmtSaddr(r.U8()); ins.mnemonic = "movw"; ins.operands = w + ", #" + Hex4(r.U16()); break; }
    case 0xCAu: { const std::string w = EsPrefix(es, "[de+" + Hex2(r.U8()) + "]"); ins.mnemonic = "mov"; ins.operands = w + ", #" + Hex2(r.U8()); break; }
    case 0xCBu: { const std::string w = FmtSfr(r.U8()); ins.mnemonic = "movw"; ins.operands = w + ", #" + Hex4(r.U16()); break; }
    case 0xCCu: { const std::string w = EsPrefix(es, "[hl+" + Hex2(r.U8()) + "]"); ins.mnemonic = "mov"; ins.operands = w + ", #" + Hex2(r.U8()); break; }
    case 0xCDu: { const std::string w = FmtSaddr(r.U8()); ins.mnemonic = "mov"; ins.operands = w + ", #" + Hex2(r.U8()); break; }
    case 0xCEu: {
        const uint8_t sfr = r.U8();
        if (sfr == 0xFBu && !es) {
            const uint8_t ext = r.U8();
            switch (ext) {
            case 0x01u: ins.mnemonic = "mulhu"; break;
            case 0x02u: ins.mnemonic = "mulh"; break;
            case 0x03u: ins.mnemonic = "divhu"; break;
            case 0x0Bu: ins.mnemonic = "divwu"; break;
            case 0x05u: ins.mnemonic = "machu"; break;
            case 0x06u: ins.mnemonic = "mach"; break;
            default: ins.valid = false; return ins;
            }
        } else {
            const std::string w = FmtSfr(sfr);
            ins.mnemonic = "mov";
            ins.operands = w + ", #" + Hex2(r.U8());
        }
        break;
    }
    case 0xCFu: { const std::string w = FmtAddr16Data(r.U16(), es); ins.mnemonic = "mov"; ins.operands = w + ", #" + Hex2(r.U8()); break; }
    case 0xD0u: case 0xD1u: case 0xD2u: case 0xD3u:
        ins.mnemonic = "cmp0"; ins.operands = kReg8Names[lo]; break;
    case 0xD4u: ins.mnemonic = "cmp0"; ins.operands = FmtSaddr(r.U8()); break;
    case 0xD5u: ins.mnemonic = "cmp0"; ins.operands = FmtAddr16Data(r.U16(), es); break;
    case 0xD6u: ins.mnemonic = "mulu"; ins.operands = "x"; break;
    case 0xD7u: ins.mnemonic = "ret"; ins.is_stop_flow = true; break;
    case 0xD8u: ins.mnemonic = "mov"; ins.operands = "x, " + FmtSaddr(r.U8()); break;
    case 0xE8u: ins.mnemonic = "mov"; ins.operands = "b, " + FmtSaddr(r.U8()); break;
    case 0xF8u: ins.mnemonic = "mov"; ins.operands = "c, " + FmtSaddr(r.U8()); break;
    case 0xD9u: ins.mnemonic = "mov"; ins.operands = "x, " + FmtAddr16Data(r.U16(), es); break;
    case 0xE9u: ins.mnemonic = "mov"; ins.operands = "b, " + FmtAddr16Data(r.U16(), es); break;
    case 0xF9u: ins.mnemonic = "mov"; ins.operands = "c, " + FmtAddr16Data(r.U16(), es); break;
    case 0xDAu: ins.mnemonic = "movw"; ins.operands = "bc, " + FmtSaddr(r.U8()); break;
    case 0xEAu: ins.mnemonic = "movw"; ins.operands = "de, " + FmtSaddr(r.U8()); break;
    case 0xFAu: ins.mnemonic = "movw"; ins.operands = "hl, " + FmtSaddr(r.U8()); break;
    case 0xDBu: ins.mnemonic = "movw"; ins.operands = "bc, " + FmtAddr16Data(r.U16(), es); break;
    case 0xEBu: ins.mnemonic = "movw"; ins.operands = "de, " + FmtAddr16Data(r.U16(), es); break;
    case 0xFBu: ins.mnemonic = "movw"; ins.operands = "hl, " + FmtAddr16Data(r.U16(), es); break;
    case 0xDCu: { const uint32_t t = r.Rel8(); ins.mnemonic = "bc";  ins.operands = "$" + Hex5(t); set_tgt(t, true, false, false); break; }
    case 0xDDu: { const uint32_t t = r.Rel8(); ins.mnemonic = "bz";  ins.operands = "$" + Hex5(t); set_tgt(t, true, false, false); break; }
    case 0xDEu: { const uint32_t t = r.Rel8(); ins.mnemonic = "bnc"; ins.operands = "$" + Hex5(t); set_tgt(t, true, false, false); break; }
    case 0xDFu: { const uint32_t t = r.Rel8(); ins.mnemonic = "bnz"; ins.operands = "$" + Hex5(t); set_tgt(t, true, false, false); break; }
    case 0xECu: { const uint32_t t = r.U20();  ins.mnemonic = "br";  ins.operands = "!!" + Hex5(t); set_tgt(t, true, false, true); break; }
    case 0xEDu: { const uint16_t t = r.U16();  ins.mnemonic = "br";  ins.operands = "!" + Hex4(t);  set_tgt(t, true, false, true); break; }
    case 0xEEu: { const uint32_t t = r.Rel16();ins.mnemonic = "br";  ins.operands = "$!" + Hex5(t); set_tgt(t, true, false, true); break; }
    case 0xEFu: { const uint32_t t = r.Rel8(); ins.mnemonic = "br";  ins.operands = "$" + Hex5(t);  set_tgt(t, true, false, true); break; }
    case 0xE0u: case 0xE1u: case 0xE2u: case 0xE3u:
        ins.mnemonic = "oneb"; ins.operands = kReg8Names[lo]; break;
    case 0xE4u: ins.mnemonic = "oneb"; ins.operands = FmtSaddr(r.U8()); break;
    case 0xE5u: ins.mnemonic = "oneb"; ins.operands = FmtAddr16Data(r.U16(), es); break;
    case 0xE6u: ins.mnemonic = "onew"; ins.operands = "ax"; break;
    case 0xE7u: ins.mnemonic = "onew"; ins.operands = "bc"; break;
    case 0xF0u: case 0xF1u: case 0xF2u: case 0xF3u:
        ins.mnemonic = "clrb"; ins.operands = kReg8Names[lo]; break;
    case 0xF4u: ins.mnemonic = "clrb"; ins.operands = FmtSaddr(r.U8()); break;
    case 0xF5u: ins.mnemonic = "clrb"; ins.operands = FmtAddr16Data(r.U16(), es); break;
    case 0xF6u: ins.mnemonic = "clrw"; ins.operands = "ax"; break;
    case 0xF7u: ins.mnemonic = "clrw"; ins.operands = "bc"; break;
    case 0xFCu: { const uint32_t t = r.U20();  ins.mnemonic = "call"; ins.operands = "!!" + Hex5(t); set_tgt(t, false, true, false); break; }
    case 0xFDu: { const uint16_t t = r.U16();  ins.mnemonic = "call"; ins.operands = "!" + Hex4(t);  set_tgt(t, false, true, false); break; }
    case 0xFEu: { const uint32_t t = r.Rel16();ins.mnemonic = "call"; ins.operands = "$!" + Hex5(t); set_tgt(t, false, true, false); break; }
    case 0xFFu: ins.mnemonic = "brk1"; ins.is_stop_flow = true; break;
    default: ins.valid = false; return ins;
    }

    ins.valid = true;
    return ins;
}

}  // namespace rl78
