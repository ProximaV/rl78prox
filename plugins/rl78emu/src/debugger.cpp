#include "debugger.h"

#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <winsock2.h>
#include <ws2tcpip.h>
using socklen_t = int;
static inline void CloseSock(intptr_t s) {
    if (s != -1) {
        closesocket(static_cast<SOCKET>(s));
    }
}
static inline intptr_t InvalidSock() { return static_cast<intptr_t>(INVALID_SOCKET); }
#else
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <unistd.h>
static inline void CloseSock(intptr_t s) {
    if (s >= 0) {
        close(static_cast<int>(s));
    }
}
static inline intptr_t InvalidSock() { return -1; }
#endif

#include <algorithm>
#include <cctype>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <sstream>
#include <vector>

#include "log.h"
#include "machine.h"

namespace rl78 {

namespace {

#ifdef _WIN32
struct WinsockGuard {
    bool ok = false;
    WinsockGuard() {
        WSADATA wsa{};
        ok = (WSAStartup(MAKEWORD(2, 2), &wsa) == 0);
    }
    ~WinsockGuard() {
        if (ok) {
            WSACleanup();
        }
    }
};
#endif

inline uint8_t HexNibble(char c, bool *valid) {
    if (c >= '0' && c <= '9') return static_cast<uint8_t>(c - '0');
    if (c >= 'a' && c <= 'f') return static_cast<uint8_t>(c - 'a' + 10);
    if (c >= 'A' && c <= 'F') return static_cast<uint8_t>(c - 'A' + 10);
    *valid = false;
    return 0;
}

struct GdbRegDesc {
    const char *name;
    uint8_t bytes;
    const char *type;
};

constexpr GdbRegDesc kGdbRegs[] = {
    { "pc",    4, "code_ptr" },
    { "sp",    2, "data_ptr" },
    { "psw",   1, nullptr },
    { "cs",    1, nullptr },
    { "es",    1, nullptr },
    { "pmc",   1, nullptr },
    { "mem",   1, nullptr },
    { "ax",    2, nullptr },
    { "bc",    2, nullptr },
    { "de",    2, nullptr },
    { "hl",    2, nullptr },
    { "rb",    1, nullptr },
    { "macrl", 2, nullptr },
    { "macrh", 2, nullptr },
    { "if0l",  1, nullptr },
    { "if0h",  1, nullptr },
    { "if1l",  1, nullptr },
    { "if1h",  1, nullptr },
    { "mk0l",  1, nullptr },
    { "mk0h",  1, nullptr },
    { "mk1l",  1, nullptr },
    { "mk1h",  1, nullptr },
};
constexpr uint32_t kNumGdbRegs = static_cast<uint32_t>(sizeof(kGdbRegs) / sizeof(kGdbRegs[0]));

}  // namespace

Debugger::Debugger(Rl78Machine *machine_, int port_)
    : machine(machine_), port(port_) {}

Debugger::~Debugger() {
    Stop();
}

void Debugger::Stop() {
    stop_requested.store(true);
}

std::string Debugger::ToHexBytes(const uint8_t *data, size_t len) {
    static const char kHex[] = "0123456789abcdef";
    std::string out;
    out.reserve(len * 2);
    for (size_t i = 0; i < len; ++i) {
        out.push_back(kHex[(data[i] >> 4) & 0xFu]);
        out.push_back(kHex[data[i] & 0xFu]);
    }
    return out;
}

std::string Debugger::EncodeRegLE32(uint32_t val) {
    const uint8_t bytes[4] = {
        static_cast<uint8_t>(val & 0xFFu),
        static_cast<uint8_t>((val >> 8) & 0xFFu),
        static_cast<uint8_t>((val >> 16) & 0xFFu),
        static_cast<uint8_t>((val >> 24) & 0xFFu),
    };
    return ToHexBytes(bytes, 4);
}

std::string Debugger::EncodeRegLE16(uint16_t val) {
    const uint8_t bytes[2] = {
        static_cast<uint8_t>(val & 0xFFu),
        static_cast<uint8_t>((val >> 8) & 0xFFu),
    };
    return ToHexBytes(bytes, 2);
}

std::string Debugger::EncodeReg8(uint8_t val) {
    return ToHexBytes(&val, 1);
}

bool Debugger::DecodeRegLE(const std::string &hex, uint8_t bytes, uint32_t *out) {
    if (bytes == 0 || bytes > 4 || hex.size() < static_cast<size_t>(bytes) * 2) {
        return false;
    }
    bool valid = true;
    uint32_t v = 0;
    for (uint8_t i = 0; i < bytes; ++i) {
        const uint8_t hi = HexNibble(hex[i * 2], &valid);
        const uint8_t lo = HexNibble(hex[i * 2 + 1], &valid);
        if (!valid) return false;
        v |= static_cast<uint32_t>((hi << 4) | lo) << (i * 8u);
    }
    *out = v;
    return true;
}

std::string Debugger::HexDecodeString(const std::string &hex) {
    std::string out;
    out.reserve(hex.size() / 2);
    for (size_t i = 0; i + 1 < hex.size(); i += 2) {
        bool valid = true;
        const uint8_t ch = static_cast<uint8_t>((HexNibble(hex[i], &valid) << 4) | HexNibble(hex[i + 1], &valid));
        if (!valid) break;
        out.push_back(static_cast<char>(ch));
    }
    return out;
}

std::string Debugger::HexEncodeString(const std::string &text) {
    return ToHexBytes(reinterpret_cast<const uint8_t *>(text.data()), text.size());
}

uint8_t Debugger::Checksum(const std::string &payload) {
    uint8_t sum = 0;
    for (unsigned char c : payload) {
        sum = static_cast<uint8_t>(sum + c);
    }
    return sum;
}

uint8_t Debugger::GdbRegByteSize(uint32_t idx) const {
    return idx < kNumGdbRegs ? kGdbRegs[idx].bytes : 0;
}

uint32_t Debugger::ReadGdbReg(uint32_t idx) const {
    if (!machine || idx >= kNumGdbRegs) return 0;
    switch (idx) {
    case 0:  return machine->cpu.GetPC();
    case 1:  return machine->cpu.GetSP();
    case 2:  return machine->cpu.GetPSW();
    case 3:  return machine->cpu.GetCS();
    case 4:  return machine->cpu.GetES();
    case 5:  return machine->cpu.GetPMC();
    case 6:  return machine->cpu.GetMEM();
    case 7:  return machine->cpu.ReadRegPair(RP_AX);
    case 8:  return machine->cpu.ReadRegPair(RP_BC);
    case 9:  return machine->cpu.ReadRegPair(RP_DE);
    case 10: return machine->cpu.ReadRegPair(RP_HL);
    case 11: return machine->cpu.GetRB();
    case 12: return machine->cpu.GetMACRL();
    case 13: return machine->cpu.GetMACRH();
    default:
        return machine->intc.Peek(static_cast<uint32_t>(0xFFFE0u + (idx - 14u)));
    }
}

bool Debugger::WriteGdbReg(uint32_t idx, uint32_t val) {
    if (!machine || idx >= kNumGdbRegs) return false;
    switch (idx) {
    case 0:  machine->cpu.SetPC(val); return true;
    case 1:  machine->cpu.SetSP(static_cast<uint16_t>(val)); return true;
    case 2:  machine->cpu.SetPSW(static_cast<uint8_t>(val)); return true;
    case 3:  machine->cpu.SetCS(static_cast<uint8_t>(val)); return true;
    case 4:  machine->cpu.SetES(static_cast<uint8_t>(val)); return true;
    case 5:  machine->cpu.SetPMC(static_cast<uint8_t>(val)); return true;
    case 6:  machine->cpu.SetMEM(static_cast<uint8_t>(val)); return true;
    case 7:  machine->cpu.WriteRegPair(RP_AX, static_cast<uint16_t>(val)); return true;
    case 8:  machine->cpu.WriteRegPair(RP_BC, static_cast<uint16_t>(val)); return true;
    case 9:  machine->cpu.WriteRegPair(RP_DE, static_cast<uint16_t>(val)); return true;
    case 10: machine->cpu.WriteRegPair(RP_HL, static_cast<uint16_t>(val)); return true;
    case 11: machine->cpu.SetRB(static_cast<uint8_t>(val)); return true;
    case 12: machine->cpu.SetMACR((machine->cpu.GetMACR() & 0xFFFF0000u) | (val & 0xFFFFu)); return true;
    case 13: machine->cpu.SetMACR((machine->cpu.GetMACR() & 0x0000FFFFu) | ((val & 0xFFFFu) << 16)); return true;
    default:
        machine->intc.Poke(static_cast<uint32_t>(0xFFFE0u + (idx - 14u)), static_cast<uint8_t>(val));
        return true;
    }
}

std::string Debugger::BuildStopReply(const StopInfo &info) const {
    int sig = 5;
    std::string extra;
    char buf[64];

    switch (info.reason) {
    case StopReason::Watchpoint:
        sig = 5;
        std::snprintf(buf, sizeof(buf), "%s:%x;", info.is_write ? "watch" : "rwatch", info.detail);
        extra = buf;
        break;
    case StopReason::UnmappedMemory:
        sig = 11;
        break;
    case StopReason::InvalidInsn:
        sig = 4;
        break;
    default:
        sig = 5;
        break;
    }

    std::snprintf(buf, sizeof(buf), "T%02xthread:01;%s", sig, extra.c_str());
    return std::string(buf);
}

std::string Debugger::BuildTargetXml() const {
    std::ostringstream oss;
    oss << "<?xml version=\"1.0\"?>\n"
        << "<!DOCTYPE target SYSTEM \"gdb-target.dtd\">\n"
        << "<target version=\"1.0\">\n"
        << "  <architecture>rl78</architecture>\n"
        << "  <feature name=\"org.gnu.gdb.rl78.core\">\n";
    for (uint32_t i = 0; i < 12; ++i) {
        oss << "    <reg name=\"" << kGdbRegs[i].name << "\" bitsize=\"" << (kGdbRegs[i].bytes * 8)
            << "\" regnum=\"" << i << "\"";
        if (kGdbRegs[i].type) oss << " type=\"" << kGdbRegs[i].type << "\"";
        oss << "/>\n";
    }
    oss << "  </feature>\n"
        << "  <feature name=\"org.renesas.rl78.sys\">\n";
    for (uint32_t i = 12; i < kNumGdbRegs; ++i) {
        oss << "    <reg name=\"" << kGdbRegs[i].name << "\" bitsize=\"" << (kGdbRegs[i].bytes * 8)
            << "\" regnum=\"" << i << "\"/>\n";
    }
    oss << "  </feature>\n"
        << "</target>\n";
    return oss.str();
}

std::string Debugger::BuildMemoryMapXml() const {
    std::ostringstream oss;
    oss << "<?xml version=\"1.0\"?>\n"
        << "<!DOCTYPE memory-map SYSTEM \"gdb-memory-map.dtd\">\n"
        << "<memory-map>\n";
    if (machine) {
        for (const auto &reg : machine->bus.GetRegions()) {
            const char *type = reg.is_device ? "rom" : "ram";
            char line[128];
            std::snprintf(line, sizeof(line),
                          "  <memory type=\"%s\" start=\"0x%x\" length=\"0x%x\"/>\n",
                          type, reg.start, reg.size);
            oss << line;
        }
    }
    oss << "</memory-map>\n";
    return oss.str();
}

std::string Debugger::HandleXfer(const std::string &full_data, size_t offset, size_t length) const {
    if (offset >= full_data.size()) return "l";
    const size_t avail = full_data.size() - offset;
    const size_t take = std::min(avail, length);
    const char prefix = (offset + take >= full_data.size()) ? 'l' : 'm';
    return std::string(1, prefix) + full_data.substr(offset, take);
}

std::string Debugger::HandleMonitorCommand(const std::string &cmd) {
    if (!machine) return "E01";
    std::string out;
    machine->ExecuteCommand(cmd, out);
    if (!out.empty() && out.back() != '\n') out.push_back('\n');
    return HexEncodeString(out);
}

std::string Debugger::HandleContinue(bool single_step) {
    if (!machine) return "E01";

    if (single_step) {
        if (machine->cpu.GetRunState() != RunState::Running) {
            machine->cpu.SetRunState(RunState::Running);
        }
        const StopInfo info = machine->Step(true);
        resume_ignore_bpt = (info.reason == StopReason::Breakpoint);
        return BuildStopReply(info);
    }

    StopInfo info{};
    bool first = true;
    while (!stop_requested.load()) {
        if (active_client != InvalidSock()) {
            uint8_t b = 0;
            if (RecvByte(active_client, &b, 0) && b == 0x03) {
                info = StopInfo{StopReason::None, machine->cpu.GetPC(), 0, false};
                return BuildStopReply(info);
            }
        }

        for (int batch = 0; batch < 1024; ++batch) {
            info = machine->Step(first && resume_ignore_bpt);
            first = false;
            resume_ignore_bpt = false;
            if (info.reason != StopReason::None) {
                if (info.reason == StopReason::Breakpoint) {
                    resume_ignore_bpt = true;
                }
                return BuildStopReply(info);
            }
        }
    }

    info = StopInfo{StopReason::None, machine->cpu.GetPC(), 0, false};
    return BuildStopReply(info);
}

std::string Debugger::ProcessPacket(const std::string &payload, bool *should_disconnect_out) {
    if (should_disconnect_out) *should_disconnect_out = false;
    if (payload.empty() || !machine) return "";

    auto encode_reg = [&](uint32_t idx) -> std::string {
        const uint8_t bsz = GdbRegByteSize(idx);
        const uint32_t v = ReadGdbReg(idx);
        if (bsz == 4) return EncodeRegLE32(v);
        if (bsz == 2) return EncodeRegLE16(static_cast<uint16_t>(v));
        return EncodeReg8(static_cast<uint8_t>(v));
    };

    const char cmd = payload[0];
    switch (cmd) {
    case '?': return "T05thread:01;";
    case 'Q':
        if (payload == "QStartNoAckMode") { no_ack_mode = true; return "OK"; }
        return "";
    case 'q': {
        if (payload.rfind("qSupported", 0) == 0) {
            return "PacketSize=4096;qXfer:features:read+;qXfer:memory-map:read+;QStartNoAckMode+;hwbreak+;swbreak+";
        }
        if (payload == "qC") return "QC01";
        if (payload == "qfThreadInfo") return "m1";
        if (payload == "qsThreadInfo") return "l";
        if (payload == "qAttached") return "1";
        if (payload == "qOffsets") return "Text=0;Data=0;Bss=0";
        if (payload.rfind("qXfer:features:read:target.xml:", 0) == 0) {
            size_t off = 0, len = 4096;
            const std::string args = payload.substr(std::strlen("qXfer:features:read:target.xml:"));
            const size_t comma = args.find(',');
            if (comma != std::string::npos) {
                off = std::strtoul(args.substr(0, comma).c_str(), nullptr, 16);
                len = std::strtoul(args.substr(comma + 1).c_str(), nullptr, 16);
            }
            return HandleXfer(BuildTargetXml(), off, len);
        }
        if (payload.rfind("qXfer:memory-map:read::", 0) == 0) {
            size_t off = 0, len = 4096;
            const std::string args = payload.substr(std::strlen("qXfer:memory-map:read::"));
            const size_t comma = args.find(',');
            if (comma != std::string::npos) {
                off = std::strtoul(args.substr(0, comma).c_str(), nullptr, 16);
                len = std::strtoul(args.substr(comma + 1).c_str(), nullptr, 16);
            }
            return HandleXfer(BuildMemoryMapXml(), off, len);
        }
        if (payload.rfind("qRcmd,", 0) == 0) {
            return HandleMonitorCommand(HexDecodeString(payload.substr(6)));
        }
        return "";
    }
    case 'H': case 'T': return "OK";
    case 'g': {
        std::string out;
        for (uint32_t i = 0; i < kNumGdbRegs; ++i) out += encode_reg(i);
        return out;
    }
    case 'G': {
        const std::string hex = payload.substr(1);
        size_t pos = 0;
        for (uint32_t i = 0; i < kNumGdbRegs; ++i) {
            const uint8_t bsz = GdbRegByteSize(i);
            const size_t nchars = static_cast<size_t>(bsz) * 2u;
            if (pos + nchars > hex.size()) break;
            uint32_t val = 0;
            if (!DecodeRegLE(hex.substr(pos, nchars), bsz, &val)) return "E01";
            WriteGdbReg(i, val);
            pos += nchars;
        }
        return "OK";
    }
    case 'p': {
        const uint32_t regno = static_cast<uint32_t>(std::strtoul(payload.c_str() + 1, nullptr, 16));
        if (regno >= kNumGdbRegs) return "xxxx";
        return encode_reg(regno);
    }
    case 'P': {
        const size_t eq = payload.find('=');
        if (eq == std::string::npos) return "E01";
        const uint32_t regno = static_cast<uint32_t>(std::strtoul(payload.substr(1, eq - 1).c_str(), nullptr, 16));
        if (regno >= kNumGdbRegs) return "E01";
        uint32_t val = 0;
        if (!DecodeRegLE(payload.substr(eq + 1), GdbRegByteSize(regno), &val)) return "E01";
        return WriteGdbReg(regno, val) ? "OK" : "E01";
    }
    case 'm': {
        const size_t comma = payload.find(',');
        if (comma == std::string::npos) return "E01";
        const uint32_t addr = static_cast<uint32_t>(std::strtoul(payload.substr(1, comma - 1).c_str(), nullptr, 16));
        const uint32_t len = static_cast<uint32_t>(std::strtoul(payload.substr(comma + 1).c_str(), nullptr, 16));
        if (len == 0) return "";
        if (addr + len > Rl78Bus::kAddressSpaceSize) return "E0E";
        std::vector<uint8_t> buf(len, 0);
        if (!machine->bus.ReadDebug(addr, len, buf.data())) return "E0E";
        return ToHexBytes(buf.data(), len);
    }
    case 'M': {
        const size_t comma = payload.find(',');
        const size_t colon = payload.find(':');
        if (comma == std::string::npos || colon == std::string::npos || colon < comma) return "E01";
        const uint32_t addr = static_cast<uint32_t>(std::strtoul(payload.substr(1, comma - 1).c_str(), nullptr, 16));
        const uint32_t len = static_cast<uint32_t>(std::strtoul(payload.substr(comma + 1, colon - comma - 1).c_str(), nullptr, 16));
        const std::string hex = payload.substr(colon + 1);
        if (hex.size() < static_cast<size_t>(len) * 2 || addr + len > Rl78Bus::kAddressSpaceSize) return "E0E";
        std::vector<uint8_t> buf(len);
        for (uint32_t i = 0; i < len; ++i) {
            bool valid = true;
            buf[i] = static_cast<uint8_t>((HexNibble(hex[i * 2], &valid) << 4) | HexNibble(hex[i * 2 + 1], &valid));
            if (!valid) return "E01";
        }
        if (len > 0 && !machine->bus.WriteDebug(addr, len, buf.data())) return "E0E";
        return "OK";
    }
    case 'Z':
    case 'z': {
        if (payload.size() < 3) return "E01";
        const int type = payload[1] - '0';
        const size_t c1 = payload.find(',', 2);
        const size_t c2 = (c1 != std::string::npos) ? payload.find(',', c1 + 1) : std::string::npos;
        if (c1 == std::string::npos || c2 == std::string::npos) return "E01";
        const uint32_t addr = static_cast<uint32_t>(std::strtoul(payload.substr(c1 + 1, c2 - c1 - 1).c_str(), nullptr, 16));
        const uint32_t len = static_cast<uint32_t>(std::strtoul(payload.substr(c2 + 1).c_str(), nullptr, 16));
        const bool add = (cmd == 'Z');
        if (type == 0 || type == 1) {
            if (add) machine->cpu.AddBreakpoint(addr);
            else machine->cpu.RemoveBreakpoint(addr);
            return "OK";
        }
        if (type >= 2 && type <= 4) {
            const int wp_mask = (type == 2) ? 1 : ((type == 3) ? 2 : 3);
            const uint32_t wp_sz = (len == 0) ? 1u : len;
            if (add) machine->bus.AddWatchpoint(addr, wp_sz, wp_mask);
            else machine->bus.RemoveWatchpoint(addr, wp_sz, wp_mask);
            return "OK";
        }
        return "";
    }
    case 's':
        if (payload.size() > 1) machine->cpu.SetPC(static_cast<uint32_t>(std::strtoul(payload.c_str() + 1, nullptr, 16)));
        return HandleContinue(true);
    case 'c':
        if (payload.size() > 1) machine->cpu.SetPC(static_cast<uint32_t>(std::strtoul(payload.c_str() + 1, nullptr, 16)));
        return HandleContinue(false);
    case 'v':
        if (payload == "vCont?") return "vCont;c;C;s;S;t";
        if (payload.rfind("vCont;", 0) == 0) {
            const char action = (payload.size() > 6) ? payload[6] : 'c';
            if (action == 's' || action == 'S') return HandleContinue(true);
            if (action == 'c' || action == 'C') return HandleContinue(false);
            if (action == 't') return "OK";
        }
        return "";
    case 'D': case 'k':
        if (should_disconnect_out) *should_disconnect_out = true;
        return "OK";
    default: return "";
    }
}

bool Debugger::SendRaw(intptr_t sock, const std::string &data) {
    size_t sent = 0;
    while (sent < data.size()) {
#ifdef _WIN32
        const int rc = send(static_cast<SOCKET>(sock), data.data() + sent, static_cast<int>(data.size() - sent), 0);
#else
        const ssize_t rc = send(static_cast<int>(sock), data.data() + sent, data.size() - sent, 0);
#endif
        if (rc <= 0) return false;
        sent += static_cast<size_t>(rc);
    }
    return true;
}

bool Debugger::SendPacket(intptr_t sock, const std::string &payload) {
    char csum[8];
    std::snprintf(csum, sizeof(csum), "#%02x", Checksum(payload));
    return SendRaw(sock, "$" + payload + csum);
}

bool Debugger::RecvByte(intptr_t sock, uint8_t *out, int timeout_ms) {
    fd_set rfds;
    FD_ZERO(&rfds);
#ifdef _WIN32
    FD_SET(static_cast<SOCKET>(sock), &rfds);
#else
    FD_SET(static_cast<int>(sock), &rfds);
#endif
    timeval tv{};
    tv.tv_sec = timeout_ms / 1000;
    tv.tv_usec = (timeout_ms % 1000) * 1000;
    if (select(static_cast<int>(sock) + 1, &rfds, nullptr, nullptr, &tv) <= 0) return false;
    char ch = 0;
#ifdef _WIN32
    const int n = recv(static_cast<SOCKET>(sock), &ch, 1, 0);
#else
    const ssize_t n = recv(static_cast<int>(sock), &ch, 1, 0);
#endif
    if (n <= 0) return false;
    *out = static_cast<uint8_t>(ch);
    return true;
}

bool Debugger::ReadPacket(intptr_t sock, std::string *payload_out, bool *ctrl_c_out) {
    *ctrl_c_out = false;
    payload_out->clear();
    uint8_t b = 0;
    while (!stop_requested.load()) {
        if (!RecvByte(sock, &b, 1000)) {
            char peek_buf = 0;
            fd_set rfds;
            FD_ZERO(&rfds);
#ifdef _WIN32
            FD_SET(static_cast<SOCKET>(sock), &rfds);
            timeval tv{0, 0};
            if (select(0, &rfds, nullptr, nullptr, &tv) > 0 &&
                recv(static_cast<SOCKET>(sock), &peek_buf, 1, MSG_PEEK) <= 0) {
                return false;
            }
#else
            FD_SET(static_cast<int>(sock), &rfds);
            timeval tv{0, 0};
            if (select(static_cast<int>(sock) + 1, &rfds, nullptr, nullptr, &tv) > 0 &&
                recv(static_cast<int>(sock), &peek_buf, 1, MSG_PEEK) <= 0) {
                return false;
            }
#endif
            continue;
        }
        if (b == 0x03) { *ctrl_c_out = true; return true; }
        if (b == '$') break;
    }
    if (stop_requested.load()) return false;

    std::string body;
    bool escaped = false;
    while (!stop_requested.load()) {
        if (!RecvByte(sock, &b, 5000)) return false;
        if (escaped) { body.push_back(static_cast<char>(b ^ 0x20u)); escaped = false; continue; }
        if (b == '}') { escaped = true; continue; }
        if (b == '#') break;
        body.push_back(static_cast<char>(b));
    }

    uint8_t c1 = 0, c2 = 0;
    if (!RecvByte(sock, &c1, 5000) || !RecvByte(sock, &c2, 5000)) return false;
    bool valid = true;
    const uint8_t expected = static_cast<uint8_t>((HexNibble(static_cast<char>(c1), &valid) << 4) |
                                                  HexNibble(static_cast<char>(c2), &valid));
    const uint8_t actual = Checksum(body);
    if (!no_ack_mode) SendRaw(sock, (valid && expected == actual) ? "+" : "-");
    if (!valid || expected != actual) { payload_out->clear(); return true; }
    *payload_out = std::move(body);
    return true;
}

bool Debugger::WaitForConnection() {
#ifdef _WIN32
    WinsockGuard wsa_guard;
    if (!wsa_guard.ok) return false;
#endif
    intptr_t listen_sock = static_cast<intptr_t>(socket(AF_INET, SOCK_STREAM, 0));
    if (listen_sock == InvalidSock()) return false;
    int opt = 1;
#ifdef _WIN32
    setsockopt(static_cast<SOCKET>(listen_sock), SOL_SOCKET, SO_REUSEADDR, reinterpret_cast<const char *>(&opt), sizeof(opt));
#else
    setsockopt(static_cast<int>(listen_sock), SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
#endif
    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_ANY);
    addr.sin_port = htons(static_cast<uint16_t>(port));
    if (bind(
#ifdef _WIN32
            static_cast<SOCKET>(listen_sock),
#else
            static_cast<int>(listen_sock),
#endif
            reinterpret_cast<sockaddr *>(&addr), sizeof(addr)) != 0 ||
        listen(
#ifdef _WIN32
            static_cast<SOCKET>(listen_sock),
#else
            static_cast<int>(listen_sock),
#endif
            1) != 0) {
        CloseSock(listen_sock);
        return false;
    }

    LOG("GDB server listening on 127.0.0.1:%d", port);
    while (!stop_requested.load()) {
        fd_set rfds;
        FD_ZERO(&rfds);
#ifdef _WIN32
        FD_SET(static_cast<SOCKET>(listen_sock), &rfds);
#else
        FD_SET(static_cast<int>(listen_sock), &rfds);
#endif
        timeval tv{0, 250000};
        if (select(static_cast<int>(listen_sock) + 1, &rfds, nullptr, nullptr, &tv) <= 0) continue;
        sockaddr_in client_addr{};
        socklen_t client_len = sizeof(client_addr);
        intptr_t client = static_cast<intptr_t>(accept(
#ifdef _WIN32
            static_cast<SOCKET>(listen_sock),
#else
            static_cast<int>(listen_sock),
#endif
            reinterpret_cast<sockaddr *>(&client_addr), &client_len));
        if (client == InvalidSock()) continue;

        no_ack_mode = false;
        active_client = client;
        while (!stop_requested.load()) {
            std::string payload;
            bool ctrl_c = false;
            if (!ReadPacket(client, &payload, &ctrl_c)) break;
            if (ctrl_c) { SendPacket(client, "T05thread:01;"); continue; }
            if (payload.empty()) continue;
            bool disconnect = false;
            const std::string reply = ProcessPacket(payload, &disconnect);
            if (!SendPacket(client, reply)) break;
            if (disconnect) break;
        }
        active_client = InvalidSock();
        CloseSock(client);
        break;
    }
    CloseSock(listen_sock);
    return true;
}

}  // namespace rl78
