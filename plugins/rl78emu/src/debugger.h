#pragma once

#include <atomic>
#include <cstdint>
#include <string>

namespace rl78 {

class Rl78Machine;
struct StopInfo;

class Debugger {
public:
    explicit Debugger(Rl78Machine *machine_, int port_ = 23946);
    ~Debugger();

    Debugger(const Debugger &) = delete;
    Debugger &operator=(const Debugger &) = delete;

    bool WaitForConnection();
    void Stop();
    int Port() const { return port; }

    // Single-packet dispatcher exposed for unit testing without sockets.
    std::string ProcessPacket(const std::string &payload,
                              bool *should_disconnect_out = nullptr);

private:
    static std::string ToHexBytes(const uint8_t *data, size_t len);
    static std::string EncodeRegLE32(uint32_t val);
    static std::string EncodeRegLE16(uint16_t val);
    static std::string EncodeReg8(uint8_t val);
    static bool DecodeRegLE(const std::string &hex, uint8_t bytes, uint32_t *out);
    static std::string HexDecodeString(const std::string &hex);
    static std::string HexEncodeString(const std::string &text);
    static uint8_t Checksum(const std::string &payload);

    uint32_t ReadGdbReg(uint32_t idx) const;
    bool WriteGdbReg(uint32_t idx, uint32_t val);
    uint8_t GdbRegByteSize(uint32_t idx) const;

    std::string BuildStopReply(const StopInfo &info) const;
    std::string BuildTargetXml() const;
    std::string BuildMemoryMapXml() const;
    std::string HandleXfer(const std::string &full_data, size_t offset, size_t length) const;
    std::string HandleMonitorCommand(const std::string &cmd);
    std::string HandleContinue(bool single_step);

    bool SendRaw(intptr_t sock, const std::string &data);
    bool SendPacket(intptr_t sock, const std::string &payload);
    bool RecvByte(intptr_t sock, uint8_t *out, int timeout_ms);
    bool ReadPacket(intptr_t sock, std::string *payload_out, bool *ctrl_c_out);

    Rl78Machine *machine = nullptr;
    int port = 23946;
    bool no_ack_mode = false;
    bool resume_ignore_bpt = false;
    intptr_t active_client = -1;
    std::atomic<bool> stop_requested{false};
};

}  // namespace rl78
