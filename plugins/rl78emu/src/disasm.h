#pragma once

#include <cstdint>
#include <string>

#include "memory.h"

namespace rl78 {

struct DecodedInsn {
    uint32_t addr = 0;
    uint8_t length = 0;
    uint8_t bytes[6] = {};
    std::string mnemonic;
    std::string operands;
    bool valid = false;
    bool is_call = false;
    bool is_branch = false;
    bool is_stop_flow = false;  // ret, reti, retb, unconditional br, brk
    bool is_skip = false;
    bool has_es = false;
    bool has_target = false;
    uint32_t target_addr = 0;

    std::string Format() const;
    std::string FormatWithBytes() const;
};

const char *LookupSfrName(uint32_t addr);
DecodedInsn DisassembleAt(const Rl78Bus &bus, uint32_t addr);

}  // namespace rl78
