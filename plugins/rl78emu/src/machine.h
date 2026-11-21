#pragma once

#include <atomic>
#include <cstdint>
#include <string>
#include <vector>

#include "cpu.h"
#include "disasm.h"
#include "memory.h"
#include "rl78_peripherals.h"

namespace rl78 {

class Rl78Machine {
public:
    Rl78Machine();

    void Configure(CoreProfile core = CoreProfile::S3,
                   uint32_t code_flash_end = 0x080000u,
                   uint32_t data_flash_size = 0x002000u,
                   uint32_t ram_start = Rl78Bus::kDefaultRamStart);

    // Reset peripherals and CPU (reads reset vector from 0x00000 unless entry_override != -1).
    void Reset(int32_t entry_override = -1);

    // Load binary firmware or Data Flash image.
    bool LoadRomBytes(const uint8_t *data, size_t size, uint32_t base_addr = 0);
    bool LoadRomFile(const char *path, uint32_t base_addr = 0);
    bool LoadDataFlashBytes(const uint8_t *data, size_t size, uint32_t offset = 0);
    bool LoadDataFlashFile(const char *path, uint32_t offset = 0);

    StopInfo Step(bool ignore_bpt_at_pc = false);
    StopInfo RunSteps(uint64_t max_steps,
                      bool ignore_bpt_at_first_pc = false,
                      const std::atomic<bool> *cancel = nullptr);

    // Diagnostics & CLI command processor (shared by GDB qRcmd and IDA ev_rexec).
    std::string FormatStatus() const;
    std::string FormatBanks() const;
    std::string FormatIntc() const;
    std::string FormatClock() const;
    std::string FormatTimers() const;
    std::string FormatPorts() const;
    std::string FormatSau() const;
    std::string FormatAdc() const;
    std::string FormatDma() const;
    std::string FormatFlash() const;
    std::string FormatMemoryMap() const;
    bool ExecuteCommand(const std::string &cmdline, std::string &out);

    CoreProfile Core() const { return core_; }

    Rl78Bus bus;
    Rl78Cpu cpu;

    Rl78Intc intc;
    Rl78Clock clock;
    Rl78Wdt wdt;
    Rl78Ports ports;
    Rl78Tau tau0;
    Rl78Tau tau1;
    Rl78RtcIt rtc_it;
    Rl78Adc adc;
    Rl78Sau sau0;
    Rl78Sau sau1;
    Rl78Iica iica0;
    Rl78Iica iica1;
    Rl78MulDiv muldiv;
    Rl78Dma dma;
    Rl78FlashCtrl flash;

private:
    void WirePeripherals();

    CoreProfile core_ = CoreProfile::S3;
};

}  // namespace rl78
