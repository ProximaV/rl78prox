#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace rl78 {

enum class CoreProfile : uint8_t {
    S1 = 1,
    S2 = 2,
    S3 = 3,
};

enum MemPerm : uint8_t {
    MEM_PERM_READ  = 1,
    MEM_PERM_WRITE = 2,
    MEM_PERM_EXEC  = 4,
    MEM_PERM_RW    = MEM_PERM_READ | MEM_PERM_WRITE,
    MEM_PERM_RX    = MEM_PERM_READ | MEM_PERM_EXEC,
    MEM_PERM_RWX   = MEM_PERM_READ | MEM_PERM_WRITE | MEM_PERM_EXEC,
};

struct MemoryRegion {
    uint32_t start = 0;
    uint32_t size = 0;
    std::string name;
    bool is_device = false;
    uint8_t perm = MEM_PERM_RWX;
};

struct Watchpoint {
    uint32_t addr = 0;
    uint32_t size = 1;
    int type = 0;  // bit 0 (1) = write, bit 1 (2) = read, 3 = read/write
};

class PeripheralDevice {
public:
    virtual ~PeripheralDevice() = default;

    // CPU-initiated access (20-bit address in 0xF0000..0xFFFFF).
    virtual uint8_t Read(uint32_t addr) = 0;
    virtual void Write(uint32_t addr, uint8_t value) = 0;

    // Debugger / inspection access (side-effect-free).
    virtual uint8_t Peek(uint32_t addr) const = 0;
    virtual void Poke(uint32_t addr, uint8_t value) { Write(addr, value); }

    virtual void Reset() {}
    virtual void Tick(uint32_t cpu_cycles,
                      uint32_t prs_cycles,
                      uint32_t sub_cycles,
                      uint32_t il_cycles,
                      bool in_halt,
                      bool in_stop) {
        (void)cpu_cycles;
        (void)prs_cycles;
        (void)sub_cycles;
        (void)il_cycles;
        (void)in_halt;
        (void)in_stop;
    }
};

class Rl78Bus {
public:
    static constexpr uint32_t kAddressSpaceSize = 0x100000u;  // 1 MB (20-bit)
    static constexpr uint32_t kAddressMask      = 0x0FFFFFu;
    static constexpr uint32_t kMaxCodeFlashEnd  = 0x0F0000u;  // Up to 960 KB linear code flash
    static constexpr uint32_t kNearBase         = 0x0F0000u;  // Near 64 KB data space (0xF0000..0xFFFFF)
    static constexpr uint32_t kSfr2Start        = 0x0F0000u;
    static constexpr uint32_t kSfr2End          = 0x0F08FFu;  // 2nd SFR (0xF0000..0xF07FF) + FSL mailbox (0xF0800..0xF08FF)
    static constexpr uint32_t kSfr2Size         = 0x000900u;
    static constexpr uint32_t kBootClusterSize  = 0x001000u;  // 4 KB boot cluster (0x0000..0x0FFF / 0x1000..0x1FFF)
    static constexpr uint32_t kFlashBlockSize   = 0x000400u;  // 1 KB code flash block
    static constexpr uint32_t kFslRomStart      = 0x0EFFC0u;  // Internal FSL firmware stub region
    static constexpr uint32_t kFslRomEnd        = 0x0EFFFFu;
    static constexpr uint32_t kDataFlashStart   = 0x0F1000u;
    static constexpr uint32_t kMaxDataFlashSize = 0x002000u;  // Up to 8 KB Data Flash (0xF1000..0xF2FFF)
    static constexpr uint32_t kMaxRamBase       = 0x0F3000u;  // Earliest RAM start in 0xFxxxx
    static constexpr uint32_t kHighSpeedRamEnd  = 0x0FFEDFu;
    static constexpr uint32_t kGprStart         = 0x0FFEE0u;
    static constexpr uint32_t kGprEnd           = 0x0FFEFFu;
    static constexpr uint32_t kSfrStart         = 0x0FFF00u;
    static constexpr uint32_t kSfrEnd           = 0x0FFFFFu;
    static constexpr uint32_t kDefaultRamStart  = 0x0F7F00u;  // 32 KB near RAM (accommodates <=32KB RL78 parts)

    Rl78Bus();

    void ConfigureLayout(CoreProfile core,
                         uint32_t code_flash_end = 0x080000u,
                         uint32_t data_flash_size = 0x002000u,
                         uint32_t ram_start = kDefaultRamStart);

    void ClearMemory();
    void ClearAllDevices();
    void ResetDevices();

    void RegisterDevice(PeripheralDevice *dev);
    void MapSfr(uint32_t addr, PeripheralDevice *dev);
    void MapSfrRange(uint32_t start_addr, uint32_t end_addr, PeripheralDevice *dev);

    // Load flat firmware image into address space.
    bool LoadRom(const uint8_t *data, size_t size, uint32_t base_addr = 0);
    // Load Data Flash image (up to 8 KB at 0xF1000).
    bool LoadDataFlash(const uint8_t *data, size_t size, uint32_t offset = 0);

    // PMC.MAA (0xFFFFE bit 0): selects whether mirror window maps 0x0xxxx (0) or 0x1xxxx (1).
    void SetMirrorAreaAlt(bool maa) { maa_ = maa; }
    bool GetMirrorAreaAlt() const { return maa_; }

    // DFLCTL.DFLEN (0xF0090 bit 0): enables reading Data Flash at 0xF1000..data_flash_end_.
    void SetDataFlashEnabled(bool en) { data_flash_enabled_ = en; }
    bool IsDataFlashEnabled() const { return data_flash_enabled_; }

    // Address helpers per RL78 architecture manual.
    static constexpr uint32_t ResolveSfr(uint8_t offset) {
        return kSfrStart + offset;
    }
    static constexpr uint32_t ResolveSaddr(uint8_t offset) {
        return (offset < 0x20u) ? (kSfrStart + offset) : (0x0FFE00u + offset);
    }
    static constexpr uint32_t ResolveNear(uint16_t addr16) {
        return kNearBase | addr16;
    }
    static constexpr uint32_t ResolveWithEs(uint16_t addr16, bool use_es, uint8_t es_val) {
        return use_es ? ((static_cast<uint32_t>(es_val & 0x0Fu) << 16) | addr16)
                      : (kNearBase | addr16);
    }

    // CPU-side bus operations (mask addresses to 20 bits).
    uint8_t FetchByte(uint32_t pc);
    uint8_t ReadCpu(uint32_t addr);
    void WriteCpu(uint32_t addr, uint8_t value);

    // Side-effect-free debugger memory operations.
    uint8_t PeekByte(uint32_t addr) const;
    void PokeByte(uint32_t addr, uint8_t value);
    bool ReadDebug(uint32_t addr, size_t size, void *dest) const;
    bool WriteDebug(uint32_t addr, size_t size, const void *src);

    // Watchpoints (20-bit addresses).
    void AddWatchpoint(uint32_t addr, uint32_t size, int type);
    void RemoveWatchpoint(uint32_t addr, uint32_t size, int type);
    void ClearWatchpoints();

    void ClearFaults() {
        unmapped_fault = false;
        fault_addr = 0;
        fault_is_write = false;
        watchpoint_hit = false;
        watchpoint_addr = 0;
        watchpoint_is_write = false;
    }

    void TickDevices(uint32_t cpu_cycles,
                     uint32_t prs_cycles,
                     uint32_t sub_cycles,
                     uint32_t il_cycles,
                     bool in_halt,
                     bool in_stop);

    std::vector<MemoryRegion> GetRegions() const;

    CoreProfile Core() const { return core_; }
    uint32_t CodeFlashEnd() const { return code_flash_end_; }
    uint32_t DataFlashEnd() const { return data_flash_end_; }
    uint32_t MirrorStart() const { return mirror_start_; }
    uint32_t RamStart() const { return ram_start_; }

    // Boot cluster swap & flash self-programming helpers.
    void SwapBootClusters();
    void SetBootSwapped(bool swapped);
    bool IsBootSwapped() const { return boot_swapped_; }
    uint32_t BootSwapCount() const { return boot_swap_count_; }
    uint32_t FlashMutationCount() const { return flash_mutation_count_; }
    bool BlankCheckFlashBlock(uint32_t block_index) const;
    bool EraseFlashBlock(uint32_t block_index);
    bool ProgramFlashBytes(uint32_t flash_addr, const uint8_t *data, size_t size);
    void InstallFslRomStub(uint16_t max_page_word = 0x03FFu);

    bool stop_on_unmapped = false;
    bool rom_writable = false;

    bool unmapped_fault = false;
    uint32_t fault_addr = 0;
    bool fault_is_write = false;

    bool watchpoint_hit = false;
    uint32_t watchpoint_addr = 0;
    bool watchpoint_is_write = false;

private:
    bool IsCodeFlashAddr(uint32_t addr) const { return addr < code_flash_end_; }
    bool IsSfr2Addr(uint32_t addr) const { return addr >= kSfr2Start && addr <= kSfr2End; }
    bool IsDataFlashAddr(uint32_t addr) const {
        return data_flash_end_ > kDataFlashStart && addr >= kDataFlashStart && addr < data_flash_end_;
    }
    bool IsMirrorAddr(uint32_t addr) const {
        return addr >= mirror_start_ && addr < ram_start_;
    }
    bool IsRamAddr(uint32_t addr) const { return addr >= ram_start_ && addr <= kHighSpeedRamEnd; }
    bool IsGprAddr(uint32_t addr) const { return addr >= kGprStart && addr <= kGprEnd; }
    bool IsSfrAddr(uint32_t addr) const { return addr >= kSfrStart && addr <= kSfrEnd; }
    bool IsMappedAddr(uint32_t addr) const;

    uint32_t TranslateMirrorAddr(uint32_t addr) const {
        return (maa_ ? 0x010000u : 0x000000u) | (addr & 0x00FFFFu);
    }

    void CheckWatchpoints(uint32_t addr, bool is_write);

    CoreProfile core_ = CoreProfile::S3;
    uint32_t code_flash_end_ = 0x080000u;
    uint32_t data_flash_end_ = 0x0F3000u;
    uint32_t mirror_start_   = 0x0F3000u;
    uint32_t ram_start_      = kDefaultRamStart;

    bool maa_ = false;
    bool data_flash_enabled_ = false;
    bool data_flash_loaded_ = false;
    bool boot_swapped_ = false;
    uint32_t boot_swap_count_ = 0;
    uint32_t flash_mutation_count_ = 0;
    bool fsl_rom_enabled_ = false;

    std::vector<uint8_t> code_flash_;                    // up to 960 KB (0x00000..0xEFFFF)
    std::array<uint8_t, 64> fsl_rom_{};                  // 0xEFFC0..0xEFFFF FSL firmware stub
    std::array<uint8_t, kSfr2Size> sfr2_ram_{};          // 0xF0000..0xF08FF
    std::array<uint8_t, kMaxDataFlashSize> data_flash_{};  // 0xF1000..0xF2FFF
    std::vector<uint8_t> near_ram_;                      // 0xF3000..0xFFEDF
    std::array<uint8_t, 0x0020u> gpr_ram_{};             // 0xFFEE0..0xFFEFF
    std::array<uint8_t, 0x0100u> sfr_ram_{};             // 0xFFF00..0xFFFFF

    std::array<PeripheralDevice *, kSfr2Size> sfr2_devs_{};
    std::array<PeripheralDevice *, 256> sfr_devs_{};
    std::vector<PeripheralDevice *> devices_;
    std::vector<Watchpoint> watchpoints_;
};

}  // namespace rl78
