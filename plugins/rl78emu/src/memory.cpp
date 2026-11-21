#include "memory.h"

#include <algorithm>
#include <cstring>
#include <utility>

namespace rl78 {

Rl78Bus::Rl78Bus()
    : code_flash_(kMaxCodeFlashEnd, 0xFFu),
      near_ram_(kSfrStart - kMaxRamBase, 0x00u) {
    ConfigureLayout(CoreProfile::S3, 0x080000u, 0x002000u, kDefaultRamStart);
    ClearMemory();
}

void Rl78Bus::ConfigureLayout(CoreProfile core,
                              uint32_t code_flash_end,
                              uint32_t data_flash_size,
                              uint32_t ram_start) {
    core_ = core;
    if (code_flash_end == 0 || code_flash_end > kMaxCodeFlashEnd) {
        code_flash_end_ = kMaxCodeFlashEnd;
    } else {
        code_flash_end_ = code_flash_end;
    }

    const uint32_t df_sz = (data_flash_size <= kMaxDataFlashSize) ? data_flash_size : kMaxDataFlashSize;
    data_flash_end_ = kDataFlashStart + df_sz;
    mirror_start_ = (df_sz > 0) ? data_flash_end_ : kDataFlashStart;

    if (ram_start < kMaxRamBase) {
        ram_start_ = kMaxRamBase;
    } else if (ram_start > kHighSpeedRamEnd) {
        ram_start_ = kHighSpeedRamEnd - 0xFFu;
    } else {
        ram_start_ = ram_start;
    }
    if (mirror_start_ > ram_start_) {
        mirror_start_ = ram_start_;
    }
}

void Rl78Bus::ClearMemory() {
    std::fill(code_flash_.begin(), code_flash_.end(), 0xFFu);
    data_flash_.fill(0xFFu);
    std::fill(near_ram_.begin(), near_ram_.end(), 0x00u);
    gpr_ram_.fill(0x00u);
    sfr2_ram_.fill(0x00u);
    sfr_ram_.fill(0x00u);
    fsl_rom_.fill(0xFFu);
    maa_ = false;
    data_flash_enabled_ = false;
    data_flash_loaded_ = false;
    fsl_rom_enabled_ = false;
    boot_swapped_ = false;
    boot_swap_count_ = 0;
    flash_mutation_count_ = 0;
    ClearFaults();
}

void Rl78Bus::ClearAllDevices() {
    sfr2_devs_.fill(nullptr);
    sfr_devs_.fill(nullptr);
    devices_.clear();
}

void Rl78Bus::ResetDevices() {
    maa_ = false;
    data_flash_enabled_ = false;
    sfr2_ram_.fill(0x00u);
    sfr_ram_.fill(0x00u);
    for (PeripheralDevice *dev : devices_) {
        if (dev) {
            dev->Reset();
        }
    }
}

void Rl78Bus::RegisterDevice(PeripheralDevice *dev) {
    if (!dev) {
        return;
    }
    if (std::find(devices_.begin(), devices_.end(), dev) == devices_.end()) {
        devices_.push_back(dev);
    }
}

void Rl78Bus::MapSfr(uint32_t addr, PeripheralDevice *dev) {
    addr &= kAddressMask;
    if (IsSfr2Addr(addr)) {
        RegisterDevice(dev);
        sfr2_devs_[addr - kSfr2Start] = dev;
    } else if (IsSfrAddr(addr)) {
        RegisterDevice(dev);
        sfr_devs_[addr - kSfrStart] = dev;
    }
}

void Rl78Bus::MapSfrRange(uint32_t start_addr, uint32_t end_addr, PeripheralDevice *dev) {
    start_addr &= kAddressMask;
    end_addr &= kAddressMask;
    if (end_addr < start_addr) {
        return;
    }
    RegisterDevice(dev);
    for (uint32_t a = start_addr; a <= end_addr; ++a) {
        if (IsSfr2Addr(a)) {
            sfr2_devs_[a - kSfr2Start] = dev;
        } else if (IsSfrAddr(a)) {
            sfr_devs_[a - kSfrStart] = dev;
        }
    }
}

bool Rl78Bus::LoadRom(const uint8_t *data, size_t size, uint32_t base_addr) {
    if (!data && size > 0) {
        return false;
    }
    if (size == 0) {
        return true;
    }
    base_addr &= kAddressMask;
    if (base_addr >= kAddressSpaceSize || size > kAddressSpaceSize - base_addr) {
        return false;
    }

    // If loading starting in code flash (< 0xF0000), copy code flash up to 0xEFFFF.
    const uint32_t end_addr = static_cast<uint32_t>(base_addr + size);
    const uint32_t cf_end = std::min<uint32_t>(end_addr, kMaxCodeFlashEnd);
    if (base_addr < kMaxCodeFlashEnd && cf_end > base_addr) {
        std::memcpy(code_flash_.data() + base_addr, data, cf_end - base_addr);
        if (cf_end > code_flash_end_) {
            code_flash_end_ = cf_end;
        }
    }

    // Full 1 MB image (like hardware dumps spanning 0x00000..0xFFFFF):
    // check if 0xF1000..0xF2FFF mirrors bank 0 (no separate Data Flash) and detect RAM boundary.
    if (base_addr == 0 && size > kNearBase) {
        if (size >= 0xF3000u) {
            const bool mirrors_bank0 = (std::memcmp(data + 0xF1000u, data + 0x01000u, 0x2000u) == 0);
            if (mirrors_bank0) {
                data_flash_end_ = kDataFlashStart;
                mirror_start_ = kDataFlashStart;
            }
        }
        if (size >= kSfrStart) {
            // Find the lowest address >= 0xF3000 where image differs from both bank 0 & bank 1 mirror.
            uint32_t detected_ram = ram_start_;
            for (uint32_t a = kMaxRamBase; a < kGprStart; a += 0x100u) {
                const uint32_t off = a & 0xFFFFu;
                const bool eq0 = (std::memcmp(data + a, data + off, 0x100u) == 0);
                const bool eq1 = (std::memcmp(data + a, data + 0x10000u + off, 0x100u) == 0);
                if (!eq0 && !eq1) {
                    detected_ram = a;
                    break;
                }
            }
            if (detected_ram >= kMaxRamBase && detected_ram < ram_start_) {
                // Keep if user already configured a larger RAM, or adjust if default was smaller/larger.
                ram_start_ = detected_ram;
            } else if (detected_ram > ram_start_ && ram_start_ == kDefaultRamStart) {
                ram_start_ = detected_ram;
            }
            const uint32_t ram_copy_end = std::min<uint32_t>(end_addr, kHighSpeedRamEnd + 1u);
            if (ram_copy_end > ram_start_) {
                std::memcpy(near_ram_.data() + (ram_start_ - kMaxRamBase),
                            data + ram_start_,
                            ram_copy_end - ram_start_);
            }
        }
    } else if (end_addr > kNearBase) {
        // Explicit load into high region (>= 0xF0000) via WriteDebug.
        const uint32_t high_start = std::max<uint32_t>(base_addr, kNearBase);
        const uint32_t src_off = high_start - base_addr;
        WriteDebug(high_start, end_addr - high_start, data + src_off);
    }

    return true;
}

bool Rl78Bus::LoadDataFlash(const uint8_t *data, size_t size, uint32_t offset) {
    if (!data && size > 0) {
        return false;
    }
    if (offset >= kMaxDataFlashSize || size > kMaxDataFlashSize - offset) {
        return false;
    }
    if (size > 0) {
        std::memcpy(data_flash_.data() + offset, data, size);
        data_flash_loaded_ = true;
        if (data_flash_end_ < kDataFlashStart + offset + size) {
            data_flash_end_ = static_cast<uint32_t>(kDataFlashStart + offset + size);
            if (mirror_start_ < data_flash_end_) {
                mirror_start_ = data_flash_end_;
            }
        }
    }
    return true;
}

bool Rl78Bus::IsMappedAddr(uint32_t addr) const {
    return IsCodeFlashAddr(addr) ||
           (fsl_rom_enabled_ && addr >= kFslRomStart && addr <= kFslRomEnd) ||
           IsSfr2Addr(addr) || IsDataFlashAddr(addr) ||
           IsMirrorAddr(addr) || IsRamAddr(addr) || IsGprAddr(addr) || IsSfrAddr(addr);
}

void Rl78Bus::CheckWatchpoints(uint32_t addr, bool is_write) {
    if (watchpoints_.empty()) {
        return;
    }
    for (const auto &wp : watchpoints_) {
        const uint32_t wp_end = wp.addr + (wp.size ? wp.size : 1u);
        if (addr >= wp.addr && addr < wp_end) {
            const bool match = is_write ? ((wp.type & 1) != 0) : ((wp.type & 2) != 0);
            if (match && !watchpoint_hit) {
                watchpoint_hit = true;
                watchpoint_addr = addr;
                watchpoint_is_write = is_write;
            }
        }
    }
}

uint8_t Rl78Bus::FetchByte(uint32_t pc) {
    pc &= kAddressMask;
    if (fsl_rom_enabled_ && pc >= kFslRomStart && pc <= kFslRomEnd) {
        return fsl_rom_[pc - kFslRomStart];
    }
    if (IsCodeFlashAddr(pc)) {
        return code_flash_[pc];
    }
    if (IsRamAddr(pc)) {
        return near_ram_[pc - kMaxRamBase];
    }
    if (IsMirrorAddr(pc)) {
        const uint32_t phys = TranslateMirrorAddr(pc);
        return (phys < kMaxCodeFlashEnd) ? code_flash_[phys] : 0xFFu;
    }
    if (stop_on_unmapped && !IsMappedAddr(pc)) {
        unmapped_fault = true;
        fault_addr = pc;
        fault_is_write = false;
    }
    return PeekByte(pc);
}

uint8_t Rl78Bus::ReadCpu(uint32_t addr) {
    addr &= kAddressMask;
    CheckWatchpoints(addr, false);
    if (fsl_rom_enabled_ && addr >= kFslRomStart && addr <= kFslRomEnd) {
        return fsl_rom_[addr - kFslRomStart];
    }
    if (IsCodeFlashAddr(addr)) {
        return code_flash_[addr];
    }
    if (IsSfr2Addr(addr)) {
        PeripheralDevice *dev = sfr2_devs_[addr - kSfr2Start];
        return dev ? dev->Read(addr) : sfr2_ram_[addr - kSfr2Start];
    }
    if (IsDataFlashAddr(addr)) {
        return (data_flash_enabled_ || data_flash_loaded_) ? data_flash_[addr - kDataFlashStart] : 0xFFu;
    }
    if (IsMirrorAddr(addr)) {
        const uint32_t phys = TranslateMirrorAddr(addr);
        return (phys < kMaxCodeFlashEnd) ? code_flash_[phys] : 0xFFu;
    }
    if (IsRamAddr(addr)) {
        return near_ram_[addr - kMaxRamBase];
    }
    if (IsGprAddr(addr)) {
        return gpr_ram_[addr - kGprStart];
    }
    if (IsSfrAddr(addr)) {
        PeripheralDevice *dev = sfr_devs_[addr - kSfrStart];
        return dev ? dev->Read(addr) : sfr_ram_[addr - kSfrStart];
    }
    if (stop_on_unmapped) {
        unmapped_fault = true;
        fault_addr = addr;
        fault_is_write = false;
    }
    return 0xFFu;
}

void Rl78Bus::WriteCpu(uint32_t addr, uint8_t value) {
    addr &= kAddressMask;
    CheckWatchpoints(addr, true);
    if (IsCodeFlashAddr(addr)) {
        if (rom_writable) {
            code_flash_[addr] = value;
        }
        return;
    }
    if (IsSfr2Addr(addr)) {
        PeripheralDevice *dev = sfr2_devs_[addr - kSfr2Start];
        if (dev) {
            dev->Write(addr, value);
        } else {
            sfr2_ram_[addr - kSfr2Start] = value;
        }
        return;
    }
    if (IsDataFlashAddr(addr) || IsMirrorAddr(addr)) {
        return;  // Read-only in normal operation
    }
    if (IsRamAddr(addr)) {
        near_ram_[addr - kMaxRamBase] = value;
        return;
    }
    if (IsGprAddr(addr)) {
        gpr_ram_[addr - kGprStart] = value;
        return;
    }
    if (IsSfrAddr(addr)) {
        PeripheralDevice *dev = sfr_devs_[addr - kSfrStart];
        if (dev) {
            dev->Write(addr, value);
        } else {
            sfr_ram_[addr - kSfrStart] = value;
        }
        return;
    }
    if (stop_on_unmapped) {
        unmapped_fault = true;
        fault_addr = addr;
        fault_is_write = true;
    }
}

uint8_t Rl78Bus::PeekByte(uint32_t addr) const {
    addr &= kAddressMask;
    if (fsl_rom_enabled_ && addr >= kFslRomStart && addr <= kFslRomEnd) {
        return fsl_rom_[addr - kFslRomStart];
    }
    if (IsCodeFlashAddr(addr)) {
        return code_flash_[addr];
    }
    if (IsSfr2Addr(addr)) {
        const PeripheralDevice *dev = sfr2_devs_[addr - kSfr2Start];
        return dev ? dev->Peek(addr) : sfr2_ram_[addr - kSfr2Start];
    }
    if (IsDataFlashAddr(addr)) {
        return data_flash_[addr - kDataFlashStart];
    }
    if (IsMirrorAddr(addr)) {
        const uint32_t phys = TranslateMirrorAddr(addr);
        return (phys < kMaxCodeFlashEnd) ? code_flash_[phys] : 0xFFu;
    }
    if (IsRamAddr(addr)) {
        return near_ram_[addr - kMaxRamBase];
    }
    if (IsGprAddr(addr)) {
        return gpr_ram_[addr - kGprStart];
    }
    if (IsSfrAddr(addr)) {
        const PeripheralDevice *dev = sfr_devs_[addr - kSfrStart];
        return dev ? dev->Peek(addr) : sfr_ram_[addr - kSfrStart];
    }
    return 0xFFu;
}

void Rl78Bus::PokeByte(uint32_t addr, uint8_t value) {
    addr &= kAddressMask;
    if (IsCodeFlashAddr(addr)) {
        code_flash_[addr] = value;
        return;
    }
    if (IsSfr2Addr(addr)) {
        PeripheralDevice *dev = sfr2_devs_[addr - kSfr2Start];
        if (dev) {
            dev->Poke(addr, value);
        } else {
            sfr2_ram_[addr - kSfr2Start] = value;
        }
        return;
    }
    if (IsDataFlashAddr(addr)) {
        data_flash_[addr - kDataFlashStart] = value;
        return;
    }
    if (IsMirrorAddr(addr)) {
        return;
    }
    if (IsRamAddr(addr)) {
        near_ram_[addr - kMaxRamBase] = value;
        return;
    }
    if (IsGprAddr(addr)) {
        gpr_ram_[addr - kGprStart] = value;
        return;
    }
    if (IsSfrAddr(addr)) {
        PeripheralDevice *dev = sfr_devs_[addr - kSfrStart];
        if (dev) {
            dev->Poke(addr, value);
        } else {
            sfr_ram_[addr - kSfrStart] = value;
        }
    }
}

bool Rl78Bus::ReadDebug(uint32_t addr, size_t size, void *dest) const {
    if (!dest && size > 0) {
        return false;
    }
    uint8_t *out = static_cast<uint8_t *>(dest);
    for (size_t i = 0; i < size; ++i) {
        if (addr + i >= kAddressSpaceSize) {
            return false;
        }
        out[i] = PeekByte(static_cast<uint32_t>(addr + i));
    }
    return true;
}

bool Rl78Bus::WriteDebug(uint32_t addr, size_t size, const void *src) {
    if (!src && size > 0) {
        return false;
    }
    const uint8_t *in = static_cast<const uint8_t *>(src);
    for (size_t i = 0; i < size; ++i) {
        if (addr + i >= kAddressSpaceSize) {
            return false;
        }
        PokeByte(static_cast<uint32_t>(addr + i), in[i]);
    }
    return true;
}

void Rl78Bus::AddWatchpoint(uint32_t addr, uint32_t size, int type) {
    addr &= kAddressMask;
    const uint32_t sz = size ? size : 1u;
    for (auto &wp : watchpoints_) {
        if (wp.addr == addr && wp.size == sz) {
            wp.type |= type;
            return;
        }
    }
    watchpoints_.push_back(Watchpoint{addr, sz, type});
}

void Rl78Bus::RemoveWatchpoint(uint32_t addr, uint32_t size, int type) {
    addr &= kAddressMask;
    const uint32_t sz = size ? size : 1u;
    for (auto it = watchpoints_.begin(); it != watchpoints_.end();) {
        if (it->addr == addr && it->size == sz) {
            it->type &= ~type;
            if (it->type == 0) {
                it = watchpoints_.erase(it);
                continue;
            }
        }
        ++it;
    }
}

void Rl78Bus::ClearWatchpoints() {
    watchpoints_.clear();
}

void Rl78Bus::TickDevices(uint32_t cpu_cycles,
                          uint32_t prs_cycles,
                          uint32_t sub_cycles,
                          uint32_t il_cycles,
                          bool in_halt,
                          bool in_stop) {
    for (PeripheralDevice *dev : devices_) {
        if (dev) {
            dev->Tick(cpu_cycles, prs_cycles, sub_cycles, il_cycles, in_halt, in_stop);
        }
    }
}

std::vector<MemoryRegion> Rl78Bus::GetRegions() const {
    std::vector<MemoryRegion> regions;
    if (code_flash_end_ > 0) {
        regions.push_back(MemoryRegion{0x00000u, code_flash_end_, "CODE_FLASH", false, MEM_PERM_RX});
    }
    if (fsl_rom_enabled_ && code_flash_end_ <= kFslRomStart) {
        regions.push_back(MemoryRegion{
            kFslRomStart,
            kFslRomEnd - kFslRomStart + 1u,
            "FSL_ROM",
            false,
            MEM_PERM_RX,
        });
    }
    regions.push_back(MemoryRegion{kSfr2Start, kSfr2Size, "SFR_2ND", true, MEM_PERM_RW});
    if (data_flash_end_ > kDataFlashStart) {
        regions.push_back(MemoryRegion{
            kDataFlashStart,
            data_flash_end_ - kDataFlashStart,
            "DATA_FLASH",
            false,
            MEM_PERM_READ,
        });
    }
    if (ram_start_ > mirror_start_) {
        regions.push_back(MemoryRegion{
            mirror_start_,
            ram_start_ - mirror_start_,
            "MIRROR_ROM",
            false,
            MEM_PERM_READ,
        });
    }
    if (ram_start_ <= kHighSpeedRamEnd) {
        regions.push_back(MemoryRegion{
            ram_start_,
            kHighSpeedRamEnd - ram_start_ + 1u,
            "INTRAM",
            false,
            MEM_PERM_RWX,
        });
    }
    regions.push_back(MemoryRegion{kGprStart, 0x0020u, "GPR", false, MEM_PERM_RW});
    regions.push_back(MemoryRegion{kSfrStart, 0x0100u, "SFR_1ST", true, MEM_PERM_RW});
    return regions;
}

void Rl78Bus::SwapBootClusters() {
    if (code_flash_end_ < 2u * kBootClusterSize || code_flash_.size() < 2u * kBootClusterSize) {
        return;
    }
    for (uint32_t i = 0; i < kBootClusterSize; ++i) {
        std::swap(code_flash_[i], code_flash_[kBootClusterSize + i]);
    }
    boot_swapped_ = !boot_swapped_;
    ++boot_swap_count_;
    ++flash_mutation_count_;
}

void Rl78Bus::SetBootSwapped(bool swapped) {
    if (boot_swapped_ != swapped) {
        SwapBootClusters();
    }
}

bool Rl78Bus::BlankCheckFlashBlock(uint32_t block_index) const {
    const uint32_t max_blocks = code_flash_end_ / kFlashBlockSize;
    if (block_index >= max_blocks) {
        return false;
    }
    const uint32_t start = block_index * kFlashBlockSize;
    if (start + kFlashBlockSize > code_flash_.size()) {
        return false;
    }
    for (uint32_t i = 0; i < kFlashBlockSize; ++i) {
        if (code_flash_[start + i] != 0xFFu) {
            return false;
        }
    }
    return true;
}

bool Rl78Bus::EraseFlashBlock(uint32_t block_index) {
    const uint32_t max_blocks = code_flash_end_ / kFlashBlockSize;
    if (block_index >= max_blocks) {
        return false;
    }
    const uint32_t start = block_index * kFlashBlockSize;
    if (start + kFlashBlockSize > code_flash_.size()) {
        return false;
    }
    std::fill_n(code_flash_.begin() + start, kFlashBlockSize, 0xFFu);
    ++flash_mutation_count_;
    return true;
}

bool Rl78Bus::ProgramFlashBytes(uint32_t flash_addr, const uint8_t *data, size_t size) {
    flash_addr &= kAddressMask;
    if ((!data && size > 0) || flash_addr >= code_flash_end_) {
        return false;
    }
    if (size > code_flash_end_ - flash_addr || flash_addr + size > code_flash_.size()) {
        return false;
    }
    for (size_t i = 0; i < size; ++i) {
        code_flash_[flash_addr + i] = data[i];
    }
    if (size > 0) {
        ++flash_mutation_count_;
    }
    return true;
}

void Rl78Bus::InstallFslRomStub(uint16_t max_page_word) {
    fsl_rom_.fill(0xFFu);
    fsl_rom_[0x10u] = static_cast<uint8_t>(max_page_word & 0xFFu);
    fsl_rom_[0x11u] = static_cast<uint8_t>((max_page_word >> 8u) & 0xFFu);
    fsl_rom_[0x38u] = 0xD7u;  // RET
    fsl_rom_enabled_ = true;
}

}  // namespace rl78
