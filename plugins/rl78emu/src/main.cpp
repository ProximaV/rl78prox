#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>

#include "debugger.h"
#include "disasm.h"
#include "machine.h"

namespace {

void PrintUsage(const char *prog) {
    std::printf(
        "Usage: %s [options]\n"
        "Options:\n"
        "  --rom <path>           ROM/firmware binary to load at 0x00000\n"
        "  --dflash <path>        Data Flash binary to load at 0xF1000\n"
        "  --core <s1|s2|s3>      RL78 core profile (default: s3)\n"
        "  --pc <addr>            Override initial 20-bit PC (default: reset vector [0x00000])\n"
        "  --sp <addr>            Override initial 16-bit SP (default: 0x0000)\n"
        "  --trace                Print instruction trace during headless run\n"
        "  --max-steps <n>        Maximum instructions in headless mode (0 = unlimited)\n"
        "  --map                  Print memory map and exit\n"
        "  --gdb, -g              Start GDB RSP server\n"
        "  --gdb-port <port>      GDB RSP TCP port (default: 23946, implies --gdb)\n"
        "  --headless             Run headless (default)\n"
        "  --help, -h             Show this help message\n",
        prog ? prog : "rl78emu");
}

const char *StopReasonName(rl78::StopReason r) {
    switch (r) {
    case rl78::StopReason::None: return "None";
    case rl78::StopReason::Breakpoint: return "Breakpoint";
    case rl78::StopReason::Watchpoint: return "Watchpoint";
    case rl78::StopReason::BreakInsn: return "BreakInsn";
    case rl78::StopReason::Halt: return "Halt";
    case rl78::StopReason::Stop: return "Stop";
    case rl78::StopReason::UnmappedMemory: return "UnmappedMemory";
    case rl78::StopReason::InvalidInsn: return "InvalidInsn";
    case rl78::StopReason::WdtReset: return "WdtReset";
    }
    return "Unknown";
}

}  // namespace

int main(int argc, char *argv[]) {
    std::setvbuf(stdout, nullptr, _IONBF, 0);

    std::string rom_path;
    std::string dflash_path;
    rl78::CoreProfile core = rl78::CoreProfile::S3;
    int32_t pc_override = -1;
    int32_t sp_override = -1;
    bool trace = false;
    bool show_map = false;
    bool use_gdb = false;
    bool force_headless = false;
    int gdb_port = 23946;
    uint64_t max_steps = 0;

    for (int i = 1; i < argc; ++i) {
        const char *arg = argv[i];
        if (std::strcmp(arg, "--help") == 0 || std::strcmp(arg, "-h") == 0) {
            PrintUsage(argv[0]);
            return 0;
        } else if (std::strcmp(arg, "--rom") == 0 && i + 1 < argc) {
            rom_path = argv[++i];
        } else if (std::strcmp(arg, "--dflash") == 0 && i + 1 < argc) {
            dflash_path = argv[++i];
        } else if (std::strcmp(arg, "--core") == 0 && i + 1 < argc) {
            const char *c = argv[++i];
            if (std::strcmp(c, "s1") == 0 || std::strcmp(c, "S1") == 0) core = rl78::CoreProfile::S1;
            else if (std::strcmp(c, "s2") == 0 || std::strcmp(c, "S2") == 0) core = rl78::CoreProfile::S2;
            else core = rl78::CoreProfile::S3;
        } else if (std::strcmp(arg, "--pc") == 0 && i + 1 < argc) {
            pc_override = static_cast<int32_t>(std::strtoul(argv[++i], nullptr, 0) & rl78::Rl78Bus::kAddressMask);
        } else if (std::strcmp(arg, "--sp") == 0 && i + 1 < argc) {
            sp_override = static_cast<int32_t>(std::strtoul(argv[++i], nullptr, 0) & 0xFFFFu);
        } else if (std::strcmp(arg, "--trace") == 0) {
            trace = true;
        } else if (std::strcmp(arg, "--map") == 0) {
            show_map = true;
        } else if (std::strcmp(arg, "--max-steps") == 0 && i + 1 < argc) {
            max_steps = std::strtoull(argv[++i], nullptr, 0);
        } else if (std::strcmp(arg, "--gdb") == 0 || std::strcmp(arg, "-g") == 0) {
            use_gdb = true;
        } else if (std::strcmp(arg, "--gdb-port") == 0 && i + 1 < argc) {
            gdb_port = std::atoi(argv[++i]);
            use_gdb = true;
        } else if (std::strcmp(arg, "--headless") == 0) {
            force_headless = true;
            use_gdb = false;
        } else {
            std::fprintf(stderr, "Unknown or incomplete option: %s\n", arg);
            PrintUsage(argv[0]);
            return 1;
        }
    }

    rl78::Rl78Machine machine;
    machine.Configure(core, 0x080000u, 0x002000u, rl78::Rl78Bus::kDefaultRamStart);

    if (show_map) {
        std::printf("%s", machine.FormatMemoryMap().c_str());
        return 0;
    }

    if (!rom_path.empty()) {
        if (!machine.LoadRomFile(rom_path.c_str(), 0)) {
            std::fprintf(stderr, "Failed to load ROM image: %s\n", rom_path.c_str());
            return 1;
        }
    } else if (!use_gdb) {
        std::fprintf(stderr, "No ROM specified. Use --rom <path> or --gdb.\n");
        PrintUsage(argv[0]);
        return 1;
    }

    if (!dflash_path.empty() && !machine.LoadDataFlashFile(dflash_path.c_str(), 0)) {
        std::fprintf(stderr, "Failed to load Data Flash image: %s\n", dflash_path.c_str());
        return 1;
    }

    machine.Reset(pc_override);
    if (sp_override >= 0) {
        machine.cpu.SetSP(static_cast<uint16_t>(sp_override));
    }

    if (use_gdb && !force_headless) {
        rl78::Debugger dbg(&machine, gdb_port);
        if (!dbg.WaitForConnection()) {
            std::fprintf(stderr, "GDB server failed on port %d\n", gdb_port);
            return 1;
        }
        return 0;
    }

    rl78::StopInfo stop{};
    if (trace) {
        uint64_t step = 0;
        while (max_steps == 0 || step < max_steps) {
            const uint32_t pc_before = machine.cpu.GetPC();
            const rl78::DecodedInsn di = rl78::DisassembleAt(machine.bus, pc_before);
            stop = machine.Step(false);
            const uint8_t psw = machine.cpu.GetPSW();
            std::printf("%05X: %-40s AX=%04X BC=%04X DE=%04X HL=%04X SP=%04X CS=%X ES=%X [IE:%d RB:%d ISP:%d Z:%d AC:%d CY:%d] T=%llu\n",
                        pc_before,
                        di.FormatWithBytes().c_str(),
                        machine.cpu.ReadRegPair(rl78::RP_AX),
                        machine.cpu.ReadRegPair(rl78::RP_BC),
                        machine.cpu.ReadRegPair(rl78::RP_DE),
                        machine.cpu.ReadRegPair(rl78::RP_HL),
                        machine.cpu.GetSP(),
                        machine.cpu.GetCS(),
                        machine.cpu.GetES(),
                        (psw & rl78::PSW_IE) ? 1 : 0,
                        machine.cpu.GetRB(),
                        machine.cpu.GetISP(),
                        (psw & rl78::PSW_Z) ? 1 : 0,
                        (psw & rl78::PSW_AC) ? 1 : 0,
                        (psw & rl78::PSW_CY) ? 1 : 0,
                        static_cast<unsigned long long>(machine.cpu.TotalCycles()));
            ++step;
            if (stop.reason != rl78::StopReason::None) {
                break;
            }
        }
    } else {
        stop = machine.RunSteps(max_steps);
    }

    std::printf("Stopped (%s) at PC=0x%05X detail=0x%X\n%s\n",
                StopReasonName(stop.reason),
                stop.pc,
                stop.detail,
                machine.FormatStatus().c_str());
    return 0;
}
