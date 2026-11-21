import ctypes
import json
import os
import traceback

import ida_auto
import ida_bytes
import ida_dbg
import ida_expr
import ida_ida
import ida_idaapi
import ida_idd
import ida_idp
import ida_kernwin
import ida_lines
import ida_loader
import ida_pro
import ida_segment
import ida_ua
import idc

REPORT_PATH = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "build",
    "ida_headless_report.json",
)


def eval_idc(expr_str):
    rv = ida_expr.idc_value_t()
    err = ida_expr.eval_idc_expr(rv, ida_idaapi.BADADDR, expr_str)
    if err:
        raise RuntimeError(f"eval_idc_expr({expr_str!r}) failed: {err}")
    if rv.vtype == ida_expr.VT_STR:
        return rv.c_str()
    if rv.vtype == ida_expr.VT_INT64:
        return int(rv.i64)
    return int(rv.num)


def disasm_at(ea):
    text = ida_lines.generate_disasm_line(ea, 0)
    if text:
        return ida_lines.tag_remove(text).strip()
    return idc.GetDisasm(ea).strip()


def run_tests():
    ida_auto.auto_wait()
    report = {
        "ok": False,
        "checks": {},
        "segments": [],
        "reg_info": {},
        "ida_dbg": {},
        "step_trace": [],
        "rexec": {},
        "errors": [],
    }

    try:
        proc_name = ida_ida.inf_get_procname()
        proc_id = ida_idp.ph_get_id()
        report["checks"]["proc_name"] = proc_name
        report["checks"]["proc_id"] = proc_id
        assert proc_name.lower() in ("rl78", "rl78prox"), f"Unexpected proc_name {proc_name!r}"

        for i in range(ida_segment.get_segm_qty()):
            seg = ida_segment.getnseg(i)
            if seg is None:
                continue
            report["segments"].append({
                "name": ida_segment.get_segm_name(seg),
                "start": hex(seg.start_ea),
                "end": hex(seg.end_ea),
                "perm": seg.perm,
            })

        vec0 = ida_bytes.get_word(0x00000)
        insn = ida_ua.insn_t()
        insn_len = ida_ua.decode_insn(insn, vec0)
        assert insn_len > 0, f"Failed to decode reset entry insn at {hex(vec0)}"
        report["checks"]["reset_vector"] = hex(vec0)
        report["checks"]["entry_disasm"] = disasm_at(vec0)

        loaded_dbg = ida_dbg.load_debugger("rl78emu", False) or ida_dbg.load_debugger("rl78dbg.dll", False)
        if not loaded_dbg:
            ida_loader.load_plugin("rl78dbg")
            loaded_dbg = ida_dbg.load_debugger("rl78emu", False) or ida_dbg.load_debugger("rl78dbg.dll", False)
        report["ida_dbg"]["load_debugger"] = bool(loaded_dbg)
        assert loaded_dbg, "Failed to load rl78emu debugger backend"

        for rname in ["X", "A", "C", "B", "E", "D", "L", "H", "AX", "BC", "DE", "HL", "SP", "PSW", "CS", "ES", "CY"]:
            ri = ida_idp.reg_info_t()
            ok = ida_idp.parse_reg_name(ri, rname)
            assert ok, f"parse_reg_name failed for {rname!r}"
            report["reg_info"][rname] = {"reg": ri.reg, "size": ri.size}

        report["checks"]["host_exe"] = "ida.exe" if ctypes.windll.kernel32.GetModuleHandleW("ida.exe") else "idat.exe"

        started = ida_dbg.start_process("", "", "")
        report["ida_dbg"]["start_process"] = int(started)
        assert started == 1, f"start_process returned {started}"
        ida_dbg.wait_for_next_event(ida_dbg.WFNE_SUSP, 5)
        assert ida_dbg.get_process_state() == ida_dbg.DSTATE_SUSP

        pc0 = ida_dbg.get_reg_val("PC")
        psw0 = ida_dbg.get_reg_val("PSW")
        es0 = ida_dbg.get_reg_val("ES")
        report["ida_dbg"]["initial_pc"] = hex(pc0)
        report["ida_dbg"]["initial_psw"] = hex(psw0)
        report["ida_dbg"]["initial_es"] = hex(es0)
        assert pc0 == vec0, f"Expected initial PC={hex(vec0)}, got {hex(pc0)}"
        assert psw0 == 0x06, f"Expected initial PSW=0x06, got {hex(psw0)}"
        assert es0 == 0x0F, f"Expected initial ES=0x0F, got {hex(es0)}"

        dbg_reg_sample = {}
        for dr in ["SP", "AX", "BC", "DE", "HL", "A", "X", "CS", "ES", "PMC", "RB", "CY",
                   "IF0L", "MK0L", "CKC", "WDTE", "TCR00", "ITMC", "CYCLES"]:
            v = ida_dbg.get_reg_val(dr)
            assert v is not None, f"ida_dbg.get_reg_val({dr!r}) returned None"
            dbg_reg_sample[dr] = hex(v)
        report["ida_dbg"]["dbg_reg_sample"] = dbg_reg_sample

        idb_entry_bytes = ida_bytes.get_bytes(pc0, 4)
        dbg_entry_bytes = idc.get_bytes(pc0, 4, True)
        assert dbg_entry_bytes == idb_entry_bytes, (
            f"Live memory mismatch at {hex(pc0)}: {dbg_entry_bytes!r} vs {idb_entry_bytes!r}"
        )

        # Single step (step_into)
        assert ida_dbg.step_into()
        ida_dbg.wait_for_next_event(ida_dbg.WFNE_SUSP, 5)
        pc1 = ida_dbg.get_reg_val("PC")
        report["ida_dbg"]["pc_after_step_into"] = hex(pc1)
        assert pc1 != pc0

        # Test step_over on first CALL encountered in startup
        found_call = False
        bpt_target = None
        for _ in range(40):
            cur = ida_dbg.get_reg_val("PC")
            dline = disasm_at(cur).lower()
            if dline.startswith("call ") or dline.startswith("callt "):
                ins = ida_ua.insn_t()
                ilen = ida_ua.decode_insn(ins, cur)
                assert ilen > 0
                expected_ret = cur + ilen
                assert ida_dbg.step_over(), "step_over failed"
                ida_dbg.wait_for_next_event(ida_dbg.WFNE_SUSP, 5)
                pc_after_over = ida_dbg.get_reg_val("PC")
                report["ida_dbg"]["step_over_call_ea"] = hex(cur)
                report["ida_dbg"]["step_over_expected_pc"] = hex(expected_ret)
                report["ida_dbg"]["step_over_actual_pc"] = hex(pc_after_over)
                assert pc_after_over == expected_ret, (
                    f"step_over from {hex(cur)} landed at {hex(pc_after_over)}, expected {hex(expected_ret)}"
                )
                bpt_target = pc_after_over
                found_call = True
                break
            assert ida_dbg.step_into()
            ida_dbg.wait_for_next_event(ida_dbg.WFNE_SUSP, 5)
        assert found_call, "Did not encounter a call in first 40 startup steps"

        # Register write/readback via ida_dbg
        old_ax = ida_dbg.get_reg_val("AX")
        assert ida_dbg.set_reg_val("AX", 0xBEEF)
        assert ida_dbg.get_reg_val("AX") == 0xBEEF
        assert ida_dbg.get_reg_val("A") == 0xBE
        assert ida_dbg.set_reg_val("AX", old_ax)

        # RAM write & GPR mirror sync
        old_x = ida_dbg.get_dbg_byte(0xFFEF8)
        assert ida_dbg.put_dbg_byte(0xFFEF8, 0x77)
        assert ida_dbg.get_reg_val("X") == 0x77
        assert ida_dbg.put_dbg_byte(0xFFEF8, old_x)

        # Test execute breakpoint on next instruction
        ins2 = ida_ua.insn_t()
        ilen2 = ida_ua.decode_insn(ins2, bpt_target)
        assert ilen2 > 0
        next_bpt = bpt_target + ilen2
        assert ida_dbg.add_bpt(next_bpt)
        assert ida_dbg.continue_process()
        ida_dbg.wait_for_next_event(ida_dbg.WFNE_SUSP, 5)
        assert ida_dbg.get_reg_val("PC") == next_bpt
        assert ida_dbg.del_bpt(next_bpt)

        # Hardware write watchpoint test on the startup RAM-clear loop (writes 0xFFEDE down to 0xFFE20)
        wp_addr = 0xFFED0
        assert ida_dbg.add_bpt(wp_addr, 2, ida_idd.BPT_WRITE)
        assert ida_dbg.continue_process()
        ida_dbg.wait_for_next_event(ida_dbg.WFNE_SUSP, 5)
        assert ida_dbg.get_process_state() == ida_dbg.DSTATE_SUSP
        report["ida_dbg"]["watchpoint_addr"] = hex(wp_addr)
        report["ida_dbg"]["watchpoint_stop_pc"] = hex(ida_dbg.get_reg_val("PC"))
        assert ida_dbg.del_bpt(wp_addr)

        # Exercise ev_rexec
        rexec_res = ida_dbg.send_dbg_command("status")
        report["rexec"]["send_dbg_command_ok"] = bool(rexec_res is not None)

        assert ida_dbg.exit_process()
        ida_dbg.wait_for_next_event(ida_dbg.WFNE_SUSP, 5)

        # Exercise rl78dbg_* IDC helpers
        entry = eval_idc("rl78dbg_start()")
        assert entry == vec0, f"Expected rl78dbg_start()=={hex(vec0)}, got {hex(entry)}"

        for sidx in range(8):
            cpc = eval_idc('rl78dbg_get_reg("PC")')
            dtext = disasm_at(cpc)
            npc = eval_idc("rl78dbg_step(1)")
            report["step_trace"].append({
                "step": sidx,
                "pc": hex(cpc),
                "disasm": dtext,
                "next_pc": hex(npc),
            })

        assert eval_idc('rl78dbg_set_reg("AX", 0xCAFE)') == 1
        assert eval_idc('rl78dbg_get_reg("AX")') == 0xCAFE
        assert eval_idc("rl78dbg_write_u8(0xFFE50, 0xA5)") == 1
        assert eval_idc("rl78dbg_read_u8(0xFFE50)") == 0xA5
        assert eval_idc("rl78dbg_write_u16(0xFFE52, 0x1357)") == 1
        assert eval_idc("rl78dbg_read_u16(0xFFE52)") == 0x1357

        for cmd in ("status", "banks", "intc", "clock", "timers", "ports", "flash", "map"):
            out = eval_idc(f'rl78dbg_exec("{cmd}")')
            report["rexec"][cmd] = out
            assert out and "Unknown" not in out, f"rl78dbg_exec({cmd!r}) failed: {out!r}"

        # Flash / boot-cluster swap controls & registers
        for freg in ("BECTL", "PFCMD", "FLPMC", "FLRST"):
            fval = eval_idc(f'rl78dbg_get_reg("{freg}")')
            assert fval is not None and fval >= 0, f"rl78dbg_get_reg({freg!r}) failed: {fval!r}"
            report["checks"][f"reg_{freg}"] = fval

        assert eval_idc("rl78dbg_read_u16(0x00000)") == 0xE000
        assert eval_idc("rl78dbg_read_u16(0x01000)") == 0x209B
        assert (eval_idc('rl78dbg_get_reg("BECTL")') & 1) == 0

        swapped = eval_idc("rl78dbg_boot_swap()")
        assert swapped == 1, f"Expected rl78dbg_boot_swap()==1, got {swapped}"
        assert eval_idc("rl78dbg_read_u16(0x00000)") == 0x209B
        assert eval_idc("rl78dbg_read_u16(0x01000)") == 0xE000
        assert (eval_idc('rl78dbg_get_reg("BECTL")') & 1) == 1

        restored = eval_idc("rl78dbg_boot_swap()")
        assert restored == 0, f"Expected rl78dbg_boot_swap()==0, got {restored}"
        assert eval_idc("rl78dbg_read_u16(0x00000)") == 0xE000
        assert eval_idc("rl78dbg_read_u16(0x01000)") == 0x209B
        assert (eval_idc('rl78dbg_get_reg("BECTL")') & 1) == 0

        assert eval_idc("rl78dbg_stop()") == 1
        report["ok"] = True
    except Exception as exc:
        report["errors"].append(f"{exc}\n{traceback.format_exc()}")
    finally:
        os.makedirs(os.path.dirname(REPORT_PATH), exist_ok=True)
        with open(REPORT_PATH, "w", encoding="utf-8") as fp:
            json.dump(report, fp, indent=2)
        ida_pro.qexit(0 if report["ok"] else 1)


class _ReadyHooks(ida_kernwin.UI_Hooks):
    def ready_to_run(self):
        self.unhook()
        run_tests()


_READY_HOOKS = None

if __name__ == "__main__":
    if ctypes.windll.kernel32.GetModuleHandleW("ida.exe") != 0:
        _READY_HOOKS = _ReadyHooks()
        _READY_HOOKS.hook()
    else:
        run_tests()
