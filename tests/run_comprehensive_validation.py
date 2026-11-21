import ida_ida
import ida_funcs
import ida_segment
import ida_ua
import ida_bytes
import ida_frame
import ida_nalt
import ida_xref
import ida_auto
import ida_typeinf
import idc
import idautils
import sys

def main():
    print("==================================================================")
    print("   RL78PROX COMPREHENSIVE REAL-WORLD VALIDATION SUITE            ")
    print("   Target Database: DOL-1001-VTE-1001-00703030.i64 (1MB PS4 Syscon ROM) ")
    print("==================================================================")

    # 1. Check processor identification
    proc_name = ida_ida.inf_get_procname()
    print(f"[TEST 1] Processor Module: '{proc_name}'")
    assert proc_name.lower() in ("rl78", "rl78prox"), f"Unexpected processor {proc_name}"
    print(" -> PASSED: Module identified correctly.\n")

    # 2. Instruction decoding coverage across database
    print("[TEST 2] Analyzing instruction decoding coverage across 100,000+ instructions...")
    total_insns = 0
    decode_errors = 0
    branches = 0
    calls = 0
    callts = 0

    for head in idautils.Heads(0, 0x100000):
        if ida_bytes.is_code(ida_bytes.get_flags(head)):
            total_insns += 1
            insn = ida_ua.insn_t()
            sz = ida_ua.decode_insn(insn, head)
            if sz <= 0:
                decode_errors += 1
            else:
                mnem = idc.print_insn_mnem(head).lower()
                if mnem in ("br", "bc", "bnc", "bz", "bnz", "bh", "bnh", "bt", "bf"):
                    branches += 1
                elif mnem in ("call", "callt"):
                    if mnem == "callt":
                        callts += 1
                    calls += 1

    print(f" -> Total instructions decoded: {total_insns}")
    print(f" -> Branches decoded: {branches}")
    print(f" -> Calls decoded: {calls} (callt table calls: {callts})")
    print(f" -> Decode errors: {decode_errors}")
    assert decode_errors == 0, f"Encountered {decode_errors} decode failures!"
    assert total_insns > 100000, f"Expected >100,000 instructions, found {total_insns}"
    print(" -> PASSED: 100% clean instruction decoding coverage with 0 errors.\n")

    # 3. Stack return size verification across functions
    print("[TEST 3] Verifying stack return size across real-world functions...")
    func_count = 0
    checked_funcs = 0
    for f_ea in idautils.Functions():
        func_count += 1
        pfn = ida_funcs.get_func(f_ea)
        if pfn:
            retsize = ida_frame.get_frame_retsize(pfn)
            assert retsize == 4, f"Function 0x{f_ea:X} has retsize {retsize}, expected 4"
            checked_funcs += 1

    print(f" -> Total functions verified: {checked_funcs} / {func_count}")
    print(" -> PASSED: All functions accurately report 4-byte RL78 stack return size.\n")

    # 4. Function Frame & Stack Variable Analysis
    print("[TEST 4] Testing function frame & local variable analysis on sub_2429...")
    f_2429 = 0x2429
    end_2429 = 0x250E
    # Delete and re-add function to trigger fresh frame analysis via our processor module
    ida_funcs.del_func(f_2429)
    ida_funcs.add_func(f_2429, end_2429)
    ida_auto.auto_wait()

    pfn_2429 = ida_funcs.get_func(f_2429)
    assert pfn_2429 is not None, "Failed to find sub_2429 after add_func"
    print(f" -> sub_2429 frame: frsize=0x{pfn_2429.frsize:X}, frregs=0x{pfn_2429.frregs:X}")
    print(f" -> FUNC_FRAME flag: {bool(pfn_2429.flags & ida_funcs.FUNC_FRAME)}")
    print(f" -> FUNC_BOTTOMBP flag: {bool(pfn_2429.flags & ida_funcs.FUNC_BOTTOMBP)}")
    assert pfn_2429.flags & ida_funcs.FUNC_FRAME, "Expected FUNC_FRAME on sub_2429"
    assert pfn_2429.frsize >= 6, f"Expected frsize >= 6, got {pfn_2429.frsize}"
    assert pfn_2429.frregs == 8, f"Expected frregs == 8, got {pfn_2429.frregs}"

    # Verify stack operands
    stk_found = 0
    for head in idautils.Heads(pfn_2429.start_ea, pfn_2429.end_ea):
        dis = idc.generate_disasm_line(head, 0)
        if "[hl+" in dis.lower() or "var_" in dis.lower():
            stk_found += 1
            if stk_found <= 5:
                print(f"    [0x{head:X}] {dis}")

    print(f" -> Total local stack variable accesses detected: {stk_found}")
    assert stk_found >= 10, f"Expected >= 10 stack variable accesses, got {stk_found}"
    print(" -> PASSED: Frame pointer (HL) and local stack variables successfully created.\n")

    # 5. Switch Jump Table Analysis at 0xD365
    print("[TEST 5] Testing Far 32-bit switch jump table analysis at 0xD365...")
    # Force re-analysis of the indirect jump at 0xD365
    ida_bytes.del_items(0xD365, ida_bytes.DELIT_SIMPLE, 2)
    ida_ua.create_insn(0xD365)
    ida_auto.auto_wait()

    si = ida_nalt.switch_info_t()
    has_switch = ida_nalt.get_switch_info(si, 0xD365)
    assert has_switch, "Failed to detect switch at 0xD365!"
    print(f" -> Switch detected at 0xD365:")
    print(f"    Table address: 0x{si.jumps:X}")
    print(f"    Element size:  {si.get_jtable_element_size()} bytes")
    print(f"    Cases count:   {si.ncases}")
    print(f"    Table flags:   0x{si.flags:X}")
    assert si.jumps == 0xD368, f"Expected jumps at 0xD368, got 0x{si.jumps:X}"
    assert si.get_jtable_element_size() == 4, f"Expected element size 4, got {si.get_jtable_element_size()}"
    assert si.ncases >= 4, f"Expected >= 4 cases, got {si.ncases}"

    # Verify code xrefs from 0xD365 to targets
    crefs = list(idautils.CodeRefsFrom(0xD365, 1))
    print(f"    Cross-references created to case targets: {[hex(x) for x in crefs]}")
    assert len(crefs) >= 3, f"Expected >= 3 case target xrefs, got {len(crefs)}"
    assert 0xD3A4 in crefs, "Expected 0xD3A4 in case xrefs"
    assert 0xD44E in crefs, "Expected 0xD44E in case xrefs"
    print(" -> PASSED: 32-bit far switch table and case xrefs accurately resolved.\n")

    # 6. Type library and calling convention verification
    print("[TEST 6] Testing compiler type definitions and calling conventions...")
    assert ida_ida.inf_get_cc_size_i() == 2, "Expected sizeof(int) == 2"
    assert ida_ida.inf_get_cc_size_l() == 4, "Expected sizeof(long) == 4"
    assert ida_ida.inf_get_cc_defalign() == 2, "Expected defalign == 2"

    tif = ida_typeinf.tinfo_t()
    parsed = ida_typeinf.parse_decl(tif, None, "int test_fn(int a, char b, long c);", ida_typeinf.PT_SIL)
    assert parsed, "Failed to parse test function declaration"
    fi = ida_typeinf.func_type_data_t()
    assert tif.get_func_details(fi), "Failed to get function details"
    print(f" -> Function: {tif}")
    print(f"    arg 0 ({fi[0].name}): reg={fi[0].argloc.reg1()} (rAX)")
    print(f"    arg 1 ({fi[1].name}): reg={fi[1].argloc.reg1()} (rC)")
    if fi[2].argloc.is_stkoff():
        print(f"    arg 2 ({fi[2].name}): stack offset = {fi[2].argloc.stkoff()} (aligned stack param)")
    assert fi[0].argloc.reg1() == 8, "Expected arg 0 in rAX"
    assert fi[1].argloc.reg1() == 2, "Expected arg 1 in rC"
    assert fi[2].argloc.is_stkoff(), "Expected arg 2 on stack (registers exhausted)"
    print(" -> PASSED: CC-RL calling conventions and type rules verified.\n")

    print("==================================================================")
    print("   ALL REAL-WORLD VALIDATION SUITE TESTS PASSED (100% SUCCESS)    ")
    print("==================================================================")
    idc.qexit(0)

if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        print(f"\n[ERROR] TEST FAILED: {e}")
        import traceback
        traceback.print_exc()
        idc.qexit(1)
