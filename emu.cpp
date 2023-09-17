#include "rl78.hpp"


bool has_prefix(const insn_t& insn) {
	return insn.auxpref & kHasPrefix;
}

bool has_prefix(const op_t& op) {
	return op.specval & kHasPrefix;
}

// Convert |addr| to a 20bit addr, taking into account value of ES at insn.ea
// Returns BADDADDR if ES is not known
// If |require_prefix|, returns BADADDR if |insn| does not use ES
ea_t calc_data_ea(const insn_t& insn, ea_t addr,bool require_prefix = false) {
	if (has_prefix(insn)) {
		auto es = get_sreg(insn.ea, rES);
		if (es == BADSEL) {
			return BADADDR;
		}
		addr |= es << 16;
	}
	else if (require_prefix) {
		return BADADDR;
	}
	return addr;
}

/**
 * @brief Handle an operand in a disassembled instruction.
 *
 * This function handles the operands of disassembled instructions and updates
 * the instruction attributes accordingly (e.g., immediate values, displacements,
 * memory references, etc.)
 *
 * @param insn    Disassembled instruction.
 * @param op_idx  Index of the operand to handle.
 * @param is_alt  Flag indicating if this is an alternate operand (not used here).
 * @param is_load Flag indicating if this is a load operation.
 * @param flow    Pointer to a boolean that indicates if the function returns.
 */
static void handle_operand(const insn_t& insn, int op_idx, bool is_alt,
	bool is_load, bool* flow) {
	auto& op = insn.ops[op_idx];
	ea_t ea;  // Effective address

	flags_t F = get_flags(insn.ea);  // Get instruction flags

	switch (op.type) {
	case o_imm:
		set_immd(insn.ea);
		break;
	case o_displ:
	case o_mem:
	case o_bit:  // Handling o_bit similar to o_displ and o_mem
		if (op.type == o_bit && op.bit_base_type != o_mem) {
			break; // Skip if bit_base_type is not o_mem
		}
		// Calculate effective address
		ea = calc_data_ea(insn, op.addr, op.type == o_displ);
		if (ea != BADADDR) {
			insn.create_op_data(ea, op);
			insn.add_dref(ea, op.offb, is_load ? dr_R : dr_W);
		}
		break;
	case o_near:
	case o_far:
		ea = map_code_ea(insn, op);
		bool is_far = op.type == o_far;
		bool is_call = has_insn_feature(insn.itype, CF_CALL);
		insn.add_cref(ea, op.offb, is_far ? (is_call ? fl_CF : fl_JF) : (is_call ? fl_CN : fl_JN));
		if (*flow && is_call) {
			*flow = func_does_return(ea);
		}
		break;
	}

	// Check if a stack variable can be created
	if (!has_prefix(op) && may_create_stkvars() && !is_defarg(F, op.n)) {
		if (op.type == o_displ && op.ind_reg == rHL) {
			func_t* pfn = get_func(insn.ea);
			if (pfn && (pfn->flags & FUNC_FRAME)) {
				if (insn.create_stkvar(op, op.addr, STKVAR_VALID_SIZE)) {
					op_stkvar(insn.ea, op.n);
				}
			}
		}
	}
}


/*
static void handle_operand(const insn_t &insn, int op_idx, bool is_alt,
	bool is_load, bool *flow) {
	auto &op = insn.ops[op_idx];
	ea_t ea;
	switch (op.type) {
	case o_imm:
		set_immd(insn.ea);
		break;
	case o_displ:
	case o_mem:
		ea = calc_data_ea(insn, op.addr, op.type == o_displ);
		if (ea == BADADDR) {
			break;
		}
		insn.create_op_data(ea, op);
		insn.add_dref(ea, op.offb, is_load ? dr_R : dr_W);
		break;
	case o_bit:
		switch (op.bit_base_type) {
		case o_mem:
			ea = calc_data_ea(insn, op.addr);
			if (ea == BADADDR) {
				break;
			}
			insn.create_op_data(ea, op);
			insn.add_dref(ea, op.offb, is_load ? dr_R : dr_W);
			break;
		}
		break;
	case o_near:
	case o_far:
		// mark call/jump near/far
		ea = map_code_ea(insn, op);
		bool is_far = op.type == o_far;
		bool is_call = has_insn_feature(insn.itype, CF_CALL);
		insn.add_cref(ea, op.offb, is_far ? (is_call ? fl_CF : fl_JF) : (is_call ? fl_CN : fl_JN));
		if (*flow && is_call) {
			*flow = func_does_return(ea);
		}
		break;
	}

	flags_t F = get_flags(insn.ea);
	if (!has_prefix(op) && may_create_stkvars() && !is_defarg(F, op.n)) {
		if (op.type == o_displ && op.ind_reg == rHL) {
			func_t *pfn = get_func(insn.ea);
			if (!pfn || !(pfn->flags & FUNC_FRAME)) {
				return;
			}
			if (insn.create_stkvar(op, op.addr, STKVAR_VALID_SIZE)) {
				op_stkvar(insn.ea, op.n);
			}
		}
	}
}
*/

// TODO could be tricky to catch segreg updates via mem writes through prefixed
// insns, but probably will never happen in compiler generated code?
static void handle_segreg_update(const insn_t& insn, RL78Register reg) {
	// mov es, (#byte, a, saddr)
	// only mov from immediate sets a concrete value, others set to BADSEL
	// same for cs
	if (insn.itype == RL78_mov && insn.Op1.type == o_reg && insn.Op1.reg == reg) {
		auto& src = insn.Op2;
		sel_t val = BADSEL;
		if (src.type == o_imm) {
			val = src.value;
		}
		split_sreg_range(insn.ea, reg, val, SR_auto);
	}
}

static bool is_skip_insn(const insn_t& insn) {
	return insn.itype == RL78_skc || insn.itype == RL78_sknc ||
		insn.itype == RL78_skz || insn.itype == RL78_sknz ||
		insn.itype == RL78_skh || insn.itype == RL78_sknh;
}

static void trace_sp(const insn_t& insn) {
	adiff_t delta = 0;
	bool fuzzy = false;

	switch (insn.itype) {
	case RL78_push:
	case RL78_pop:
		delta = (insn.itype == RL78_push) ? -2 : 2;
		break;
	case RL78_addw:
	case RL78_subw:
		// addw/subw with sp as dst implies src is #byte
		if (!insn.Op1.is_reg(rSP)) {
			return;
		}
		delta = insn.Op2.value;
		if (insn.itype == RL78_subw) {
			delta = -delta;
		}
		break;
	case RL78_movw:
		// treat any mov to sp as untraceable
		if (!insn.Op1.is_reg(rSP)) {
			return;
		}
		fuzzy = true;
		break;
	default:
		return;
	}

	func_t* pfn = get_func(insn.ea);
	if (!pfn) {
		return;
	}
	if (fuzzy) {
#if (IDA_SDK_VERSION >= 710)
		// TODO is this correct?
		pfn->flags |= FUNC_FUZZY_SP;
		update_func(pfn);
#endif
		return;
	}

	add_auto_stkpnt(pfn, insn.ea + insn.size, delta);
}

void rl78_t::create_func_frame(func_t* pfn) {
	ea_t ea = pfn->start_ea;
	insn_t insn;
	sval_t frsize = 0;
	ushort frregs = 0;
	// Don't track functions which `push psw`
	// This convention seems to only be used by "OS" funcs, which don't setup
	// a stack frame with local vars, anyways.
	bool saves[4]{};

	for (int i = 0; i < 10 && ea < pfn->end_ea; i++) {
		if (!decode_insn(&insn, ea)) {
			break;
		}
		// push rp
		if (insn.itype == RL78_push && !insn.Op1.is_reg(rPSW)) {
			auto& reg_saved = saves[insn.Op1.reg - rAX];
			if (!reg_saved) {
				frregs += 2;
				reg_saved = true;
			}
			else {
				frsize += 2;
			}
		}
		// movw hl, sp
		else if (insn.itype == RL78_movw && insn.Op1.is_reg(rHL) &&
			insn.Op2.is_reg(rSP)) {
			pfn->flags |= FUNC_FRAME | FUNC_BOTTOMBP;
			// expected to be last stack-setup insn
			break;
		}
		// subw sp, #byte
		else if (insn.itype == RL78_subw && insn.Op1.is_reg(rSP)) {
			frsize += insn.Op2.value;
		}
		// prologue sequence ended without setting hl
		else {
			// stop now so frame doesn't include space pushed for calls
			break;
		}
		ea += insn.size;
	}

	if (frsize || frregs) {
		add_frame(pfn, frsize, frregs, 0);
	}
}

void rl78_t::is_sp_based(int* mode, const insn_t& insn, const op_t& op) {
	*mode = OP_SP_ADD | (op.is_reg(rSP) ? OP_SP_BASED : OP_FP_BASED);
}

static void fuse_far_ptrs(const insn_t& insn) {
	// try to create dref from insn pattern:
	// movw rp, #word
	// mov r, #byte
	// ...where r:rp is valid addr
	// This won't catch all far ptrs (e.g. when each value is push'd, or insn
	// order is inverted, etc), but it works most of the time.
	if (insn.itype == RL78_mov && insn.Op1.type == o_reg &&
		insn.Op2.type == o_imm && (insn.Op2.value >> 4) == 0) {
		insn_t prev;
		if (decode_prev_insn(&prev, insn.ea) > 0 && prev.itype == RL78_movw &&
			insn.Op1.type == o_reg && prev.Op2.type == o_imm) {
			// last sanity check - check for reg overlap
			if (prev.Op1.reg == rAX + (insn.Op1.reg / 2)) {
				return;
			}

			ea_t seg_base = insn.Op2.value << 16;
			ea_t to = seg_base | prev.Op2.value;

			refinfo_t ri;
			ri.init(REF_OFF32 | REFINFO_NOBASE, seg_base);
			op_offset_ex(prev.ea, prev.Op2.n, &ri);

			prev.add_dref(to, prev.Op2.offb, dr_O);
		}
	}
}

int rl78_t::rl78_emu(const insn_t& insn) {
	uint32 feature = insn.get_canon_feature(PH);
	bool flow = (feature & CF_STOP) == 0;

	bool flag1 = is_forced_operand(insn.ea, 0);
	bool flag2 = is_forced_operand(insn.ea, 1);

	if (feature & CF_USE1) {
		handle_operand(insn, 0, flag1, true, &flow);
	}
	if (feature & CF_USE2) {
		handle_operand(insn, 1, flag2, true, &flow);
	}
	if (feature & CF_CHG1) {
		handle_operand(insn, 0, flag1, false, &flow);
	}
	if (feature & CF_CHG2) {
		handle_operand(insn, 1, flag2, false, &flow);
	}

	if (is_skip_insn(insn)) {
		insn_t next_insn;
		if (decode_insn(&next_insn, insn.ea + insn.size)) {
			add_cref(insn.ea, next_insn.ea + next_insn.size, fl_JN);
		}
	}

	if (flow) {
		add_cref(insn.ea, insn.ea + insn.size, fl_F);
	}

	handle_segreg_update(insn, rES);
	handle_segreg_update(insn, rCS);

	fuse_far_ptrs(insn);

	// handle sp modifications
	if (may_trace_sp()) {
		if (!flow) {
			recalc_spd(insn.ea);
		}
		else {
			trace_sp(insn);
		}
	}

	return 1;
}
