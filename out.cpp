#include "rl78.hpp"

extern ea_t calc_data_ea(const insn_t& insn, ea_t addr, bool require_prefix = false);

class out_rl78_t : public outctx_t {
	out_rl78_t(void) = delete; // not used
public:
	bool out_operand(const op_t& x);
	void out_insn(void);
};
CASSERT(sizeof(out_rl78_t) == sizeof(outctx_t));

DECLARE_OUT_FUNCS_WITHOUT_OUTMNEM(out_rl78_t)

bool out_rl78_t::out_operand(const op_t& x) {
	if (x.specval & kHasPrefix) {
		out_register(ph.reg_names[rES]);
		out_symbol(':');
	}
	switch (x.type) {
	case o_void:
		return false;
	case o_reg:
		out_register(ph.reg_names[x.reg]);
		return true;
	case o_phrase:
		out_symbol('[');
		switch (x.phrase) {
		case kHlReg:
			out_register(ph.reg_names[rHL]);
			out_symbol('+');
			out_register(ph.reg_names[x.ind_reg]);
			break;
		default:
			warning("o_phrase:%d\n", x.phrase);
			break;
		}
		out_symbol(']');
		return true;
	case o_displ:
		switch (x.phrase) {
		case kReg:
			out_symbol('[');
			out_register(ph.reg_names[x.ind_reg]);
			// special case for [hl] as frame pointer
			if (is_stkvar(get_flags(insn.ea), x.n)) {
				out_symbol('+');
				out_value(x, OOF_ADDR);
			}
			out_symbol(']');
			break;
		case kReg8:
			out_symbol('[');
			out_register(ph.reg_names[x.ind_reg]);
			out_symbol('+');
			out_value(x, OOF_ADDR | OOFW_16);
			out_symbol(']');
			break;
		case kReg16: {
			ea_t ea = calc_data_ea(insn, x.addr, true);
			if (ea == BADADDR || !out_name_expr(x, ea)) {
				out_value(x, OOF_ADDR | OOFW_16);
			}
			out_symbol('[');
			out_register(ph.reg_names[x.ind_reg]);
			out_symbol(']');
		} break;
		default:
			warning("o_displ:%d\n", x.phrase);
			break;
		}
		return true;
	case o_imm:
		out_symbol('#');
		out_value(x, OOFW_IMM);
		return true;
	case o_mem: {
		bool is_callt = (insn.itype == RL78_callt);
		if (is_callt)
			out_symbol('[');
		ea_t ea = calc_data_ea(insn, x.addr);
		if (ea == BADADDR || !out_name_expr(x, ea)) {
			out_value(x, OOF_ADDR | OOFW_24);
		}
		if (is_callt)
			out_symbol(']');
	} return true;
	case o_bit:
		if (x.addr_mode == kIndirect) {
			out_symbol('[');
		}
		switch (x.bit_base_type) {
		case o_reg:
			out_register(ph.reg_names[x.reg]);
			break;
		case o_mem: {
			ea_t ea = calc_data_ea(insn, x.addr);
			if (ea == BADADDR || !out_name_expr(x, ea)) {
				out_value(x, OOF_ADDR | OOFW_24);
			}
		} break;
		default:
			warning("o_bit:%d\n", x.bit_base_type);
			break;
		}
		if (x.addr_mode == kIndirect) {
			out_symbol(']');
		}
		out_symbol('.');
		out_value(x, OOFW_IMM);
		return true;
	case o_near:
	case o_far: {
		ea_t v = to_ea(insn.cs, x.addr);
		if (!out_name_expr(x, v, x.addr)) {
			out_value(x, OOF_ADDR | OOF_NUMBER | OOFW_24);
		}
	} return true;
	default:
		msg("%s:%d\n", __func__, x.type);
		return false;
	}
}

void out_rl78_t::out_insn(void) {
	out_mnemonic();

	out_one_operand(0);
	for (int i = 1; i < RL78_MAX_OPERANDS; i++) {
		if (insn.ops[i].type != o_void) {
			out_symbol(',');
			out_char(' ');
			out_one_operand(i);
		}
	}

	out_immchar_cmts();
	flush_outbuf();
}