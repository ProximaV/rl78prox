// Renesas RL78 processor module for IDA
// Based on R01US0015EJ0220, Rev.2.20, Nov 20, 2014

#include "rl78.hpp"
extern ea_t calc_data_ea(const insn_t& insn, ea_t addr, bool require_prefix = false);

int data_id;
static const char *const reg_names[] = {
	"x", "a", "c", "b", "e", "d", "l", "h", "ax", "bc", "de", "hl",
	"rb0", "rb1", "rb2", "rb3",
	"psw", "sp",
	"cy",
	"vcs", "vds",
	"cs", "es",
};
static_assert(qnumber(reg_names) == r_count, "array doesn't match enum");


static const asm_t assembler = {
	AS_COLON | AS_N2CHR | ASH_HEXF0 | ASD_DECF0 | ASB_BINF0 | AS_ONEDUP | AS_NOXRF,
	0,
	"RL78 Assembler",
	0,
	nullptr,		// array of automatically generated header lines
					// they appear at the start of disassembled text
	".org",			// org directive
	".end",			// end directive
	";",			// comment string (see also cmnt2)
	'"',			// string literal delimiter
	'\'',			// char constant delimiter
	"'\"",			// special chars that can not appear
					// as is in string and char literals
	// Data representation (db,dw,...):
	".db",			// ascii
	".db",			// byte
	".dw",			// word
	".dd",			// dword
	nullptr,		// qword
	nullptr,		// oword
	nullptr,		// float
	nullptr,		// double
	nullptr,		// tbytes
	nullptr,		// packreal
	nullptr,		// dups
	nullptr,		// bss
	".equ",			// equ
	nullptr,		// seg
	"$",			// curip
	nullptr,		// out_func_header
	nullptr,		// out_func_footer
	nullptr,		// public
	nullptr,		// weak
	nullptr,		// extern
	nullptr,		// communal variable
	nullptr,		// get_type_name
	nullptr,		// align
	'(',			// lbrace
	')',			// rbrace
	// Assembler-time operators
	nullptr,		// %
	nullptr,		// &
	nullptr,		// |
	nullptr,		// ^
	nullptr,		// ~
	nullptr,		// <<
	nullptr,		// >>
	nullptr,		// size of type (format string)
	0,				// flag2
	nullptr,		// cmnt2
	nullptr,		// low8
	nullptr,		// high8
	nullptr,		// low16
	nullptr,		// high16
	nullptr,		// include_fmt
	nullptr,		// vstruc_fmt
	nullptr,		// rva
	nullptr,		// yword
};




idaman int ida_export is_align_insn(ea_t ea) {
	insn_t insn;
	if (decode_insn(&insn, ea) < 1) {
		return 0;
	}
	switch (insn.itype) {
	case RL78_brk1:
		break;
	default:
		return 0;
	}
	return insn.size;
}

static void newfile(char *fname) {
	// load config file or smth
	// TODO should respect device specific code/data flash + ram ranges
}

static int get_reg_info(const char **main_regname, bitrange_t *bitrange, const char *regname)
{
	if (regname == nullptr || regname[0] == '\0')
		return -1;

	static const struct
	{
		const char *name;
		const char *main;
		uint16 off;
		uint16 size;
	} regs[] =
	{
		{ "x",   "ax", 0,  8 },
		{ "a",   "ax", 8,  8 },
		{ "c",   "bc", 0,  8 },
		{ "b",   "bc", 8,  8 },
		{ "e",   "de", 0,  8 },
		{ "d",   "de", 8,  8 },
		{ "l",   "hl", 0,  8 },
		{ "h",   "hl", 8,  8 },
		{ "ax",  "ax", 0, 16 },
		{ "bc",  "bc", 0, 16 },
		{ "de",  "de", 0, 16 },
		{ "hl",  "hl", 0, 16 },
		{ "sp",  "sp", 0, 16 },
		{ "psw", "psw", 0, 16 },
		{ "cs",  "cs", 0,  8 },
		{ "es",  "es", 0,  8 },
	};

	for (const auto &r : regs)
	{
		if (strieq(regname, r.name))
		{
			if (main_regname != nullptr)
				*main_regname = r.main;
			if (bitrange != nullptr)
				*bitrange = bitrange_t(r.off, r.size);
			return 1;
		}
	}
	return -1;
}

// not sure why, but this doesn't seem to be called very often
static int may_be_func(const insn_t &insn, int state) {
	int prob = 0;
	if (insn.itype == RL78_push) {
		prob = 100;
	}
	return prob;
}

/*
2F0EE is more complex...

10 subw    ax, #X | sub a, #X	adj
10 shr      a, #X

9  cmpw    ax, #N | cmp a, #N	ncases

8  skc
7  br      default				default if adj(idx) >= ncases

7, 8 could be replaced with `bnc default` (closer target)

6  shrw    ax, #8				move a to x

common chunk
5  movw    bc, ax
   mov     es, #2				don't need to care since we track segregs
4  mov     a, es:byte_2CEE2[bc]
3  shlw    bc, #1
2  mov     cs, a
1  movw    ax, es:word_2CED8[bc]
0  br      ax
*/
//#define JUMP_DEBUG
#include "jptcmn.cpp"
static const char rl78_jmp_roots[] = { 1, 2, 0 };
static const char rl78_jmp_depends[][2] = {
	{ 1, 2 },	// 0: ax, cs
	{ 3 },		// 1: bc
	{ 4 },		// 2: cs
	{ 5 },		// 3: bc
	{ 5 },		// 4: bc
	{ -6 },	    // 5: ax
	{ },		// 6: optional shrw ax, #8
};
class rl78_jmp_pattern_t : public jump_pattern_t {
public:
	rl78_jmp_pattern_t(switch_info_t *si)
		: jump_pattern_t(si, rl78_jmp_roots, rl78_jmp_depends) {
	}
	bool jpi6() final;
	bool jpi5() final;
	bool jpi4() final;
	bool jpi3() final;
	bool jpi2() final;
	bool jpi1() final;
	bool jpi0() final;

	RL78Register table_reg;
	ea_t ax_table{ BADADDR };
	ea_t cs_table{ BADADDR };
};

bool rl78_jmp_pattern_t::jpi6() {
	msg("%x jpi6: %s\n", insn.ea, instructions[insn.itype].name);
	return true;
}

bool rl78_jmp_pattern_t::jpi5() {
	return insn.itype == RL78_movw && insn.Op1.is_reg(table_reg) && insn.Op2.is_reg(rAX);
}

bool rl78_jmp_pattern_t::jpi4() {
	// don't necessarily need to limit to rA here (could be immediate in jpi2)
	if (insn.itype == RL78_mov && insn.Op1.is_reg(rA) &&
		insn.Op2.type == o_displ && (insn.Op2.phrase == kReg8 || insn.Op2.phrase == kReg16) && insn.Op2.ind_reg == table_reg) {
		ea_t ea = calc_data_ea(insn, insn.Op2.addr, true);
		if (ea == BADADDR) {
			return false;
		}
		cs_table = ea;
		return true;
	}
	return false;
}

bool rl78_jmp_pattern_t::jpi3() {
	return insn.itype == RL78_shlw && insn.Op1.is_reg(table_reg) && insn.Op2.is_imm(1);
}

bool rl78_jmp_pattern_t::jpi2() {
	if (!(insn.itype == RL78_mov && insn.Op1.is_reg(rCS))) {
		return false;
	}
	bool src_is_a = insn.Op2.is_reg(rA);
	if (!src_is_a) {
		// would be simple to handle, just haven't seen it
		msg("jmptbl: cs not from reg\n");
	}
	return src_is_a;
}

bool rl78_jmp_pattern_t::jpi1() {
	if (insn.itype == RL78_movw && insn.Op1.is_reg(rAX) &&
		insn.Op2.type == o_displ && (insn.Op2.phrase == kReg8 || insn.Op2.phrase == kReg16)) {
		ea_t ea = calc_data_ea(insn, insn.Op2.addr, true);
		if (ea == BADADDR) {
			return false;
		}
		ax_table = ea;
		table_reg = (RL78Register)insn.Op2.ind_reg;
		return true;
	}
	return false;
}

bool is_br_ax(const insn_t &insn) {
	return insn.itype == RL78_br && insn.Op1.is_reg(rAX);
}

bool rl78_jmp_pattern_t::jpi0() {
	return is_br_ax(insn);
}

static const char rl78_near_jmp_roots[] = { 1, 0 };
static const char rl78_near_jmp_depends[][2] = {
	{ 1 },       // 0: ax
	{ 2 },       // 1: table_reg
	{ },         // 2: shlw table_reg, 1
};

class rl78_near_jmp_pattern_t : public jump_pattern_t {
public:
	rl78_near_jmp_pattern_t(switch_info_t *si)
		: jump_pattern_t(si, rl78_near_jmp_roots, rl78_near_jmp_depends) {}
	bool jpi2() final;
	bool jpi1() final;
	bool jpi0() final;

	RL78Register table_reg = rBC;
	ea_t table{ BADADDR };
};

bool rl78_near_jmp_pattern_t::jpi0() {
	return is_br_ax(insn);
}

bool rl78_near_jmp_pattern_t::jpi1() {
	if (insn.itype == RL78_movw && insn.Op1.is_reg(rAX) &&
		insn.Op2.type == o_displ && (insn.Op2.phrase == kReg8 || insn.Op2.phrase == kReg16)) {
		ea_t ea = calc_data_ea(insn, insn.Op2.addr, false);
		if (ea == BADADDR)
			return false;
		table = ea;
		table_reg = (RL78Register)insn.Op2.ind_reg;
		return true;
	}
	return false;
}

bool rl78_near_jmp_pattern_t::jpi2() {
	return insn.itype == RL78_shlw && insn.Op1.is_reg(table_reg) && insn.Op2.is_imm(1);
}

// 4-byte far interleaved table pattern:
// 6  shlw ax, #2
// 5  addw ax, #table
// 4  movw de, ax
// 3  mov a, [de+2]
// 2  mov cs, a
// 1  movw ax, [de+0]
// 0  br ax
static const char rl78_far_interleaved_roots[] = { 1, 0 };
static const char rl78_far_interleaved_depends[][2] = {
	{ 1 },      // 0: br ax -> 1 (movw ax, [de+0])
	{ 2 },      // 1: movw ax, [de+0] -> 2 (mov cs, a)
	{ 3 },      // 2: mov cs, a -> 3 (mov a, [de+2])
	{ 4 },      // 3: mov a, [de+2] -> 4 (movw de, ax)
	{ 5 },      // 4: movw de, ax -> 5 (addw ax, #table)
	{ 6 },      // 5: addw ax, #table -> 6 (shlw ax, #2)
	{ -7 },     // 6: shlw ax, #2 -> optional bounds (7)
	{ },        // 7: bounds check (and/cmp/dec)
};

class rl78_far_interleaved_pattern_t : public jump_pattern_t {
public:
	rl78_far_interleaved_pattern_t(switch_info_t *si)
		: jump_pattern_t(si, rl78_far_interleaved_roots, rl78_far_interleaved_depends) {}

	bool jpi7() final;
	bool jpi6() final;
	bool jpi5() final;
	bool jpi4() final;
	bool jpi3() final;
	bool jpi2() final;
	bool jpi1() final;
	bool jpi0() final;

	RL78Register table_reg = rDE;
	ea_t table = BADADDR;
	uint16 ncases = 0;
};

bool rl78_far_interleaved_pattern_t::jpi0() {
	return is_br_ax(insn);
}

bool rl78_far_interleaved_pattern_t::jpi1() {
	if (insn.itype == RL78_movw && insn.Op1.is_reg(rAX)
		&& insn.Op2.type == o_displ
		&& (insn.Op2.phrase == kReg8 || insn.Op2.phrase == kReg16)
		&& insn.Op2.addr == 0) {
		table_reg = (RL78Register)insn.Op2.ind_reg;
		return true;
	}
	return false;
}

bool rl78_far_interleaved_pattern_t::jpi2() {
	return insn.itype == RL78_mov && insn.Op1.is_reg(rCS) && insn.Op2.is_reg(rA);
}

bool rl78_far_interleaved_pattern_t::jpi3() {
	return insn.itype == RL78_mov && insn.Op1.is_reg(rA)
		&& insn.Op2.type == o_displ
		&& (insn.Op2.phrase == kReg8 || insn.Op2.phrase == kReg16)
		&& insn.Op2.ind_reg == table_reg
		&& insn.Op2.addr == 2;
}

bool rl78_far_interleaved_pattern_t::jpi4() {
	return insn.itype == RL78_movw && insn.Op1.is_reg(table_reg) && insn.Op2.is_reg(rAX);
}

bool rl78_far_interleaved_pattern_t::jpi5() {
	if (insn.itype == RL78_addw && insn.Op1.is_reg(rAX) && insn.Op2.type == o_imm) {
		table = calc_data_ea(insn, insn.Op2.value, false);
		if (table == BADADDR)
			table = insn.Op2.value;
		return true;
	}
	return false;
}

bool rl78_far_interleaved_pattern_t::jpi6() {
	return insn.itype == RL78_shlw && insn.Op1.is_reg(rAX) && insn.Op2.is_imm(2);
}

bool rl78_far_interleaved_pattern_t::jpi7() {
	if (insn.itype == RL78_and && insn.Op2.type == o_imm) {
		ncases = uint16(insn.Op2.value);
		return true;
	}
	if (insn.itype == RL78_cmp && insn.Op2.type == o_imm) {
		ncases = uint16(insn.Op2.value);
		return true;
	}
	return false;
}

static jump_table_type_t is_rl78_far_interleaved_pattern(switch_info_t *si, const insn_t &insn) {
	rl78_far_interleaved_pattern_t jp(si);
	if (jp.match(insn)) {
		si->jumps = jp.table;
		si->set_jtable_element_size(4);
		si->flags |= SWI_J32;
		if (jp.ncases != 0)
			si->ncases = jp.ncases;
		return JT_FLAT32;
	}
	return JT_NONE;
}

static void create_table(switch_info_t *si, const insn_t &insn, jump_table_type_t jtt) {
	if (si->is_custom()) {
		for (int i = 0; i < si->ncases; i++) {
			create_word(si->jumps + i * 2, 2);
			create_byte(si->custom + i, 1);
			uint16 ax_val = get_word(si->jumps + i * 2);
			uint8 cs_val = get_byte(si->custom + i);
			ea_t target = (ea_t(cs_val) << 16) | ax_val;
			add_cref(insn.ea, target, fl_JN);
		}
		if (si->defjump != BADADDR) {
			char buf[MAXSTR];
			qsnprintf(buf, sizeof(buf), "def_%a", insn.ip);
			if (!set_name(si->defjump, buf, SN_NOCHECK | SN_NOWARN | SN_LOCAL))
				set_name(si->defjump, buf, SN_NOCHECK | SN_NOWARN);
		}
		char buf[MAXSTR];
		qsnprintf(buf, sizeof(buf), "jpt_%a", insn.ip);
		set_name(si->jumps, buf, SN_NOCHECK | SN_NOWARN);
		set_switch_info(insn.ea, *si);
	}
	else {
		check_and_create_flat_jump_table(si, insn, jtt);
	}
}

static jump_table_type_t is_rl78_pattern(switch_info_t *si, const insn_t &insn) {
	rl78_jmp_pattern_t jp(si);
	if (jp.match(insn)) {
		if (jp.cs_table != BADADDR && jp.ax_table != BADADDR) {
			si->jumps = jp.ax_table;
			si->custom = jp.cs_table;
			si->flags |= SWI_CUSTOM | SWI_J32;
			si->set_jtable_element_size(2);
			return JT_FLAT32;
		}
		return JT_FLAT32;
	}
	return JT_NONE;
}

static jump_table_type_t is_rl78_near_pattern(switch_info_t *si, const insn_t &insn) {
	rl78_near_jmp_pattern_t jp(si);
	if (jp.match(insn)) {
		si->jumps = jp.table;
		si->set_jtable_element_size(2);
		segment_t *s = getseg(insn.ea);
		if (s != nullptr)
			si->set_elbase(s->start_ea);
		return JT_FLAT32;
	}
	return JT_NONE;
}

static int is_switch(switch_info_t *si, const insn_t &insn) {
	if (!is_br_ax(insn)) {
		return 0;
	}
	is_pattern_t *const patterns[] = {
		is_rl78_far_interleaved_pattern,
		is_rl78_pattern,
		is_rl78_near_pattern,
	};
	return check_for_table_jump(si, insn, patterns, qnumber(patterns),
		create_table) ? 1 : 0;
}

int rl78_create_switch_xrefs(ea_t insn_ea, const switch_info_t &si) {
	if (si.is_custom()) {
		for (int i = 0; i < si.ncases; i++) {
			uint16 ax_val = get_word(si.jumps + i * 2);
			uint8 cs_val = get_byte(si.custom + i);
			ea_t target = (ea_t(cs_val) << 16) | ax_val;
			add_cref(insn_ea, target, fl_JN);
		}
		if (si.defjump != BADADDR)
			add_cref(insn_ea, si.defjump, fl_JN);
		return 1;
	}
	create_switch_xrefs(insn_ea, si);
	return 1;
}

int rl78_calc_switch_cases(casevec_t *casevec, eavec_t *targets, ea_t insn_ea, const switch_info_t &si) {
	if (si.is_custom()) {
		svalvec_t vals;
		vals.push_back(0);
		for (int i = 0; i < si.ncases; i++) {
			uint16 ax_val = get_word(si.jumps + i * 2);
			uint8 cs_val = get_byte(si.custom + i);
			ea_t target = (ea_t(cs_val) << 16) | ax_val;
			if (targets != nullptr)
				targets->push_back(target);
			if (casevec != nullptr) {
				vals[0] = si.lowcase + i;
				casevec->push_back(vals);
			}
		}
		return 1;
	}
	return calc_switch_cases(casevec, targets, insn_ea, si) ? 1 : 0;
}

bool calc_rl78_retloc(argloc_t *retloc, const tinfo_t &type, cm_t cc) {
	qnotused(cc);
	if (type.is_void())
		return true;

	size_t size = type.get_size();
	if (size == BADSIZE || size == 0)
		return false;

	if (size == 1) {
		retloc->set_reg1(rA);
	}
	else if (size == 2) {
		retloc->set_reg1(rAX);
	}
	else if (size == 3) {
		// 3 bytes: C-AX (C is high byte, AX is low word)
		retloc->set_reg2(rAX, rC);
	}
	else if (size == 4) {
		if (type.is_ptr()) {
			// Far pointer: page in A, 16-bit offset in DE
			retloc->set_reg2(rDE, rA);
		}
		else {
			// Other 4 bytes (long, float, small struct): BC-AX (AX low word, BC high word)
			retloc->set_reg2(rAX, rBC);
		}
	}
	else {
		// >= 5 bytes: pointer to return value passed in AX (near pointer)
		retloc->set_reg1(rAX);
	}
	return true;
}

bool calc_rl78_arglocs(func_type_data_t *fti) {
	if (!calc_rl78_retloc(&fti->retloc, fti->rettype, fti->get_cc()))
		return false;

	bool ax_used = false;
	bool a_used = false;
	bool x_used = false;

	bool bc_used = false;
	bool b_used = false;
	bool c_used = false;

	bool de_used = false;
	bool d_used = false;
	bool e_used = false;

	size_t retsize = fti->rettype.is_void() ? 0 : fti->rettype.get_size();
	if (retsize != BADSIZE && retsize >= 5) {
		ax_used = true;
		a_used = true;
		x_used = true;
	}

	sval_t spoff = 0;

	for (size_t i = 0; i < fti->size(); ++i) {
		funcarg_t &fa = (*fti)[i];
		size_t size = fa.type.get_size();
		if (size == BADSIZE || size == 0)
			return false;

		bool allocated = false;

		if (size == 1) {
			if (!a_used && !ax_used) {
				fa.argloc.set_reg1(rA);
				a_used = true;
				allocated = true;
			}
			else if (!x_used && !ax_used) {
				fa.argloc.set_reg1(rX);
				x_used = true;
				allocated = true;
			}
			else if (!c_used && !bc_used) {
				fa.argloc.set_reg1(rC);
				c_used = true;
				allocated = true;
			}
			else if (!b_used && !bc_used) {
				fa.argloc.set_reg1(rB);
				b_used = true;
				allocated = true;
			}
			else if (!e_used && !de_used) {
				fa.argloc.set_reg1(rE);
				e_used = true;
				allocated = true;
			}
			else if (!d_used && !de_used) {
				fa.argloc.set_reg1(rD);
				d_used = true;
				allocated = true;
			}
		}
		else if (size == 2) {
			if (!ax_used && !a_used && !x_used) {
				fa.argloc.set_reg1(rAX);
				ax_used = true;
				a_used = true;
				x_used = true;
				allocated = true;
			}
			else if (!bc_used && !b_used && !c_used) {
				fa.argloc.set_reg1(rBC);
				bc_used = true;
				b_used = true;
				c_used = true;
				allocated = true;
			}
			else if (!de_used && !d_used && !e_used) {
				fa.argloc.set_reg1(rDE);
				de_used = true;
				d_used = true;
				e_used = true;
				allocated = true;
			}
		}
		else if (size == 3) {
			if (!c_used && !bc_used && !ax_used && !a_used && !x_used) {
				fa.argloc.set_reg2(rAX, rC);
				c_used = true;
				ax_used = true;
				a_used = true;
				x_used = true;
				allocated = true;
			}
			else if (!x_used && !ax_used && !bc_used && !b_used && !c_used) {
				fa.argloc.set_reg2(rBC, rX);
				x_used = true;
				bc_used = true;
				b_used = true;
				c_used = true;
				allocated = true;
			}
		}
		else if (size == 4) {
			if (fa.type.is_ptr()) {
				if (!de_used && !d_used && !e_used && !a_used && !ax_used) {
					fa.argloc.set_reg2(rDE, rA);
					de_used = true;
					d_used = true;
					e_used = true;
					a_used = true;
					allocated = true;
				}
				else if (!de_used && !d_used && !e_used && !x_used && !ax_used) {
					fa.argloc.set_reg2(rDE, rX);
					de_used = true;
					d_used = true;
					e_used = true;
					x_used = true;
					allocated = true;
				}
				else if (!de_used && !d_used && !e_used && !c_used && !bc_used) {
					fa.argloc.set_reg2(rDE, rC);
					de_used = true;
					d_used = true;
					e_used = true;
					c_used = true;
					allocated = true;
				}
				else if (!bc_used && !b_used && !c_used && !x_used && !ax_used) {
					fa.argloc.set_reg2(rBC, rX);
					bc_used = true;
					b_used = true;
					c_used = true;
					x_used = true;
					allocated = true;
				}
			}
			else {
				if (!ax_used && !a_used && !x_used && !bc_used && !b_used && !c_used) {
					fa.argloc.set_reg2(rAX, rBC);
					ax_used = true;
					a_used = true;
					x_used = true;
					bc_used = true;
					b_used = true;
					c_used = true;
					allocated = true;
				}
				else if (!bc_used && !b_used && !c_used && !de_used && !d_used && !e_used) {
					fa.argloc.set_reg2(rBC, rDE);
					bc_used = true;
					b_used = true;
					c_used = true;
					de_used = true;
					d_used = true;
					e_used = true;
					allocated = true;
				}
			}
		}

		if (!allocated) {
			spoff = (spoff + 1) & ~1;
			fa.argloc.set_stkoff(spoff);
			spoff += (size + 1) & ~1;
		}
	}

	fti->stkargs = spoff;
	return true;
}

ssize_t idaapi idb_listener_t::on_event(ssize_t code, va_list)
{
	/*
	switch (code)
	{
		// add stuff here...
		default: break;
	}
	*/

	return 0;
}
static ssize_t idaapi notify(void*, int msgid, va_list)
{
	if (msgid == processor_t::ev_get_procmod) return size_t(SET_MODULE_DATA(rl78_t));

	return 0;
}

void rl78_t::load_from_idb()
{
	ioh.restore_device();
	if (inf_get_cc_size_i() != 2) {
		inf_set_cc_id(COMP_GNU);
		inf_set_cc_cm(CM_N16_F32 | CM_CC_CDECL);
		inf_set_cc_defalign(2);
		inf_set_cc_size_i(2);
		inf_set_cc_size_b(1);
		inf_set_cc_size_e(2);
		inf_set_cc_size_s(2);
		inf_set_cc_size_l(4);
		inf_set_cc_size_ll(8);
		inf_set_cc_size_ldbl(4);
	}
}

//---------------------------------------------------------------------------------------------------------------------
bool rl78_t::rl78_find_ioport_bit(outctx_t& ctx, int port, int bit)
{
	const ioport_bit_t* b = find_ioport_bit(ioh.ports, port, bit);
	if (b != nullptr && !b->name.empty()) { ctx.out_line(b->name.c_str(), COLOR_IMPNAME); return true; }

	return false;
}

ssize_t idaapi rl78_t::on_event(ssize_t msgid, va_list va)
{
	switch (msgid) {
	case processor_t::ev_setup_til:
	{
		inf_set_cc_id(COMP_GNU);
		inf_set_cc_cm(CM_N16_F32 | CM_CC_CDECL);
		inf_set_cc_defalign(2);
		inf_set_cc_size_i(2);
		inf_set_cc_size_b(1);
		inf_set_cc_size_e(2);
		inf_set_cc_size_s(2);
		inf_set_cc_size_l(4);
		inf_set_cc_size_ll(8);
		inf_set_cc_size_ldbl(4);
		add_til("gnucmn", ADDTIL_DEFAULT);
		return 1;
	}
	case processor_t::ev_max_ptr_size:
		return 4;
	case processor_t::ev_calc_cdecl_purged_bytes:
		return 0;
	case processor_t::ev_get_cc_regs:
	{
		callregs_t *callregs = va_arg(va, callregs_t *);
		callcnv_t cc = va_arg(va, callcnv_t);
		qnotused(cc);
		static const int rl78_argregs[] = { rAX, rBC, rDE, -1 };
		callregs->set(ARGREGS_INDEPENDENT, rl78_argregs, nullptr);
		return 1;
	}
	case processor_t::ev_calc_retloc:
	{
		argloc_t *retloc = va_arg(va, argloc_t *);
		const tinfo_t *type = va_arg(va, const tinfo_t *);
		cm_t cc = va_arg(va, cm_t);
		return calc_rl78_retloc(retloc, *type, cc) ? 1 : -1;
	}
	case processor_t::ev_calc_arglocs:
	{
		func_type_data_t *fti = va_arg(va, func_type_data_t *);
		return calc_rl78_arglocs(fti) ? 1 : -1;
	}
	case processor_t::ev_newfile:
	{
		char cfgfile[QMAXFILE];
		ioh.get_cfg_filename(cfgfile, sizeof(cfgfile));
		iohandler_t::parse_area_line0_t cb(ioh);
		if (choose_ioport_device2(&ioh.device, cfgfile, &cb))
			ioh.set_device_name(ioh.device.c_str(), IORESP_ALL);
		break;
	}
	case processor_t::ev_ending_undo:
	case processor_t::ev_oldfile:
	{
		load_from_idb();
		break;
	}
	case processor_t::ev_init:
	{
		hook_event_listener(HT_IDB, &idb_listener, &LPH);
		helper.create(PROCMOD_NODE_NAME);
		break;
	}
	case processor_t::ev_term:
	{
		unhook_event_listener(HT_IDB, &idb_listener);
		ioh.ports.clear();
		clr_module_data(data_id);
		break;
	}
	case processor_t::ev_creating_segm:
	{
		segment_t* s = va_arg(va, segment_t*);
		set_default_dataseg(s->sel);
		break;
	}
	case processor_t::ev_create_merge_handlers:
	{
		merge_data_t *md = va_arg(va, merge_data_t *);
		create_std_procmod_handlers(*md);
		break;
	}
	case processor_t::ev_privrange_changed:
		helper.create(PROCMOD_NODE_NAME);
		break;
	case processor_t::ev_ana_insn:
		return rl78_ana(va_arg(va, insn_t *));
	case processor_t::ev_emu_insn:
		return rl78_emu(*va_arg(va, insn_t *));
	case processor_t::ev_out_mnem:
		break;
	case processor_t::ev_out_insn: {
		auto ctx = va_arg(va, outctx_t *);
		out_insn(*ctx);
	  } break;
	case processor_t::ev_out_operand: {
		auto ctx = va_arg(va, outctx_t *);
		auto op = va_arg(va, const op_t *);
		return out_opnd(*ctx, *op) ? 1 : -1;
	  }
	case processor_t::ev_is_align_insn:
		return is_align_insn(va_arg(va, ea_t));
	case processor_t::ev_get_reg_info: {
		auto main_regname = va_arg(va, const char **);
		auto bitrange = va_arg(va, bitrange_t *);
		auto regname = va_arg(va, const char *);
		return get_reg_info(main_regname, bitrange, regname);
	  }
	case processor_t::ev_create_function_frame: {
		ea_t func_ea = va_arg(va, ea_t);
		func_t *pfn = get_func(func_ea);
		if (pfn != nullptr) {
			create_func_frame(pfn);
			return 1;
		}
		return 0;
	  }
	case processor_t::ev_create_func_frame:
		create_func_frame(va_arg(va, func_t *));
		return 1;
	case processor_t::ev_get_function_retsize: {
		int *frsize = va_arg(va, int *);
		ea_t func_ea = va_arg(va, ea_t);
		qnotused(func_ea);
		if (frsize != nullptr)
			*frsize = 4;
		return 1;
	  }
	case processor_t::ev_is_sp_based: {
		auto mode = va_arg(va, int *);
		auto insn = va_arg(va, insn_t *);
		auto op = va_arg(va, op_t *);
		is_sp_based(mode, *insn, *op);
		return 1;
	  }
	case processor_t::ev_may_be_func: {
		auto insn = va_arg(va, const insn_t *);
		auto state = va_arg(va, int);
		return may_be_func(*insn, state);
	  }
	case processor_t::ev_is_switch: {
		auto si = va_arg(va, switch_info_t *);
		auto insn = va_arg(va, insn_t *);
		return is_switch(si, *insn);
	  }
	case processor_t::ev_calc_switch_cases: {
		auto casevec = va_arg(va, casevec_t *);
		auto targets = va_arg(va, eavec_t *);
		auto insn_ea = va_arg(va, ea_t);
		auto si = va_arg(va, switch_info_t *);
		return rl78_calc_switch_cases(casevec, targets, insn_ea, *si);
	  }
	case processor_t::ev_create_switch_xrefs: {
		auto insn_ea = va_arg(va, ea_t);
		auto si = va_arg(va, switch_info_t *);
		return rl78_create_switch_xrefs(insn_ea, *si);
	  }
	}
	return 0;
}


static const char *const short_names[] = {
	"rl78prox",
	"rl78",
	nullptr
};

static const char *const long_names[] = {
	"Renesas RL78prox",
	"Renesas RL78",
	nullptr
};

static const asm_t *const assemblers[] = {
	&assembler,
	nullptr
};

idaman processor_t ida_module_data LPH = {
	IDP_INTERFACE_VERSION,
	0x8000 + 0x78,
	PR_SEGS | PRN_HEX | PR_ALIGN_INSN |
	PR_USE32 | PR_DEFSEG32 | PR_TYPEINFO,
	PR2_FORCE_16BIT,
	8,
	8,
	short_names,
	long_names,
	assemblers,
	notify,
	reg_names,
	qnumber(reg_names),
	rVcs,
	rES,
	1,
	rVcs,
	rVds,
	nullptr,
	nullptr,
	0,
	RL78_itype_count,
	instructions,
	0,
	{},
	RL78_ret,
	nullptr
};
