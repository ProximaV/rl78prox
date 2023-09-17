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

struct RegMap {
	const char *regname;
	const char *main_regname;
	bitrange_t bitrange;
};

static const RegMap reg_map[] = {
	{ reg_names[rX], reg_names[rAX], bitrange_t{ 0, 8 } },
	{ reg_names[rA], reg_names[rAX], bitrange_t{ 8, 8 } },
	{ reg_names[rC], reg_names[rBC], bitrange_t{ 0, 8 } },
	{ reg_names[rB], reg_names[rBC], bitrange_t{ 8, 8 } },
	{ reg_names[rE], reg_names[rDE], bitrange_t{ 0, 8 } },
	{ reg_names[rD], reg_names[rDE], bitrange_t{ 8, 8 } },
	{ reg_names[rL], reg_names[rHL], bitrange_t{ 0, 8 } },
	{ reg_names[rH], reg_names[rHL], bitrange_t{ 8, 8 } },
	{ reg_names[rAX], reg_names[rAX], },
	{ reg_names[rBC], reg_names[rBC], },
	{ reg_names[rDE], reg_names[rDE], },
	{ reg_names[rHL], reg_names[rHL], },
};

static RegMap cur_query = {
	"invalid", "invalid"
};

static bool bitrange_overlap(const bitrange_t &a, const bitrange_t &b) {
	if (a.empty() || b.empty()) {
		return true;
	}
	if (a.bitoff() >= b.bitoff()) {
		return a.bitoff() < b.bitoff() + b.bitsize();
	}
	if (a.bitoff() + a.bitsize() > b.bitoff()) {
		return true;
	}
	return false;
}

// This is supposedly not required, but eh?
static int get_reg_info(const char **main_regname, bitrange_t *bitrange,
	const char *regname) {
	for (auto &mapping : reg_map) {
		if (!strcmp(mapping.regname, regname)) {
			if (bitrange) {
				// reg to test against
				*main_regname = mapping.main_regname;
				*bitrange = mapping.bitrange;
				cur_query = mapping;
				return 1;
			}
			else if (!strcmp(mapping.main_regname, cur_query.main_regname) &&
				bitrange_overlap(mapping.bitrange, cur_query.bitrange)) {
				// overlaps target reg
				*main_regname = mapping.main_regname;
				return 1;
			}
			// no overlap
			return -1;
		}
	}
	// not a reg
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
		insn.Op2.type == o_displ && insn.Op2.phrase == kReg16 && insn.Op2.ind_reg == table_reg) {
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
		insn.Op2.type == o_displ && insn.Op2.phrase == kReg16) {
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

static void create_table(switch_info_t *si, const insn_t &insn, jump_table_type_t jtt) {
	//msg("create table %d @ %x : %x %x %x %x\n", jtt, insn.ea, si->startea, si->defjump, si->elbase, si->expr_ea);
	//set_switch_info(insn.ea, *si);
}

static jump_table_type_t is_rl78_pattern(switch_info_t *si, const insn_t &insn) {
	rl78_jmp_pattern_t jp(si);
	return jp.match(insn) ? JT_FLAT32 : JT_NONE;
}

static int is_switch(switch_info_t *si, const insn_t &insn) {
	if (!is_br_ax(insn)) {
		return 0;
	}
	is_pattern_t *const patterns[] = {
		is_rl78_pattern,
	};
	return check_for_table_jump(si, insn, patterns, qnumber(patterns),
		create_table) ? 1 : 0;
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
}

//---------------------------------------------------------------------------------------------------------------------
bool rl78_t::rl78_find_ioport_bit(outctx_t& ctx, int port, int bit)
{
	const ioport_bit_t* b = find_ioport_bit(ioh.ports, port, bit);
	if (b != nullptr && !b->name.empty()) ctx.out_line(b->name.c_str(), COLOR_IMPNAME); return true;

	return false;
}

ssize_t idaapi rl78_t::on_event(ssize_t msgid, va_list va)
{
	switch (msgid) {
	case processor_t::ev_newfile:
	{
		char cfgfile[QMAXFILE];
		//warning("In newfile");
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
		// Set default value of DS register for all segments
		set_default_dataseg(s->sel);
		break;
	}
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
	case processor_t::ev_create_func_frame:
		create_func_frame(va_arg(va, func_t *));
		return 1;
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
	  } break;
	case processor_t::ev_create_switch_xrefs: {
		auto insn_ea = va_arg(va, ea_t);
		auto si = va_arg(va, switch_info_t *);
	  } break;
	}
	return 0;
}


static const char *const short_names[] = {
	"rl78prox",
	nullptr
};

static const char *const long_names[] = {
	"Renesas RL78prox",
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
	PR_USE32 | PR_DEFSEG32,
	0,
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
