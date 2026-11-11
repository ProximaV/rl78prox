
#ifndef __RL78_HPP
#define __RL78_HPP
#pragma warning (disable : 4146)
#include <ida.hpp>
#include <idp.hpp>
#include <ua.hpp>
#include <name.hpp>
#include <auto.hpp>
#include <bytes.hpp>
#include <diskio.hpp>
#include <problems.hpp>
#include <frame.hpp>
#include <lines.hpp>
#include <loader.hpp>
#include <offset.hpp>
#include <segment.hpp>
#include <segregs.hpp>
#include <kernwin.hpp>
#include <typeinf.hpp>
#include <nalt.hpp>
#include "ins.hpp"
#include "../idaidp.hpp"
#include "../iohandler.hpp"

#define PROCMOD_NODE_NAME "$ RL78"
#define PROCMOD_NAME rl78

struct merge_data_t;
void create_std_procmod_handlers(merge_data_t &md);

DECLARE_PROC_LISTENER(idb_listener_t, struct rl78_t);

struct rl78_t : public procmod_t
{
    netnode helper;
    iohandler_t ioh = iohandler_t(helper);
    idb_listener_t idb_listener = idb_listener_t(*this);

    virtual ssize_t idaapi on_event(ssize_t msgid, va_list va) override;

    int rl78_ana(insn_t* _insn);
    int rl78_emu(const insn_t& insn);
    void load_from_idb();
    bool rl78_find_ioport_bit(outctx_t& ctx, int port, int bit);
	void create_func_frame(func_t* pfn);
	void is_sp_based(int* mode, const insn_t& insn, const op_t& op);
};

// In reality all registers are just references to memory locations.
// Pick the ones which are architecturally defined to be commonly used in
// instructions to list here, as well as those which IDA needs to track.
// The rest can be named via io naming.
enum RL78Register : decltype(op_t::reg) {
	rX, rA, rC, rB, rE, rD, rL, rH, rAX, rBC, rDE, rHL,
		rRB0, rRB1, rRB2, rRB3,
		rPSW, rSP,
		rCY,
		// Fake segreg to make IDA happy
		rVcs, rVds,
		// RL78 segregs we'll use IDA to track
		rCS, rES,
		r_count
};

#define RL78_MAX_OPERANDS 2

enum : decltype(insn_t::auxpref) {
	kHasPrefix = 1,
};

enum : optype_t {
	o_bit = o_idpspec0,
};

enum : decltype(op_t::specflag2) {
	kDirect,
		kIndirect,
};

enum RL78Phrase : decltype(op_t::phrase) {
	kReg,
		kHlReg,
		kReg8,
		kReg16,
};

// for o_bit, actual type of base operand
#define bit_base_type specflag1
// for o_bit, indicate if operand is indirect
#define addr_mode specflag2
// for o_phrase and o_displ, RL78Phrase value
#define ind_reg specflag2
extern int data_id;



#endif
