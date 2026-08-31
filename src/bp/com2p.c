/* Copyright 2020 HPS/SAFARI Research Groups
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

/***************************************************************************************
 * File         : bp/com2p.c
 * Description  : COM2P metadata table.  Allocation happens at retire when a CBR
 *                with a targetable condition class crosses the H2P threshold.
 *                Structure learning is retire-time ARF-ext forward propagation
 *                (3D-Branch Overrider, PACT'20 Fig. 6): every retired op copies
 *                its source register's {load PC, immediate-only op chain} record
 *                to its destination registers, appending itself; the last flag
 *                writer additionally snapshots its register-source records (two
 *                slots -- the LVL extension over the paper).  A retiring branch
 *                classifies from that snapshot: the whole chain arrives within
 *                one dynamic pass, WAR/WAW register reuse cannot corrupt it
 *                (retire order == program order, records travel by value), and
 *                there are no producer pointers left to go stale.
 ***************************************************************************************/

#include "bp/com2p.h"

#include <stdio.h>
#include <string.h>

#include "globals/assert.h"
#include "globals/global_defs.h"
#include "globals/global_types.h"
#include "globals/global_vars.h"

#include "bp/bp.h"
#include "bp/bp.param.h"
#include "isa/isa.h"
#include "libs/hash_lib.h"
#include "lsq.h"
#include "op.h"
#include "statistics.h"

#include "xed-interface.h"

/* Hard bound for chain records everywhere; COM2P_CHAIN_MAX_OPS must stay within. */
#define COM2P_CHAIN_MAX_HARD 8

/**************************************************************************************/
/* Table */

static Hash_Table com2p_table;
static Flag com2p_table_inited = FALSE;

static void com2p_table_init(void) {
  if (com2p_table_inited)
    return;
  /* Modes that are not implemented yet must fail loudly, not be silently ignored. */
  ASSERTM(0, !COM2P_REALISTIC_SUPPLY, "com2p_realistic_supply is not implemented yet\n");
  ASSERTM(0, !COM2P_REALISTIC_COMPUTE, "com2p_realistic_compute is not implemented yet\n");
  ASSERTM(0, COM2P_CHAIN_MAX_OPS <= COM2P_CHAIN_MAX_HARD, "com2p_chain_max_ops > %u\n", COM2P_CHAIN_MAX_HARD);
  init_hash_table(&com2p_table, "com2p", COM2P_TABLE_BUCKETS, sizeof(Com2p_Entry));
  com2p_table_inited = TRUE;
}

/* ---- immediate re-decode cache -------------------------------------------------
 * scarab drops immediate VALUES at decode (only a has_immediate bit survives),
 * but Static_Inst_Info keeps the raw instruction bytes, and XED is linked in.
 * Re-decode once per distinct static instruction and cache the immediate. */
typedef struct Com2p_Imm_struct {
  int64 imm;
  uns8 width;  // bytes; 0 = no immediate
} Com2p_Imm;

static Hash_Table com2p_imm_cache;
static Flag com2p_imm_cache_inited = FALSE;
static Flag com2p_xed_inited = FALSE;

static const Com2p_Imm* com2p_get_imm(const Static_Inst_Info* si) {
  if (!com2p_imm_cache_inited) {
    init_hash_table(&com2p_imm_cache, "com2p_imm", 16384, sizeof(Com2p_Imm));
    com2p_imm_cache_inited = TRUE;
  }
  Flag new_entry = FALSE;
  Com2p_Imm* e = (Com2p_Imm*)hash_table_access_create(&com2p_imm_cache, (int64)(size_t)si, &new_entry);
  if (!new_entry)
    return e;
  e->imm = 0;
  e->width = 0;
  if (si->fake_inst || si->inst_size == 0 || si->inst_size > 16)
    return e;
  if (!com2p_xed_inited) {
    xed_tables_init();  // memtrace reader also inits; xed guards against double init
    com2p_xed_inited = TRUE;
  }
  /* Reconstruct the encoding: first min(8,size) bytes from opcode_lsb (packed
   * big-endian-first), bytes 8..size from the low bits of opcode_msb -- this
   * inverts both producers' packing (pintool and DR reader). */
  uns8 bytes[16];
  uns size = si->inst_size;
  uns head = size < 8 ? size : 8;
  for (uns i = 0; i < head; i++)
    bytes[i] = (uns8)(si->opcode_lsb >> (8 * (head - 1 - i)));
  if (size > 8) {
    uns tail = size - 8;
    for (uns i = 0; i < tail; i++)
      bytes[8 + i] = (uns8)(si->opcode_msb >> (8 * (tail - 1 - i)));
  }
  xed_decoded_inst_t xd;
  xed_state_t st;
  xed_state_init2(&st, XED_MACHINE_MODE_LONG_64, XED_ADDRESS_WIDTH_64b);
  xed_decoded_inst_zero_set_mode(&xd, &st);
  if (xed_decode(&xd, bytes, size) != XED_ERROR_NONE)
    return e;
  uns w = xed_decoded_inst_get_immediate_width(&xd);
  if (w > 0 && w <= 8) {
    e->width = (uns8)w;
    e->imm = xed_decoded_inst_get_immediate_is_signed(&xd)
                 ? (int64)xed_decoded_inst_get_signed_immediate(&xd)
                 : (int64)xed_decoded_inst_get_unsigned_immediate(&xd);
  }
  return e;
}

/* ---- chain table ---------------------------------------------------------------
 * Immediate-only op chains, one entry per (branch pc, load pc, operand slot):
 * a 1-load branch owns one entry, a 2-load branch owns two (a raw side keeps
 * len 0 so both feeder loads stay addressable -- the shape the LT pairing of
 * the realistic-supply phase will want). */
typedef struct Com2p_Chain_Step_struct {
  uns16 iclass;  // XED iclass (true_op_type) -- Op_Type is too coarse (SUB==IADD)
  int64 imm;
  uns8 has_imm;
} Com2p_Chain_Step;

typedef struct Com2p_Chain_struct {
  Addr branch_pc;  // stored for fold-collision verification
  Addr load_pc;
  uns8 slot;
  uns8 len;
  Com2p_Chain_Step step[COM2P_CHAIN_MAX_HARD];  // load-side first
  Flag valid;
} Com2p_Chain;

static Hash_Table com2p_chain_table;
static Flag com2p_chain_table_inited = FALSE;

static int64 com2p_chain_key(Addr branch_pc, Addr load_pc, uns8 slot) {
  return (int64)((branch_pc << 21) ^ (load_pc << 1) ^ slot);
}

static Com2p_Chain* com2p_chain_access(Addr branch_pc, Addr load_pc, uns8 slot, Flag create) {
  if (!com2p_chain_table_inited) {
    if (!create)
      return NULL;
    init_hash_table(&com2p_chain_table, "com2p_chain", COM2P_TABLE_BUCKETS, sizeof(Com2p_Chain));
    com2p_chain_table_inited = TRUE;
  }
  int64 key = com2p_chain_key(branch_pc, load_pc, slot);
  Com2p_Chain* c;
  if (create) {
    Flag new_entry = FALSE;
    c = (Com2p_Chain*)hash_table_access_create(&com2p_chain_table, key, &new_entry);
    if (new_entry) {
      memset(c, 0, sizeof(*c));
      c->branch_pc = branch_pc;
      c->load_pc = load_pc;
      c->slot = slot;
    }
  } else {
    c = (Com2p_Chain*)hash_table_access(&com2p_chain_table, key);
  }
  if (c && (c->branch_pc != branch_pc || c->load_pc != load_pc || c->slot != slot))
    return NULL;  // fold collision: treated as absent (counted by caller if it cares)
  return c;
}

static void com2p_chain_delete(Addr branch_pc, Addr load_pc, uns8 slot) {
  if (!com2p_chain_table_inited)
    return;
  Com2p_Chain* c = com2p_chain_access(branch_pc, load_pc, slot, FALSE);
  if (c)
    hash_table_access_delete(&com2p_chain_table, com2p_chain_key(branch_pc, load_pc, slot));
}

static Com2p_Entry* com2p_lookup(Addr pc) {
  if (!com2p_table_inited)
    return NULL;
  return (Com2p_Entry*)hash_table_access(&com2p_table, pc);
}

/* ---- feeder instance tracking ---------------------------------------------------
 * The ideal-supply analogue of the paper's FLT/LT: for every load PC named by a
 * CONFIRMED entry, remember the youngest on-path instance seen in fetch order.
 * A branch pairs with that instance at predict time (program-order-previous
 * instance; loop-carried mismatches are absorbed by the structure gate). */
typedef struct Com2p_Feeder_struct {
  Counter op_num;
  Addr va;
  Flag valid;
} Com2p_Feeder;

static Hash_Table com2p_feeder_table;
static Flag com2p_feeder_table_inited = FALSE;

static void com2p_feeder_register(Addr load_pc) {
  if (!com2p_feeder_table_inited) {
    init_hash_table(&com2p_feeder_table, "com2p_feeder", COM2P_TABLE_BUCKETS, sizeof(Com2p_Feeder));
    com2p_feeder_table_inited = TRUE;
  }
  Flag new_entry = FALSE;
  Com2p_Feeder* f = (Com2p_Feeder*)hash_table_access_create(&com2p_feeder_table, load_pc, &new_entry);
  if (new_entry)
    memset(f, 0, sizeof(*f));
}

static Com2p_Feeder* com2p_feeder_lookup(Addr load_pc) {
  if (!com2p_feeder_table_inited)
    return NULL;
  return (Com2p_Feeder*)hash_table_access(&com2p_feeder_table, load_pc);
}

void com2p_note_fetch(Op* op) {
  if (!COM2P_ENABLE || !COM2P_OVERRIDE || !com2p_feeder_table_inited)
    return;
  if (op->uop->mem_type != MEM_LD || op->off_path || op->inst->fake_inst)
    return;
  Com2p_Feeder* f = com2p_feeder_lookup(op->inst->addr);
  if (!f)
    return;  // not a feeder of any CONFIRMED entry
  f->op_num = op->op_num;
  f->va = op->oracle_info.va;
  f->valid = TRUE;
}

/**************************************************************************************/
/* ARF-ext learning */

typedef struct Com2p_Obs_struct {
  uns8 cls;
  uns8 cmp_folded;
  uns8 num_loads;
  Addr load_pc[2];
  uns8 chain_len[2];
  Com2p_Chain_Step chain[2][COM2P_CHAIN_MAX_HARD];
} Com2p_Obs;

typedef enum Com2p_Arf_Kind_enum {
  COM2P_ARF_UNKNOWN,  // register not written since reset: never an observation
  COM2P_ARF_CONST,    // rooted in immediate materialization, no load involved
  COM2P_ARF_LOAD,     // a load value behind >= 0 immediate-only ops (compliant)
  COM2P_ARF_TAINT,    // disqualified; taint carries the Com2p_Cls reason
} Com2p_Arf_Kind;

typedef struct Com2p_Arf_Rec_struct {
  uns8 kind;   // Com2p_Arf_Kind
  uns8 taint;  // COM2P_CLS_COMP_* when kind == COM2P_ARF_TAINT
  uns8 len;    // ops applied since the load (0 = raw) when kind == COM2P_ARF_LOAD
  Addr load_pc;
  Com2p_Chain_Step step[COM2P_CHAIN_MAX_HARD];  // load-side first
} Com2p_Arf_Rec;

/* Snapshot of the last flag-writer's register-source records, taken as it
 * retires.  This is what a flags-consuming branch classifies from; two slots
 * because LVL compares two register values. */
typedef struct Com2p_Flags_Rec_struct {
  Flag valid;
  uns8 num_slots;    // distinct register sources captured (<= 2)
  uns8 overflow;     // more than two distinct register sources (COMPLEX)
  uns8 self_pair;    // some register consumed twice (test r,r)
  uns8 flag_src;     // the writer consumed flags itself (adc/sbb chains)
  uns8 folded_load;  // the writer was itself a MEM_LD uop (cmp [mem],imm)
  Addr writer_pc;
  Com2p_Arf_Rec slot[2];
} Com2p_Flags_Rec;

static Com2p_Arf_Rec com2p_arf[NUM_REGS];
static Com2p_Flags_Rec com2p_flags;

static inline Flag com2p_op_class_compliant(Op_Type ot) {
  return ot == OP_MOV || ot == OP_IADD || ot == OP_LOGIC || ot == OP_SHIFT || ot == OP_LDA;
}

void com2p_note_retire(Op* op) {
  if (!COM2P_ENABLE)
    return;
  const Static_Op_Info* uop = op->uop;
  uns num_dsts = uop->num_dest_regs;
  Flag writes_flags = FALSE;
  Flag writes_reg = FALSE;
  for (uns i = 0; i < num_dsts; i++) {
    if (uop->dests[i].id == REG_ZPS)
      writes_flags = TRUE;
    else if (uop->dests[i].id < NUM_REGS)
      writes_reg = TRUE;
  }
  if (!writes_flags && !writes_reg)
    return;

  /* Read phase: snapshot the distinct register sources before any dst update
   * (a dst may alias a src; in-place chains rely on read-then-write order). */
  uns16 src_id[8];
  Com2p_Arf_Rec src_rec[8];
  uns num_src = 0;
  Flag self_pair = FALSE;
  Flag reads_flags = FALSE;
  for (uns j = 0; j < uop->num_src_regs; j++) {
    uns16 id = uop->srcs[j].id;
    if (id == REG_ZPS) {
      reads_flags = TRUE;
      continue;
    }
    if (id >= NUM_REGS)
      continue;
    Flag dup = FALSE;
    for (uns s = 0; s < num_src; s++) {
      if (src_id[s] == id) {
        dup = TRUE;
        break;
      }
    }
    if (dup) {
      self_pair = TRUE;  // same register twice is still one dynamic input
      continue;
    }
    if (num_src < 8) {
      src_id[num_src] = id;
      src_rec[num_src] = com2p_arf[id];
      num_src++;
    }
  }

  /* The record this op's register results carry forward. */
  Com2p_Arf_Rec nr;
  memset(&nr, 0, sizeof(nr));
  if (uop->mem_type == MEM_LD) {
    /* Chain root.  A load-op combo also roots here: the payload of interest is
     * the uop's own register result (COM2P's value definition). */
    nr.kind = COM2P_ARF_LOAD;
    nr.load_pc = op->inst->addr;
  } else if (uop->op_type == OP_IMUL || uop->op_type == OP_IDIV) {
    nr.kind = COM2P_ARF_TAINT;
    nr.taint = COM2P_CLS_COMP_COMPLEX_OP;
  } else if (!com2p_op_class_compliant(uop->op_type) || reads_flags) {
    /* Unsupported op class, or an extra dynamic input via flags (adc-style):
     * non-compliant input, same bucket the walk era used. */
    nr.kind = COM2P_ARF_TAINT;
    nr.taint = COM2P_CLS_COMP_MULTIREG;
  } else {
    const Com2p_Arf_Rec* dyn = NULL;
    uns num_dyn = 0;
    for (uns s = 0; s < num_src; s++) {
      if (src_rec[s].kind == COM2P_ARF_UNKNOWN)
        continue;  // untracked register: treated as a constant-ish side
      dyn = &src_rec[s];
      num_dyn++;
    }
    if (num_dyn == 0) {
      /* Pure immediate materialization roots a const; inputs that are all
       * untracked stay unknown so cold state cannot masquerade as learnt. */
      nr.kind = num_src ? COM2P_ARF_UNKNOWN : COM2P_ARF_CONST;
    } else if (num_dyn >= 2) {
      nr.kind = COM2P_ARF_TAINT;
      nr.taint = COM2P_CLS_COMP_MULTIREG;
    } else if (dyn->kind == COM2P_ARF_CONST) {
      nr.kind = COM2P_ARF_CONST;
    } else if (dyn->kind == COM2P_ARF_TAINT) {
      nr = *dyn;  // a disqualification propagates with its original reason
    } else if (dyn->len >= COM2P_CHAIN_MAX_OPS) {
      nr.kind = COM2P_ARF_TAINT;
      nr.taint = COM2P_CLS_COMP_TOO_DEEP;
    } else {
      nr = *dyn;
      const Com2p_Imm* im = com2p_get_imm(op->inst);
      nr.step[nr.len].iclass = op->inst->true_op_type;
      nr.step[nr.len].imm = im->width ? im->imm : 0;
      nr.step[nr.len].has_imm = im->width > 0;
      nr.len++;
    }
  }

  for (uns i = 0; i < num_dsts; i++) {
    uns16 id = uop->dests[i].id;
    if (id != REG_ZPS && id < NUM_REGS)
      com2p_arf[id] = nr;
  }
  if (writes_flags) {
    com2p_flags.valid = TRUE;
    com2p_flags.num_slots = (uns8)MIN2(num_src, 2);
    com2p_flags.overflow = num_src > 2;
    com2p_flags.self_pair = self_pair;
    com2p_flags.flag_src = reads_flags;
    com2p_flags.folded_load = uop->mem_type == MEM_LD;
    com2p_flags.writer_pc = op->inst->addr;
    for (uns s = 0; s < com2p_flags.num_slots; s++)
      com2p_flags.slot[s] = src_rec[s];
  }
}

/* Classification of a retiring flags-consuming CBR from the flags snapshot.
 * Fills *obs and returns its classification. */
static uns8 com2p_classify_arf(Op* op, Com2p_Obs* obs) {
  memset(obs, 0, sizeof(*obs));
  obs->cls = COM2P_CLS_UNRESOLVED;

  /* JCXZ-family branches consume a register, not flags; the per-register
   * records collapse their writer's operand split, so classifying them would
   * need a per-register slots view.  Measure the miss instead of paying it. */
  for (uns k = 0; k < op->uop->num_src_regs; k++) {
    if (op->uop->srcs[k].id != REG_ZPS) {
      STAT_EVENT(op->proc_id, COM2P_ARF_NONFLAG_BR);
      return COM2P_CLS_UNRESOLVED;
    }
  }
  const Com2p_Flags_Rec* fr = &com2p_flags;
  if (!fr->valid)
    return COM2P_CLS_UNRESOLVED;  // cold state right after reset

  /* A compare folded into a load-op is a flag-writing MEM_LD uop: the memory
   * value reaches the comparison unmodified. */
  if (fr->folded_load) {
    obs->cls = COM2P_CLS_CONST_DIR;
    obs->cmp_folded = 1;
    obs->num_loads = 1;
    obs->load_pc[0] = fr->writer_pc;
    return obs->cls;
  }
  if (fr->flag_src) {
    obs->cls = COM2P_CLS_FLAG_CHAIN;
    return obs->cls;
  }
  if (fr->overflow) {
    obs->cls = COM2P_CLS_COMPLEX;
    return obs->cls;
  }
  if (fr->self_pair && fr->num_slots == 1) {
    obs->cls = COM2P_CLS_SELF;
    return obs->cls;
  }
  uns num_slots = fr->num_slots;
  if (num_slots == 0) {
    obs->cls = COM2P_CLS_NO_COND;
    return obs->cls;
  }

  /* Per-slot outcome: a raw load, a load behind an immediate-only chain, or a
   * disqualifier -- all read directly off the propagated records. */
  uns num_load_slots = 0;
  uns num_chain_slots = 0;
  uns8 fail_cls = 0;
  for (uns s = 0; s < num_slots; s++) {
    const Com2p_Arf_Rec* r = &fr->slot[s];
    if (r->kind == COM2P_ARF_UNKNOWN) {
      /* Cold source: not an observation (a first-obs freeze off cold state
       * would poison the entry into an inconsistency reject). */
      STAT_EVENT(op->proc_id, COM2P_ARF_UNKNOWN_SRC);
      return COM2P_CLS_UNRESOLVED;
    }
    if (r->kind == COM2P_ARF_CONST) {
      /* Constant-materialized side: same label the walk era gave it. */
      if (!fail_cls)
        fail_cls = COM2P_CLS_NO_LOAD;
      continue;
    }
    if (r->kind == COM2P_ARF_TAINT) {
      if (!fail_cls)
        fail_cls = r->taint;
      continue;
    }
    if (num_load_slots < 2) {
      obs->load_pc[num_load_slots] = r->load_pc;
      obs->chain_len[num_load_slots] = r->len;
      memcpy(obs->chain[num_load_slots], r->step, sizeof(obs->chain[0]));
    }
    num_load_slots++;
    if (r->len > 0)
      num_chain_slots++;
  }

  if (num_slots == 1) {
    if (num_load_slots == 1)
      obs->cls = num_chain_slots ? COM2P_CLS_CONST_CHAIN : COM2P_CLS_CONST_DIR;
    else
      obs->cls = fail_cls ? fail_cls : COM2P_CLS_NO_LOAD;
  } else {
    if (num_load_slots == 2)
      obs->cls = num_chain_slots ? COM2P_CLS_LVL_CHAIN : COM2P_CLS_LVL_DIR;
    else if (fail_cls)
      obs->cls = fail_cls;
    else
      obs->cls = num_load_slots == 1 ? COM2P_CLS_REG_MIX : COM2P_CLS_NO_LOAD;
  }
  if (obs->cls == COM2P_CLS_CONST_DIR || obs->cls == COM2P_CLS_CONST_CHAIN) {
    obs->num_loads = 1;
  } else if (obs->cls == COM2P_CLS_LVL_DIR || obs->cls == COM2P_CLS_LVL_CHAIN) {
    obs->num_loads = 2;
    if (obs->load_pc[0] > obs->load_pc[1]) {  // operand order is encoding noise; canonicalize
      Addr t = obs->load_pc[0];
      obs->load_pc[0] = obs->load_pc[1];
      obs->load_pc[1] = t;
      uns8 tl = obs->chain_len[0];
      obs->chain_len[0] = obs->chain_len[1];
      obs->chain_len[1] = tl;
      Com2p_Chain_Step ts[COM2P_CHAIN_MAX_HARD];
      memcpy(ts, obs->chain[0], sizeof(ts));
      memcpy(obs->chain[0], obs->chain[1], sizeof(ts));
      memcpy(obs->chain[1], ts, sizeof(ts));
    }
  } else {
    obs->load_pc[0] = 0;
    obs->load_pc[1] = 0;
    obs->chain_len[0] = 0;
    obs->chain_len[1] = 0;
  }
  return obs->cls;
}

static Flag com2p_cls_is_target_chain(uns8 cls) {
  return cls == COM2P_CLS_CONST_CHAIN || cls == COM2P_CLS_LVL_CHAIN;
}
/* Coverage is a 2x2 grid of independent toggles: dir/comp x 1-load/2-load. */
static Flag com2p_cls_is_covered(uns8 cls) {
  switch (cls) {
    case COM2P_CLS_CONST_DIR:
      return COM2P_COVER_DIR && COM2P_COVER_1LOAD;
    case COM2P_CLS_LVL_DIR:
      return COM2P_COVER_DIR && COM2P_COVER_2LOAD;
    case COM2P_CLS_CONST_CHAIN:
      return COM2P_COVER_COMP && COM2P_COVER_1LOAD;
    case COM2P_CLS_LVL_CHAIN:
      return COM2P_COVER_COMP && COM2P_COVER_2LOAD;
    default:
      return FALSE;
  }
}

static Flag com2p_obs_matches_entry(const Com2p_Entry* e, const Com2p_Obs* obs) {
  if (e->cls != obs->cls || e->cmp_folded != obs->cmp_folded || e->num_loads != obs->num_loads ||
      e->load_pc[0] != obs->load_pc[0] || e->load_pc[1] != obs->load_pc[1] || e->chain_len[0] != obs->chain_len[0] ||
      e->chain_len[1] != obs->chain_len[1])
    return FALSE;
  for (uns i = 0; i < e->num_loads; i++) {
    if (e->chain_len[i] == 0)
      continue;
    Com2p_Chain* c = com2p_chain_access(e->branch_pc, e->load_pc[i], (uns8)i, FALSE);
    if (!c || c->len != obs->chain_len[i])
      return FALSE;
    for (uns k = 0; k < c->len; k++) {
      if (c->step[k].iclass != obs->chain[i][k].iclass || c->step[k].imm != obs->chain[i][k].imm ||
          c->step[k].has_imm != obs->chain[i][k].has_imm)
        return FALSE;
    }
  }
  return TRUE;
}

/* First observation of a chain-class branch: persist its chains. */
static void com2p_record_chains(Com2p_Entry* e, const Com2p_Obs* obs, uns8 proc_id) {
  for (uns i = 0; i < obs->num_loads; i++) {
    Com2p_Chain* c = com2p_chain_access(e->branch_pc, obs->load_pc[i], (uns8)i, TRUE);
    if (!c)
      continue;  // fold collision: extremely unlikely; entry will reject on mismatch
    c->len = obs->chain_len[i];
    memcpy(c->step, obs->chain[i], sizeof(c->step));
    c->valid = TRUE;
    if (c->len > 0) {
      STAT_EVENT(proc_id, COM2P_CHAIN_LEN_1 + MIN2(c->len, 4) - 1);
      for (uns k = 0; k < c->len; k++) {
        if (c->step[k].has_imm && (c->step[k].imm > 32767 || c->step[k].imm < -32768))
          STAT_EVENT(proc_id, COM2P_CHAIN_IMM_GT2B);
      }
    }
  }
}

static void com2p_delete_chains(Com2p_Entry* e) {
  for (uns i = 0; i < 2; i++) {
    if (e->load_pc[i])
      com2p_chain_delete(e->branch_pc, e->load_pc[i], (uns8)i);
  }
}

/**************************************************************************************/
/* Hooks */

static inline Flag com2p_cond_class_targetable(uns8 cc) {
  return cc == CBR_COND_FIXED || cc == CBR_COND_BOUND_UNSIGNED || cc == CBR_COND_BOUND_SIGNED || cc == CBR_COND_SIGN;
}

/* Ideal-mode override at predict time: substitute the branch direction when the
 * branch is a CONFIRMED covered target and every feeder value is ready.  The
 * decision is evaluated once per dynamic instance and cached on the op so both
 * prediction levels (L0/MAIN) act coherently; ideal compute supplies the oracle
 * direction (COM2P_PROVIDED_RISK bounds what a real computation would miss). */
void com2p_override_predict(Op* op, uns8* pred) {
  if (!COM2P_OVERRIDE || !com2p_table_inited)
    return;
  if (op->off_path || op->inst->fake_inst)
    return;
  if (op->com2p_prov == 0) {
    op->com2p_prov = 2;
    Com2p_Entry* e = com2p_lookup(op->inst->addr);
    if (!e || e->state != COM2P_ST_CONFIRMED)
      return;
    if (!com2p_cls_is_covered(e->cls))
      return;
    for (uns i = 0; i < e->num_loads; i++) {
      Com2p_Feeder* f = com2p_feeder_lookup(e->load_pc[i]);
      if (!f || !f->valid) {
        STAT_EVENT(op->proc_id, COM2P_NO_INSTANCE);
        return;
      }
      if (lsq_com2p_store_pending(f->va, f->op_num)) {
        STAT_EVENT(op->proc_id, COM2P_NOT_READY);
        return;
      }
    }
    op->com2p_prov = 1;
    STAT_EVENT(op->proc_id, COM2P_PROVIDED);
  }
  if (op->com2p_prov == 1)
    *pred = op->oracle_info.dir;
}

void com2p_on_retire(Op* op) {
  if (!COM2P_ENABLE)
    return;
  if (op->uop->cf_type != CF_CBR)
    return;
  if (!com2p_cond_class_targetable(op->uop->cbr_cond_class))
    return;

  com2p_table_init();
  Com2p_Entry* e = com2p_lookup(op->inst->addr);
  if (!e) {
    /* profile_all: cross-validation mode -- classify every targetable CBR so
     * the distribution is comparable to mispredict-weighted offline
     * taxonomies. */
    if (!COM2P_PROFILE_ALL && !is_h2p_at_exec(op->inst->addr))
      return;
    Flag new_entry = FALSE;
    e = (Com2p_Entry*)hash_table_access_create(&com2p_table, op->inst->addr, &new_entry);
    ASSERT(op->proc_id, new_entry);
    memset(e, 0, sizeof(*e));
    e->branch_pc = op->inst->addr;
    e->state = COM2P_ST_PROFILING;
    e->cond_class = op->uop->cbr_cond_class;
    STAT_EVENT(op->proc_id, COM2P_ENTRY_ALLOC);
  }
  /* Normally a REJECTED tombstone ends observation.  In profile_all mode we
   * keep classifying every instance -- otherwise CONFIRMED (dir) entries
   * accumulate stats forever while rejected classes freeze at OBS_N per PC,
   * skewing the instance-weighted distribution to ~100% dir. */
  if (e->state == COM2P_ST_REJECTED && !COM2P_PROFILE_ALL)
    return;

  Com2p_Obs obs;
  uns8 cls = com2p_classify_arf(op, &obs);

  /* Instance-level distribution, for cross-validation against the offline
   * exp29 taxonomy.  The stat blocks mirror Com2p_Cls order. */
  STAT_EVENT(op->proc_id, COM2P_OBS_UNRESOLVED + cls);
  if (op->bp_pred_main.recovery_point == RECOVER_AT_EXEC)
    STAT_EVENT(op->proc_id, COM2P_OBSMIS_UNRESOLVED + cls);

  /* Override accounting: engaged instances are judged here, where both the
   * baseline direction (pred_orig) and the realized structure are known. */
  if (op->com2p_prov == 1) {
    e->provided++;
    if (op->bp_pred_main.pred_orig != op->oracle_info.dir) {
      if (op->bp_pred_main.recovery_point == RECOVER_AT_NONE) {
        e->success++;  // the baseline would have mispredicted; the flush vanished
        STAT_EVENT(op->proc_id, COM2P_PROVIDED_SAVE);
      } else {
        STAT_EVENT(op->proc_id, COM2P_PROVIDED_BLOCKED);  // BTB miss kept its flush
      }
    }
    if (cls != COM2P_CLS_UNRESOLVED && !com2p_obs_matches_entry(e, &obs))
      STAT_EVENT(op->proc_id, COM2P_PROVIDED_RISK);  // ideal compute idealized this one
  }

  if (e->state == COM2P_ST_REJECTED)
    return;  // profile_all: distribution only, the tombstone stays final

  if (e->state == COM2P_ST_PROFILING) {
    if (cls == COM2P_CLS_UNRESOLVED) {
      e->unresolved++;
      return;
    }
    if (e->obs_count == 0) {
      e->cls = obs.cls;
      e->cmp_folded = obs.cmp_folded;
      e->num_loads = obs.num_loads;
      e->load_pc[0] = obs.load_pc[0];
      e->load_pc[1] = obs.load_pc[1];
      e->chain_len[0] = obs.chain_len[0];
      e->chain_len[1] = obs.chain_len[1];
      if (com2p_cls_is_target_chain(obs.cls))
        com2p_record_chains(e, &obs, op->proc_id);
      e->obs_count = 1;
      e->obs_match = 1;
      return;
    }
    e->obs_count++;
    if (com2p_obs_matches_entry(e, &obs))
      e->obs_match++;
    if (e->obs_count >= COM2P_OBS_N) {
      Flag consistent = (uns)e->obs_match * 100 >= (uns)e->obs_count * COM2P_CONSIST_PCT;
      Flag target = com2p_cls_is_covered(e->cls);
      if (consistent && target) {
        e->state = COM2P_ST_CONFIRMED;
        STAT_EVENT(op->proc_id, COM2P_ENTRY_CONFIRMED);
        for (uns i = 0; i < e->num_loads; i++)
          com2p_feeder_register(e->load_pc[i]);
      } else {
        e->state = COM2P_ST_REJECTED;
        e->reject_reason = consistent ? e->cls : COM2P_REJ_INCONSISTENT;
        if (com2p_cls_is_target_chain(e->cls))
          com2p_delete_chains(e);  // keep the tombstone, drop the payload
        STAT_EVENT(op->proc_id, COM2P_ENTRY_REJECTED);
      }
    }
    return;
  }

  /* CONFIRMED: the same retire-time classification becomes the structure gate.
   * The override itself (value readiness + redirect) lives in the override
   * stage; here we account for how often the learnt structure holds. */
  if (cls == COM2P_CLS_UNRESOLVED) {
    e->unresolved++;
    return;
  }
  if (com2p_obs_matches_entry(e, &obs))
    e->gate_match++;
  else
    e->gate_mismatch++;

  /* Runtime continuation of the profiling consistency check: once enough gate
   * attempts accumulate, an entry whose structure stops holding is evicted
   * (tombstoned, so it cannot thrash back in).  The confirm bar (CONSIST_PCT)
   * sits above this eviction bar on purpose -- hysteresis. */
  Counter attempts = e->gate_match + e->gate_mismatch;
  if (attempts >= COM2P_GATE_N && e->gate_match * 100 < attempts * (Counter)COM2P_GATE_MIN_PCT) {
    e->state = COM2P_ST_REJECTED;
    e->reject_reason = COM2P_REJ_GATE_UNSTABLE;
    if (com2p_cls_is_target_chain(e->cls))
      com2p_delete_chains(e);
    STAT_EVENT(op->proc_id, COM2P_ENTRY_EVICTED);
  }
}

/**************************************************************************************/
/* Reset / dump */

void com2p_reset(void) {
  memset(com2p_arf, 0, sizeof(com2p_arf));  // COM2P_ARF_UNKNOWN == 0
  memset(&com2p_flags, 0, sizeof(com2p_flags));
  if (com2p_feeder_table_inited)
    hash_table_clear(&com2p_feeder_table);
  if (com2p_chain_table_inited)
    hash_table_clear(&com2p_chain_table);
  if (!com2p_table_inited)
    return;
  hash_table_clear(&com2p_table);
}

typedef struct Com2p_Dump_Agg_struct {
  Counter entries;
  Counter by_state[3];
  Counter rejected_by_reason[COM2P_NUM_CLS + 2];
  Counter confirmed_by_cls[COM2P_NUM_CLS];
  Counter gate_match, gate_mismatch, unresolved;
  Counter provided, success;
} Com2p_Dump_Agg;

static void com2p_dump_scan(void* data, void* arg) {
  Com2p_Entry* e = (Com2p_Entry*)data;
  Com2p_Dump_Agg* agg = (Com2p_Dump_Agg*)arg;
  agg->entries++;
  agg->by_state[e->state]++;
  agg->unresolved += e->unresolved;
  if (e->state == COM2P_ST_REJECTED) {
    agg->rejected_by_reason[e->reject_reason]++;
  } else if (e->state == COM2P_ST_CONFIRMED) {
    agg->confirmed_by_cls[e->cls]++;
    agg->gate_match += e->gate_match;
    agg->gate_mismatch += e->gate_mismatch;
    agg->provided += e->provided;
    agg->success += e->success;
    printf("COM2P CONFIRMED pc=0x%llx cls=%u folded=%u loads=%u load_pc=0x%llx/0x%llx gate=%llu/%llu prov=%llu save=%llu",
           (unsigned long long)e->branch_pc, e->cls, e->cmp_folded, e->num_loads, (unsigned long long)e->load_pc[0],
           (unsigned long long)e->load_pc[1], (unsigned long long)e->gate_match,
           (unsigned long long)(e->gate_match + e->gate_mismatch), (unsigned long long)e->provided,
           (unsigned long long)e->success);
    for (uns i = 0; i < e->num_loads; i++) {
      if (!e->chain_len[i])
        continue;
      Com2p_Chain* c = com2p_chain_access(e->branch_pc, e->load_pc[i], (uns8)i, FALSE);
      printf(" chain%u=[", i);
      for (uns k = 0; c && k < c->len; k++)
        printf("%s{ic=%u,imm=%lld}", k ? "," : "", c->step[k].iclass, c->step[k].has_imm ? (long long)c->step[k].imm : 0LL);
      printf("]");
    }
    printf("\n");
  }
}

void com2p_dump(void) {
  if (!com2p_table_inited)
    return;
  Com2p_Dump_Agg agg;
  memset(&agg, 0, sizeof(agg));
  hash_table_scan(&com2p_table, com2p_dump_scan, &agg);
  printf("COM2P SUMMARY entries=%llu profiling=%llu confirmed=%llu rejected=%llu unresolved_obs=%llu\n",
         (unsigned long long)agg.entries, (unsigned long long)agg.by_state[COM2P_ST_PROFILING],
         (unsigned long long)agg.by_state[COM2P_ST_CONFIRMED], (unsigned long long)agg.by_state[COM2P_ST_REJECTED],
         (unsigned long long)agg.unresolved);
  printf("COM2P CONFIRMED_BY_CLS const_dir=%llu lvl_dir=%llu const_chain=%llu lvl_chain=%llu\n",
         (unsigned long long)agg.confirmed_by_cls[COM2P_CLS_CONST_DIR],
         (unsigned long long)agg.confirmed_by_cls[COM2P_CLS_LVL_DIR],
         (unsigned long long)agg.confirmed_by_cls[COM2P_CLS_CONST_CHAIN],
         (unsigned long long)agg.confirmed_by_cls[COM2P_CLS_LVL_CHAIN]);
  printf("COM2P GATE match=%llu mismatch=%llu\n", (unsigned long long)agg.gate_match,
         (unsigned long long)agg.gate_mismatch);
  printf("COM2P OVERRIDE provided=%llu saved=%llu\n", (unsigned long long)agg.provided,
         (unsigned long long)agg.success);
  printf("COM2P REJECTED_BY_REASON");
  for (uns r = 0; r <= COM2P_NUM_CLS + 1; r++)
    printf(" %u:%llu", r, (unsigned long long)agg.rejected_by_reason[r]);
  printf("\n");
}
