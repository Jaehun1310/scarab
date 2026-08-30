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
 *                with a targetable condition class crosses the H2P threshold;
 *                profiling happens at map time with a deliberately shallow
 *                (two-hop) dependency walk:
 *
 *                  branch --(flags/reg src)--> cond uop --(reg srcs)--> producers
 *
 *                An instance is a dir target exactly when the cond's value
 *                operands are produced by loads themselves (or the cond IS the
 *                load, for a compare folded into a load-op).  comp chains are
 *                labelled with a reason and NOT traversed -- that is 3D-Overrider
 *                scope, gated behind COM2P_COVER_COMP later.
 *
 *                Producers are resolved from in-flight state only (validated
 *                src_info).  H2P branches have varying feeder values, so their
 *                producers are near the branch and practically always in flight;
 *                COM2P_OBS_UNRESOLVED measures the residue of that assumption.
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
#include "op.h"
#include "statistics.h"

#include "xed-interface.h"

/**************************************************************************************/
/* Table */

static Hash_Table com2p_table;
static Flag com2p_table_inited = FALSE;

static void com2p_table_init(void) {
  if (com2p_table_inited)
    return;
  /* Modes that are not implemented yet must fail loudly, not be silently ignored. */
  ASSERTM(0, !COM2P_OVERRIDE, "com2p_override is not implemented yet\n");
  ASSERTM(0, !COM2P_REALISTIC_SUPPLY, "com2p_realistic_supply is not implemented yet\n");
  ASSERTM(0, !COM2P_REALISTIC_COMPUTE, "com2p_realistic_compute is not implemented yet\n");
  init_hash_table(&com2p_table, "com2p", COM2P_TABLE_BUCKETS, sizeof(Com2p_Entry));
  com2p_table_inited = TRUE;
}

/* Last retired writer per architectural register.  Recoveries stall re-fetched
 * consumers long enough for their (older, flush-surviving) producers to retire;
 * this map keeps just enough of them to finish the walk, validated exactly via
 * the (op_num, unique_num) recorded in the consumer's src_info. */
typedef struct Com2p_Retired_Reg_struct {
  Counter op_num;
  Counter unique_num;
  Addr pc;
  Flag is_load;
  Flag valid;
} Com2p_Retired_Reg;

static Com2p_Retired_Reg com2p_retired_reg[NUM_REGS];

void com2p_note_retire(Op* op) {
  if (!COM2P_ENABLE)
    return;
  for (uns i = 0; i < op->uop->num_dest_regs; i++) {
    uns16 id = op->uop->dests[i].id;
    if (id >= NUM_REGS)
      continue;
    Com2p_Retired_Reg* r = &com2p_retired_reg[id];
    r->op_num = op->op_num;
    r->unique_num = op->unique_num;
    r->pc = op->inst->addr;
    r->is_load = op->uop->mem_type == MEM_LD;
    r->valid = TRUE;
  }
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
  Com2p_Chain_Step step[4];  // load-side first
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

/**************************************************************************************/
/* Shallow walk */

typedef struct Com2p_Obs_struct {
  uns8 cls;
  uns8 cmp_folded;
  uns8 num_loads;
  Addr load_pc[2];
  uns8 chain_len[2];
  Com2p_Chain_Step chain[2][4];
} Com2p_Obs;

/* Resolves a map dependency to its in-flight producer.  Returns NULL with
 * *stale set when the producer existed but has left the op pool (retired or
 * flushed); returns NULL with *stale clear for the init_map() no-producer
 * sentinel (op_num == 0). */
static Op* com2p_resolve(Src_Info* src, Flag* stale) {
  Op* p = src->op;
  if (src->op_num == 0)
    return NULL;
  if (p && p->op_pool_valid && p->op_num == src->op_num && p->unique_num == src->unique_num && p->inst)
    return p;
  *stale = TRUE;
  return NULL;
}

static inline Flag com2p_op_is_load(Op* op) {
  return op->uop->mem_type == MEM_LD;
}

/* Slot producer view: enough for the dir judgment whether the producer is
 * still in flight or already retired (via the retired-reg snapshot). */
typedef struct Com2p_Prod_struct {
  Flag resolved;
  Flag is_load;
  Addr pc;
  Counter op_num;  // for SELF dedup
  Op* op;          // non-NULL only while in flight (chain walking needs src_info)
} Com2p_Prod;

static Flag com2p_resolve_slot(Src_Info* src, uns16 reg_id, Com2p_Prod* out) {
  memset(out, 0, sizeof(*out));
  Flag stale = FALSE;
  Op* p = com2p_resolve(src, &stale);
  if (p) {
    out->resolved = TRUE;
    out->is_load = com2p_op_is_load(p);
    out->pc = p->inst->addr;
    out->op_num = p->op_num;
    out->op = p;
    return TRUE;
  }
  if (!stale)
    return TRUE;  // no-producer sentinel: resolved as "no producer" (out->resolved stays FALSE)
  if (reg_id < NUM_REGS) {
    Com2p_Retired_Reg* r = &com2p_retired_reg[reg_id];
    if (r->valid && r->op_num == src->op_num && r->unique_num == src->unique_num) {
      out->resolved = TRUE;
      out->is_load = r->is_load;
      out->pc = r->pc;
      out->op_num = r->op_num;
      return TRUE;
    }
  }
  return FALSE;  // genuinely unresolved
}

/* Walks an immediate-only op chain backward from a non-load producer until a
 * load (success), a disqualifier (multi-register input, mul/div, depth), or a
 * stale node.  Steps are recorded cond-side-first and reversed to load-first
 * order on success.  Mirrors the 3D paper's ARF-reset semantics. */
typedef enum Com2p_Chain_Res_enum {
  COM2P_CHAIN_OK,
  COM2P_CHAIN_MULTIREG,
  COM2P_CHAIN_COMPLEX_OP,
  COM2P_CHAIN_TOO_DEEP,
  COM2P_CHAIN_TO_CONST,  // chain ends at a no-producer register (no load involved)
  COM2P_CHAIN_STALE,
} Com2p_Chain_Res;

static Com2p_Chain_Res com2p_chain_walk(Op* start, Addr* load_pc, uns8* len, Com2p_Chain_Step* steps) {
  Op* node = start;
  uns depth = 0;
  *len = 0;
  while (TRUE) {
    if (depth >= COM2P_CHAIN_MAX_OPS)
      return COM2P_CHAIN_TOO_DEEP;
    Op_Type ot = node->uop->op_type;
    if (ot == OP_IMUL || ot == OP_IDIV)
      return COM2P_CHAIN_COMPLEX_OP;
    if (ot != OP_MOV && ot != OP_IADD && ot != OP_LOGIC && ot != OP_SHIFT && ot != OP_LDA)
      return COM2P_CHAIN_MULTIREG;  // unsupported op class == non-compliant input
    /* the node must consume exactly one dynamic register value (+immediates) */
    Com2p_Prod next;
    Flag have_next = FALSE;
    uns nsrc = node->uop->num_src_regs;
    if (nsrc > node->num_srcs)
      return COM2P_CHAIN_STALE;  // src_info not fully materialized; treat as unresolved
    for (uns j = 0; j < nsrc; j++) {
      if (node->uop->srcs[j].id == REG_ZPS)
        return COM2P_CHAIN_MULTIREG;  // flags input (adc-style): extra dynamic input
      Com2p_Prod prod;
      if (!com2p_resolve_slot(&node->src_info[j], node->uop->srcs[j].id, &prod))
        return COM2P_CHAIN_STALE;
      if (!prod.resolved)
        continue;  // never-written register: constant-ish input
      if (have_next && prod.op_num != next.op_num)
        return COM2P_CHAIN_MULTIREG;
      next = prod;
      have_next = TRUE;
    }
    /* record this node as a chain step */
    const Com2p_Imm* im = com2p_get_imm(node->inst);
    steps[depth].iclass = node->inst->true_op_type;
    steps[depth].imm = im->width ? im->imm : 0;
    steps[depth].has_imm = im->width > 0;
    depth++;
    if (!have_next)
      return COM2P_CHAIN_TO_CONST;
    if (next.is_load) {
      *load_pc = next.pc;
      *len = (uns8)depth;
      for (uns a = 0, b = depth - 1; a < b; a++, b--) {  // reverse to load-first order
        Com2p_Chain_Step t = steps[a];
        steps[a] = steps[b];
        steps[b] = t;
      }
      return COM2P_CHAIN_OK;
    }
    if (!next.op) {
      STAT_EVENT(node->proc_id, COM2P_CHAIN_STALE_NODE);
      return COM2P_CHAIN_STALE;  // retired mid-chain: identity known but src_info gone
    }
    node = next.op;
  }
}

static uns8 com2p_chain_fail_cls(Com2p_Chain_Res r) {
  switch (r) {
    case COM2P_CHAIN_MULTIREG:
      return COM2P_CLS_COMP_MULTIREG;
    case COM2P_CHAIN_COMPLEX_OP:
      return COM2P_CLS_COMP_COMPLEX_OP;
    case COM2P_CHAIN_TOO_DEEP:
      return COM2P_CLS_COMP_TOO_DEEP;
    case COM2P_CHAIN_TO_CONST:
      return COM2P_CLS_NO_LOAD;
    default:
      return COM2P_CLS_UNRESOLVED;
  }
}

/* The two-hop walk.  Fills *obs and returns its classification. */
static uns8 com2p_classify(Op* op, Com2p_Obs* obs, Flag chain_sensitive) {
  memset(obs, 0, sizeof(*obs));
  obs->cls = COM2P_CLS_UNRESOLVED;

  /* Hop 1: the branch's register sources all resolve to the single op that
   * computed its condition (the flags producer; the rcx producer for JCXZ). */
  Flag stale = FALSE;
  Op* cond = NULL;
  uns num_reg_srcs = op->uop->num_src_regs;
  ASSERT(op->proc_id, num_reg_srcs <= op->num_srcs);
  for (uns k = 0; k < num_reg_srcs; k++) {
    ASSERT(op->proc_id, op->src_info[k].type == REG_DATA_DEP);
    Op* p = com2p_resolve(&op->src_info[k], &stale);
    if (!p)
      continue;
    if (cond && p->op_num != cond->op_num) {
      obs->cls = COM2P_CLS_MULTI_COND;
      return obs->cls;
    }
    cond = p;
  }
  if (stale)
    return COM2P_CLS_UNRESOLVED;
  if (!cond) {
    obs->cls = COM2P_CLS_NO_COND;
    return obs->cls;
  }

  /* A compare folded into a load-op appears as a flag-writing MEM_LD uop: the
   * memory value reaches the comparison unmodified. */
  if (com2p_op_is_load(cond)) {
    obs->cls = COM2P_CLS_CONST_DIR;
    obs->cmp_folded = 1;
    obs->num_loads = 1;
    obs->load_pc[0] = cond->inst->addr;
    return obs->cls;
  }

  /* Hop 2: the cond's register value operands. */
  Com2p_Prod slot[2];
  uns num_slots = 0;
  Flag deduped = FALSE;
  uns cond_reg_srcs = cond->uop->num_src_regs;
  ASSERT(cond->proc_id, cond_reg_srcs <= cond->num_srcs);
  for (uns j = 0; j < cond_reg_srcs; j++) {
    ASSERT(cond->proc_id, cond->src_info[j].type == REG_DATA_DEP);
    if (cond->uop->srcs[j].id == REG_ZPS) {
      obs->cls = COM2P_CLS_FLAG_CHAIN;
      return obs->cls;
    }
    Com2p_Prod prod;
    if (!com2p_resolve_slot(&cond->src_info[j], cond->uop->srcs[j].id, &prod))
      return COM2P_CLS_UNRESOLVED;
    if (prod.resolved) {
      Flag dup = FALSE;
      for (uns s = 0; s < num_slots; s++) {
        if (slot[s].resolved && slot[s].op_num == prod.op_num) {
          dup = TRUE;
          deduped = TRUE;
        }
      }
      if (dup)
        continue;
    }
    if (num_slots >= 2) {
      obs->cls = COM2P_CLS_COMPLEX;
      return obs->cls;
    }
    slot[num_slots] = prod;
    num_slots++;
  }

  if (deduped && num_slots == 1) {
    obs->cls = COM2P_CLS_SELF;
    return obs->cls;
  }
  if (num_slots == 0) {
    obs->cls = COM2P_CLS_NO_COND;
    return obs->cls;
  }

  /* Per-slot outcome: a raw load, a load behind an immediate-only chain, or a
   * disqualifier.  The chain walk runs unconditionally (classification depth);
   * only CONFIRMED-eligibility of chain classes is gated by COM2P_COVER_COMP. */
  uns num_load_slots = 0;
  uns num_chain_slots = 0;
  uns8 fail_cls = 0;
  for (uns s = 0; s < num_slots; s++) {
    if (!slot[s].resolved)
      continue;  // no-producer slot: constant-ish side
    if (slot[s].is_load) {
      if (num_load_slots < 2) {
        obs->load_pc[num_load_slots] = slot[s].pc;
        obs->chain_len[num_load_slots] = 0;
      }
      num_load_slots++;
      continue;
    }
    if (!slot[s].op) {
      /* Retired non-load producer: its identity is known but a chain walk is
       * impossible.  If this entry's learnt structure involves chains, treat
       * the instance as unresolved (a mix classification here would be a false
       * mismatch); otherwise classify by identity exactly as the pre-chain
       * code did, so chainless branches keep converging promptly. */
      if (chain_sensitive) {
        STAT_EVENT(op->proc_id, COM2P_CHAIN_STALE_NODE);
        return COM2P_CLS_UNRESOLVED;
      }
      continue;  // counts as a resolved non-load side in the combine below
    }
    Addr lpc = 0;
    uns8 clen = 0;
    Com2p_Chain_Step csteps[4];
    Com2p_Chain_Res r = com2p_chain_walk(slot[s].op, &lpc, &clen, csteps);
    if (r == COM2P_CHAIN_OK) {
      if (num_load_slots < 2) {
        obs->load_pc[num_load_slots] = lpc;
        obs->chain_len[num_load_slots] = clen;
        memcpy(obs->chain[num_load_slots], csteps, sizeof(csteps));
      }
      num_load_slots++;
      num_chain_slots++;
      continue;
    }
    if (r == COM2P_CHAIN_STALE)
      return COM2P_CLS_UNRESOLVED;
    if (!fail_cls)
      fail_cls = com2p_chain_fail_cls(r);
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
      Com2p_Chain_Step ts[4];
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

static Flag com2p_cls_is_target_dir(uns8 cls) {
  return cls == COM2P_CLS_CONST_DIR || cls == COM2P_CLS_LVL_DIR;
}
static Flag com2p_cls_is_target_chain(uns8 cls) {
  return cls == COM2P_CLS_CONST_CHAIN || cls == COM2P_CLS_LVL_CHAIN;
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

void com2p_on_retire(Op* op) {
  if (!COM2P_ENABLE)
    return;
  if (op->uop->cf_type != CF_CBR)
    return;
  if (!com2p_cond_class_targetable(op->uop->cbr_cond_class))
    return;
  /* profile_all: cross-validation mode -- classify every targetable CBR so the
   * distribution is comparable to mispredict-weighted offline taxonomies. */
  if (!COM2P_PROFILE_ALL && !is_h2p_at_exec(op->inst->addr))
    return;

  com2p_table_init();
  Flag new_entry = FALSE;
  Com2p_Entry* e = (Com2p_Entry*)hash_table_access_create(&com2p_table, op->inst->addr, &new_entry);
  if (!new_entry)
    return;
  memset(e, 0, sizeof(*e));
  e->branch_pc = op->inst->addr;
  e->state = COM2P_ST_PROFILING;
  e->cond_class = op->uop->cbr_cond_class;
  STAT_EVENT(op->proc_id, COM2P_ENTRY_ALLOC);
}

void com2p_on_map(Op* op) {
  if (!COM2P_ENABLE || !com2p_table_inited)
    return;
  if (op->off_path)
    return;
  if (op->uop->cf_type != CF_CBR)
    return;
  Com2p_Entry* e = com2p_lookup(op->inst->addr);
  if (!e || e->state == COM2P_ST_REJECTED)
    return;

  Com2p_Obs obs;
  Flag chain_sensitive = e->obs_count > 0 && (e->chain_len[0] || e->chain_len[1]);
  uns8 cls = com2p_classify(op, &obs, chain_sensitive);

  /* Instance-level distribution, for cross-validation against the offline
   * exp29 taxonomy.  The stat blocks mirror Com2p_Cls order. */
  STAT_EVENT(op->proc_id, COM2P_OBS_UNRESOLVED + cls);
  if (op->bp_pred_main.recovery_point == RECOVER_AT_EXEC)
    STAT_EVENT(op->proc_id, COM2P_OBSMIS_UNRESOLVED + cls);

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
      Flag target = com2p_cls_is_target_dir(e->cls) || (COM2P_COVER_COMP && com2p_cls_is_target_chain(e->cls));
      if (consistent && target) {
        e->state = COM2P_ST_CONFIRMED;
        STAT_EVENT(op->proc_id, COM2P_ENTRY_CONFIRMED);
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

  /* CONFIRMED: the same walk becomes the re-backtracking gate.  The override
   * itself (value readiness + redirect) lives in the override stage; here we
   * account for how often the learnt structure holds per instance. */
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
  memset(com2p_retired_reg, 0, sizeof(com2p_retired_reg));
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
    printf("COM2P CONFIRMED pc=0x%llx cls=%u folded=%u loads=%u load_pc=0x%llx/0x%llx gate=%llu/%llu",
           (unsigned long long)e->branch_pc, e->cls, e->cmp_folded, e->num_loads, (unsigned long long)e->load_pc[0],
           (unsigned long long)e->load_pc[1], (unsigned long long)e->gate_match,
           (unsigned long long)(e->gate_match + e->gate_mismatch));
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
  printf("COM2P REJECTED_BY_REASON");
  for (uns r = 0; r <= COM2P_NUM_CLS + 1; r++)
    printf(" %u:%llu", r, (unsigned long long)agg.rejected_by_reason[r]);
  printf("\n");
}
