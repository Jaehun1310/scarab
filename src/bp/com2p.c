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
  ASSERTM(0, !COM2P_COVER_COMP, "com2p_cover_comp is not implemented yet\n");
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

/* The two-hop walk.  Fills *obs and returns its classification. */
static uns8 com2p_classify(Op* op, Com2p_Obs* obs) {
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

  uns num_load_slots = 0;
  for (uns s = 0; s < num_slots; s++) {
    if (slot[s].resolved && slot[s].is_load) {
      if (num_load_slots < 2)
        obs->load_pc[num_load_slots] = slot[s].pc;
      num_load_slots++;
    }
  }

  if (num_slots == 1) {
    obs->cls = num_load_slots == 1 ? COM2P_CLS_CONST_DIR : COM2P_CLS_CONST_COMP;
  } else {
    if (num_load_slots == 2)
      obs->cls = COM2P_CLS_LVL_DIR;
    else if (num_load_slots == 1)
      obs->cls = COM2P_CLS_REG_MIX;
    else
      obs->cls = COM2P_CLS_NO_LOAD;
  }
  if (obs->cls == COM2P_CLS_CONST_DIR) {
    obs->num_loads = 1;
  } else if (obs->cls == COM2P_CLS_LVL_DIR) {
    obs->num_loads = 2;
    if (obs->load_pc[0] > obs->load_pc[1]) {  // operand order is encoding noise; canonicalize
      Addr t = obs->load_pc[0];
      obs->load_pc[0] = obs->load_pc[1];
      obs->load_pc[1] = t;
    }
  } else {
    obs->load_pc[0] = 0;
    obs->load_pc[1] = 0;
  }
  return obs->cls;
}

static Flag com2p_obs_matches_entry(const Com2p_Entry* e, const Com2p_Obs* obs) {
  return e->cls == obs->cls && e->cmp_folded == obs->cmp_folded && e->num_loads == obs->num_loads &&
         e->load_pc[0] == obs->load_pc[0] && e->load_pc[1] == obs->load_pc[1];
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
  uns8 cls = com2p_classify(op, &obs);

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
      e->obs_count = 1;
      e->obs_match = 1;
      return;
    }
    e->obs_count++;
    if (com2p_obs_matches_entry(e, &obs))
      e->obs_match++;
    if (e->obs_count >= COM2P_OBS_N) {
      Flag consistent = (uns)e->obs_match * 100 >= (uns)e->obs_count * COM2P_CONSIST_PCT;
      Flag target = e->cls == COM2P_CLS_CONST_DIR || e->cls == COM2P_CLS_LVL_DIR;
      if (consistent && target) {
        e->state = COM2P_ST_CONFIRMED;
        STAT_EVENT(op->proc_id, COM2P_ENTRY_CONFIRMED);
      } else {
        e->state = COM2P_ST_REJECTED;
        e->reject_reason = consistent ? e->cls : COM2P_REJ_INCONSISTENT;
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
    STAT_EVENT(op->proc_id, COM2P_ENTRY_EVICTED);
  }
}

/**************************************************************************************/
/* Reset / dump */

void com2p_reset(void) {
  memset(com2p_retired_reg, 0, sizeof(com2p_retired_reg));
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
    printf("COM2P CONFIRMED pc=0x%llx cls=%u folded=%u loads=%u load_pc=0x%llx/0x%llx gate=%llu/%llu\n",
           (unsigned long long)e->branch_pc, e->cls, e->cmp_folded, e->num_loads, (unsigned long long)e->load_pc[0],
           (unsigned long long)e->load_pc[1], (unsigned long long)e->gate_match,
           (unsigned long long)(e->gate_match + e->gate_mismatch));
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
  printf("COM2P CONFIRMED_BY_CLS const_dir=%llu lvl_dir=%llu\n",
         (unsigned long long)agg.confirmed_by_cls[COM2P_CLS_CONST_DIR],
         (unsigned long long)agg.confirmed_by_cls[COM2P_CLS_LVL_DIR]);
  printf("COM2P GATE match=%llu mismatch=%llu\n", (unsigned long long)agg.gate_match,
         (unsigned long long)agg.gate_mismatch);
  printf("COM2P REJECTED_BY_REASON");
  for (uns r = 0; r <= COM2P_NUM_CLS + 1; r++)
    printf(" %u:%llu", r, (unsigned long long)agg.rejected_by_reason[r]);
  printf("\n");
}
