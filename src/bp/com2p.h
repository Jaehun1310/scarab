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
 * File         : bp/com2p.h
 * Description  : COM2P -- overrides H2P conditional-branch predictions by computing
 *                the direction from the feeder load value(s).  This header exposes
 *                the metadata table that learns, per H2P branch PC, which loads
 *                feed the condition and how (direct vs computed), via ARF-ext
 *                forward propagation at retire (3D-Branch Overrider style).
 ***************************************************************************************/
#ifndef __COM2P_H__
#define __COM2P_H__

#include "globals/global_types.h"

#ifdef __cplusplus
extern "C" {
#endif

struct Op_struct;

/* Per-instance classification of a walked branch.  Order must match the
 * COM2P_OBS_* / COM2P_OBSMIS_* stat blocks in bp.stat.def. */
typedef enum Com2p_Cls_enum {
  COM2P_CLS_UNRESOLVED,  // a producer could not be identified (not counted as an observation)
  COM2P_CLS_CONST_DIR,   // load vs immediate, value reaches the compare unmodified (target)
  COM2P_CLS_LVL_DIR,     // load vs load, both raw (target)
  COM2P_CLS_CONST_COMP,  // load vs immediate behind computation (3D-Overrider scope, later)
  COM2P_CLS_REG_MIX,     // one compare side load, the other a non-load register
  COM2P_CLS_NO_LOAD,     // no compare side produced by a load
  COM2P_CLS_SELF,        // both compare sides from one producer (test r,r)
  COM2P_CLS_FLAG_CHAIN,  // condition op itself consumes flags (adc/sbb chains)
  COM2P_CLS_MULTI_COND,  // branch sources resolve to more than one producer
  COM2P_CLS_NO_COND,     // no producer for the branch condition at all
  COM2P_CLS_COMPLEX,     // more than two compare sides
  /* chain-walk refinements of the old CONST_COMP (comp mass now splits here) */
  COM2P_CLS_CONST_CHAIN,     // one load behind an immediate-only op chain (3D-coverable)
  COM2P_CLS_LVL_CHAIN,       // two loads, at least one side behind an immediate-only chain (novel)
  COM2P_CLS_COMP_MULTIREG,   // a chain node consumed a second dynamic register (ARF-reset rule)
  COM2P_CLS_COMP_COMPLEX_OP, // mul/div in the chain (disqualified even with immediates)
  COM2P_CLS_COMP_TOO_DEEP,   // chain longer than COM2P_CHAIN_MAX_OPS
  COM2P_NUM_CLS,
} Com2p_Cls;

#define COM2P_REJ_INCONSISTENT COM2P_NUM_CLS         // reject_reason: structure varied during profiling
#define COM2P_REJ_GATE_UNSTABLE (COM2P_NUM_CLS + 1)  // reject_reason: confirmed structure stopped holding at runtime

typedef enum Com2p_State_enum {
  COM2P_ST_PROFILING,
  COM2P_ST_CONFIRMED,
  COM2P_ST_REJECTED,
} Com2p_State;

typedef struct Com2p_Entry_struct {
  Addr branch_pc;
  uns8 state;          // Com2p_State
  uns8 reject_reason;  // Com2p_Cls of the learnt structure, or COM2P_REJ_INCONSISTENT
  /* structure learnt during profiling (frozen on CONFIRMED) */
  uns8 cls;  // Com2p_Cls
  uns8 cmp_folded;
  uns8 num_loads;
  uns8 cond_class;  // Cbr_Cond_Class
  uns8 chain_len[2];  // ops between load_pc[i] and the cond (0 = raw); contents live in the chain table
  Addr load_pc[2];
  uns64 imm;  // reserved for COM2P_REALISTIC_COMPUTE (immediate operand of the compare)
  /* profiling */
  uns16 obs_count;
  uns16 obs_match;
  Counter unresolved;
  /* CONFIRMED-phase re-backtracking gate */
  Counter gate_match;
  Counter gate_mismatch;
  /* override bookkeeping (driven in the override stage) */
  Counter provided;
  Counter success;
} Com2p_Entry;

void com2p_on_retire(struct Op_struct* op);   // H2P alloc + classification (profiling / gate)
void com2p_note_retire(struct Op_struct* op);  // every retired op: ARF-ext forward propagation
void com2p_note_fetch(struct Op_struct* op);   // every fetched op: track feeder load instances
void com2p_override_predict(struct Op_struct* op, uns8* pred);  // ideal-mode direction substitution
void com2p_reset(void);                        // warmup boundary: drop all state
void com2p_dump(void);                         // end-of-sim summary

#ifdef __cplusplus
}
#endif

#endif /* #ifndef __COM2P_H__ */
