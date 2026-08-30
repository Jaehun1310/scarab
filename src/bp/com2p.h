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
 *                feed the condition and how (direct vs computed), via a shallow
 *                dependency walk at map time.
 ***************************************************************************************/
#ifndef __COM2P_H__
#define __COM2P_H__

#include "globals/global_types.h"

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
  COM2P_NUM_CLS,
} Com2p_Cls;

#define COM2P_REJ_INCONSISTENT COM2P_NUM_CLS  // reject_reason: structure varied across instances

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

void com2p_on_retire(struct Op_struct* op);  // H2P detection -> table allocation
void com2p_note_retire(struct Op_struct* op); // every retired op: refresh the retired-reg snapshots
void com2p_on_map(struct Op_struct* op);     // shallow walk -> profiling / gate
void com2p_reset(void);                      // warmup boundary: drop all state
void com2p_dump(void);                       // end-of-sim summary

#endif /* #ifndef __COM2P_H__ */
