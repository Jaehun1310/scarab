/* Copyright 2020 University of California Santa Cruz
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
 * File         : frontend/pt_memtrace/memtrace_trace_reader_memtrace.h
 * Author       : Heiner Litz
 * Date         : 05/15/2020
 * Description  :
 ***************************************************************************************/
#ifndef MEMTRACE_READER_MEMTRACE_H
#define MEMTRACE_READER_MEMTRACE_H

#include <cstdio>
#include <unordered_map>

#include "globals/assert.h"

#include "frontend/pt_memtrace/memtrace_trace_reader.h"

#undef ASSERT
#undef UNUSED
#include "analyzer.h"
#include "raw2trace.h"
#include "raw2trace_directory.h"


class TraceReaderMemtrace : public TraceReader {
 public:
  const InstInfo* getNextInstruction() override;
  TraceReaderMemtrace(const std::string& _trace, uint32_t _bufsize, bool _enable_reg_value_sidecar = false);
  ~TraceReaderMemtrace();

 private:
  bool initTrace() override;
  bool locationForVAddr(uint64_t _vaddr, uint8_t** _loc, uint64_t* _size) override;
  void init(const std::string& _trace);
  static const char* parse_buildid_string(const char* src, OUT void** data);
  bool getNextInstruction__(InstInfo* _info, InstInfo* _prior);
  /// predecoded_dr: DR decode from the trace probe (same bytes); XED still decodes below.
  void processInst(InstInfo* _info, instr_t* predecoded_dr);
  /// When non-null and encoding_is_new, use this instead of decoding again (caller-owned).
  void processDrIsaInst(InstInfo* _info, bool has_another_mem, instr_t* predecoded);
  uint32_t add_dependency_info(ctype_pin_inst* info, instr_t* drinst);
  void fill_in_basic_info(ctype_pin_inst* info, instr_t* drinst, size_t size, dynamorio::drmemtrace::trace_type_t type);
  bool typeIsMem(dynamorio::drmemtrace::trace_type_t _type);
  void initRegValueSidecars(const std::string& trace);
  void closeRegValueSidecars();
  void maybeAttachRegValues(InstInfo* info);

  /// v2 reg-value sidecar file layout (written packed by the tracer; natural
  /// alignment pads identically, guarded by a static_assert at the read site).
  struct RegValueSidecarFileHeader {
    uint64_t magic;
    uint64_t version;
    uint64_t tid;
  };
  struct RegValueSidecarRecord {
    uint64_t inst_seq;  // writer-side ordinal; diagnostics only, never used for matching
    uint64_t pc;
    uint64_t value[MAX_DESTS];
    uint16_t reg[MAX_DESTS];  // normalized DR reg id per slot (0xFFFF = rflags)
    uint8_t num_dsts;
    uint8_t valid_mask;
    uint16_t reserved0;
    uint32_t reserved1;
  };
  struct RegValueSidecarStream {
    FILE* file = nullptr;
    bool eof = false;
    uint64_t tid = 0;
    /// Records dropped because their pc was never asked about (instructions the
    /// tracer records but scarab decodes without dst slots, e.g. `ret`).
    uint64_t skipped_records = 0;
  };

  std::unique_ptr<dynamorio::drmemtrace::module_mapper_t> module_mapper_ = nullptr;
  dynamorio::drmemtrace::raw2trace_directory_t directory_ = {};
  void* dcontext_ = nullptr;
  unsigned int knob_verbose_ = 0;
  bool trace_has_encodings_ = false;
  bool reg_value_sidecar_enabled_ = false;
  std::unordered_map<uint64_t, RegValueSidecarStream> reg_value_sidecars_ = {};

  enum class MTState {
    INST,
    MEM1,
    MEM2,
  };

  std::unique_ptr<dynamorio::drmemtrace::reader_t> reader_ = nullptr;
  std::unique_ptr<dynamorio::drmemtrace::reader_t> reader_end_ = nullptr;
  bool reader_at_eof_ = false;
  bool reader_first_read_ = true;
  uint64_t roi_end_ = 0;

  bool advanceReader();

  MTState mt_state_ = MTState::INST;
  dynamorio::drmemtrace::memref_t mt_ref_ = {};
  bool mt_use_next_ref_ = true;
  int mt_mem_ops_ = 0;
  uint64_t mt_seq_ = 0;
  uint32_t mt_prior_isize_ = 0;
  InstInfo mt_info_a_ = {};
  InstInfo mt_info_b_ = {};
  bool mt_using_info_a_ = true;
  ctype_pin_inst gap_patch_jmp_ = {};
  uint64_t mt_warn_target_ = 0;
};

#endif
