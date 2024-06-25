#pragma once

#include <cstdint>

// when '101' result = (PSTATE.N == PSTATE.V); // GE or LT
static inline bool CondGE(uint64_t sr_nzcv);
// when '101' result = (PSTATE.N == PSTATE.V); // GE or LT
static inline bool CondLT(uint64_t sr_nzcv);
// when '000' result = (PSTATE.Z == '1'); // EQ or NE
static inline bool CondEQ(uint64_t sr_nzcv);
// when '000' result = (PSTATE.Z == '1'); // EQ or NE
static inline bool CondNE(uint64_t sr_nzcv);
// when '110' result = (PSTATE.N == PSTATE.V && PSTATE.Z == '0'); // GT or LE
static inline bool CondGT(uint64_t sr_nzcv);
// when '110' result = (PSTATE.N == PSTATE.V && PSTATE.Z == '0'); // GT or LE
static inline bool CondLE(uint64_t sr_nzcv);
// when '001' result = (PSTATE.C == '1'); // CS or CC
static inline bool CondCS(uint64_t sr_nzcv);
// when '001' result = (PSTATE.C == '1'); // CS or CC
static inline bool CondCC(uint64_t sr_nzcv);
// when '010' result = (PSTATE.N == '1'); // MI or PL
static inline bool CondMI(uint64_t sr_nzcv);
// when '010' result = (PSTATE.N == '1'); // MI or PL
static inline bool CondPL(uint64_t sr_nzcv);
// when '011' result = (PSTATE.V == '1'); // VS or VC
static inline bool CondVS(uint64_t sr_nzcv);
// when '011' result = (PSTATE.V == '1'); // VS or VC
static inline bool CondVC(uint64_t sr_nzcv);
// when '100' result = (PSTATE.C == '1' && PSTATE.Z == '0'); // HI or LS
static inline bool CondHI(uint64_t sr_nzcv);
// when '100' result = (PSTATE.C == '1' && PSTATE.Z == '0'); // HI or LS
static inline bool CondLS(uint64_t sr_nzcv);
static inline bool CondAL(uint64_t sr_nzcv);