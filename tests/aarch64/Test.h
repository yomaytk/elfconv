#pragma once
#include "front/Memory.h"

const _ecv_reg_t __G__E_PHENT = 56;
const _ecv_reg_t __G_E_PHNUM = 7;

const addr_t __g_entry_pc = 0x00400000;
_ecv_reg_t __g_e_phent = __G__E_PHENT;
_ecv_reg_t __g_e_phnum = __G_E_PHNUM;
uint8_t __g_e_ph[__G__E_PHENT * __G_E_PHNUM];
