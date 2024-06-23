#pragma once

#include "remill/Arch/AArch64/Runtime/Operators.h"
#include "remill/Arch/AArch64/Runtime/State.h"
#include "remill/Arch/AArch64/Runtime/Types.h"
#include "remill/Arch/Name.h"
#include "remill/Arch/Runtime/Float.h"
#include "remill/Arch/Runtime/Intrinsics.h"
#include "remill/Arch/Runtime/Operators.h"
#include "remill/Arch/Runtime/Types.h"

template <typename T, typename S1, typename S2>
[[gnu::const]] ALWAYS_INLINE static bool ZeroFlag(T res, S1 lhs, S2 rhs);

template <typename T, typename S1, typename S2>
[[gnu::const]] ALWAYS_INLINE static bool SignFlag(T res, S1 lhs, S2 rhs);

template <typename F, typename T>
ALWAYS_INLINE static auto CheckedFloatUnaryOp(State &state, F func, T arg1) -> decltype(func(arg1));

template <typename F, typename T>
ALWAYS_INLINE static auto CheckedFloatBinOp(State &state, F func, T arg1,
                                            T arg2) -> decltype(func(arg1, arg2));