## Debug Tools
This document shows how to use debug tools that elfconv provides. 
### 1. LIFT_DEBUG
The `LIFT_DEBUG` macro lets you use debug features as follows.
- **Store the program counter to the %PC variable.** This lets you confirm the program counter of every instruction by watching the `g_state.gpr.pc.qword` (via the `debug_state_machine` function, and so on) at runtime.
- **Register the custom signal handler.** This lets you register your function to the custom handler, so you can easily debug when the lifted binary process receives signals. In the default implementation, the custom handler for `SIGSEGV` is registered (see [`Entry.cpp`](https://github.com/yomaytk/elfconv/blob/main/runtime/Entry.cpp) for detail).
#### How to use
1. Comment out the `define #LIFT_DEBUG` in the [`HelperMacro.h`](https://github.com/yomaytk/elfconv/blob/main/backend/remill/include/remill/BC/HelperMacro.h)
### 2. LIFT_CALLSTACK_DEBUG
The `LIFT_CALLSTACK_DEBUG` lets you **output the call stack of the lifted functions** as follows, so you can check the order of the executed functions when executing the lifted binary, and so on.
```bash
|||start : __cxa_atexit_____1088_406020
||||start : __internal_atexit_____1089_405f20
|||||start : __aarch64_cas4_acq_____94_451c70
|||||start : __new_exitfn_____1090_405e10
|||||start : __aarch64_swp4_rel_____83_451ec0
|||start : _init_____1145_4002b8
||||start : call_weak_fn_____1139_4005c4
...
```
#### How to use
1. Comment out the `define #LIFT_CALLSTACK_DEBUG` in the [`HelperMacro.h`](https://github.com/yomaytk/elfconv/blob/main/backend/remill/include/remill/BC/HelperMacro.h)
### 3. LIFT_INSN_DEBUG
The `LIFT_INSN_DEBUG` macro lets you **confirm the CPU state of the specified instructions** via the `debug_insn` function as follows. you should edit the `debug_insn` if you want to confirm the additional CPU states.
```bash
[DEBUG INSN]
PC: 0x41fc30 x0: 0x400000022000 x1: 0x8 x2: 0x400000021b80 x3: 0x0
```
#### How to use
1. Comment out the `define #LIFT_INSN_DEBUG` in the [`HelperMacro.h`](https://github.com/yomaytk/elfconv/blob/main/backend/remill/include/remill/BC/HelperMacro.h)
2. Add the address of the target instruction to the `target_addrs` vector in the [`InstrucitonLifter.cpp`](https://github.com/yomaytk/elfconv/blob/main/backend/remill/lib/BC/InstructionLifter.cpp).
### 4. Others
#### 4-1. Confirm the All instructions of the Specified function
You can **confirm the all executed instructions for the specified function** via the `debug_insn` at runtime as follows.
```bash
[DEBUG INSN]
PC: 0x41fc38 x0: 0x400000021b78 x1: 0x400000021b78 x2: 0xfffffffffffff000 x3: 0x4
[DEBUG INSN]
PC: 0x41fc3c x0: 0x400000021b78 x1: 0x400000021b78 x2: 0x499000 x3: 0x4
[DEBUG INSN]
PC: 0x41fc40 x0: 0x400000021b78 x1: 0x400000021b78 x2: 0x499000 x3: 0x4
[DEBUG INSN]
PC: 0x41fc44 x0: 0x400000021b78 x1: 0x400000021b78 x2: 0x499000 x3: 0x4
[DEBUG INSN]
PC: 0x41fc48 x0: 0x400000021b78 x1: 0x400000021b78 x2: 0x499000 x3: 0x4
...
```
**How to use**

You should add option `--dbg_fun_cfg <function name>` to the lifting command (`elflift`). If you use [`scripts/dev.sh`](https://github.com/yomaytk/elfconv/blob/main/scripts/dev.sh) or [`bin/elfconv.sh`](https://github.com/yomaytk/elfconv/blob/main/bin/elfconv.sh), you can turn on this feature by executing as follows
(The example target function is `_dl_get_origin`).
```bash
# scripts/dev.sh
elfconv/build$ TARGET=native ../scripts/dev.sh ../examples/hello/a.out _dl_get_origin
# bin/elfconv.sh
elfconv/bin$ TARGET=wasm-host ./elfconv.sh ../examples/hello/a.out _dl_get_origin
```
#### 4-2. Confirm the Memory Value
To confirm the memory value at runtime, elfconv implements two functions, `debug_memory_value` and `debug_memory_value_change` in the [`elfconv.cpp`](https://github.com/yomaytk/elfconv/blob/main/utils/elfconv.cpp).
You can confirm the value and the change of the value stored in the target memory.

**How to use**

Please see the comment of the `debug_memory_value` and `debug_memory_value_change` functions.
