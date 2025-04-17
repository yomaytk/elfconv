# Adding new AArch64 Instruction Supports

When adding a new AArch64 instruction to elfconv (based on Remill), follow these four steps:

1.	**Decode the raw byte pattern**
2.	**Convert decode results into elfconv’s (Remill's) format**
3.	**Implement the instruction’s semantics**
4.	**Bind the instruction form to its semantic function**

As a sample, we explain the steps for adding the `STP <Wt1>, <Wt2>, [<Xn|SP>, #<imm>]!` instruction. Naturally, the implementation details will vary depending on the instruction, but since the basic flow is the same for every instruction, adding a new one isn’t that difficult.

## 1. Decode the raw byte pattern

First, check whether the incoming 32‑bit instruction word matches the STP (Store Pair with Update) pattern, then unpack each field into an InstData structure:

Relevant file: [`backend/remill/lib/Arch/AArch64/Extract.cpp`](https://raw.githubusercontent.com/yomaytk/elfconv/refs/heads/main/backend/remill/lib/Arch/AArch64/Extract.cpp)

```cpp
static bool TryExtractSTP_32_LDSTPAIR_PRE(InstData &inst, uint32_t bits) {
  // If the top 12 bits aren’t 0x298, this isn’t STP
  if ((bits & 0xffc00000U) != 0x29800000U) {
    return false;
  }
  // Use a union to split out each bitfield
  union {
    uint32_t flat;
    struct {
      uint32_t Rt    : 5;
      uint32_t Rn    : 5;
      uint32_t Rt2   : 5;
      uint32_t imm7  : 7;
      uint32_t L     : 1;
      uint32_t _23   : 1;  // always 1
      uint32_t _24   : 1;  // always 1
      uint32_t _25   : 1;  // always 0
      uint32_t V     : 1;
      uint32_t _27   : 1;  // always 1
      uint32_t _28   : 1;  // always 0
      uint32_t _29   : 1;  // always 1
      uint32_t opc   : 2;
    } __attribute__((packed));
  } __attribute__((packed)) enc;
  static_assert(sizeof(enc) == 4, "Unexpected struct size");
  enc.flat = bits;

  // Copy into InstData
  inst.Rt          = static_cast<uint8_t>(enc.Rt);
  inst.opc         = static_cast<uint8_t>(enc.opc);
  inst.Rt2         = static_cast<uint8_t>(enc.Rt2);
  inst.L           = static_cast<uint8_t>(enc.L);
  inst.V           = static_cast<uint8_t>(enc.V);
  inst.Rn          = static_cast<uint8_t>(enc.Rn);
  inst.imm7.uimm   = static_cast<uint64_t>(enc.imm7);
  inst.iform       = InstForm::STP_32_LDSTPAIR_PRE;
  inst.iclass      = InstName::STP;
  return true;
}
```

## 2. Convert decode results into elfconv’s (Remill's) format

Second, take the fields in `InstData` and make an Instruction object that Remill can process. Here we add register and memory operands:

Relevant file: [`backend/remill/lib/Arch/AArch64/Arch.cpp`](https://github.com/yomaytk/elfconv/blob/main/backend/remill/lib/Arch/AArch64/Arch.cpp)

```cpp
// STP  <Wt1>, <Wt2>, [<Xn|SP>, #<imm>]!
bool TryDecodeSTP_32_LDSTPAIR_PRE(const InstData &data, Instruction &inst) {
  inst.sema_func_arg_type = SemaFuncArgType::Runtime;
  AddRegOperand(inst, kActionRead, kRegW, kUseAsValue, data.Rt);
  AddRegOperand(inst, kActionRead, kRegW, kUseAsValue, data.Rt2);
  uint64_t offset = static_cast<uint64_t>(data.imm7.simm7);
  AddPreIndexMemOp(inst, 64, data.Rn, offset << 2);
  return true;
}
```

## 3. Implement the instruction’s semantics functions.

As described in Document [`docs/README.md`](), the process that operates equivalent to the machine instruction is defined as a *semantic function* by Remill.
We can define the runtime behavior using Remill’s `DEF_SEM` macros. For a 32‑bit store-pair-with-update instruction, read two 32‑bit registers and write them as a vector to memory:

Relevant directory: [`backend/remill/lib/Arch/AArch64/Semantics`](https://github.com/yomaytk/elfconv/tree/main/backend/remill/lib/Arch/AArch64/Semantics)

```cpp
DEF_SEM_VOID_RUN(StorePairUpdateIndex32, R32 src1, R32 src2, MVI64 dst_mem) {
  // Read the two 32‑bit source registers
  _ecv_u32v2_t vec = { Read(src1), Read(src2) };
  // Store the two‑element vector to the memory address
  UWriteMVI32(dst_mem, vec);
}
```

## 4. Bind the instruction form to its semantic function
Finally, this semantics function needs to be registered with the `LLVM Module*` so that it can be looked up by the instruction identifier (`STP_32_LDSTPAIR_PRE` in the following example). To do that, we define it as follows using an identifier representing the instruction.

Relevant Directory: [`backend/remill/lib/Arch/AArch64/Semantics`](https://github.com/yomaytk/elfconv/tree/main/backend/remill/lib/Arch/AArch64/Semantics)

```cpp
// Map STP_32_LDSTPAIR_PRE (STP <Wt1>, <Wt2>, [<Xn|SP>, #<I'm>]!) to the StorePairUpdateIndex32 function
DEF_ISEL(STP_32_LDSTPAIR_PRE) = StorePairUpdateIndex32;
```

