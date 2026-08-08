#pragma once

#include <algorithm>
#include <cstdint>
#include <cstring>
#include <iostream>
#include <list>
#include <map>
#include <memory>
#include <queue>
#include <string>
#include <unordered_map>
#include <vector>

namespace BinaryLoader {

class ELFSymbol;
class ELFSection;
class ELFObject;
struct ELFObjectImpl;

// The address range of one ELF section.
//
// This replaces bfd's `asection` in the two roles elfconv actually used it for: as a stable
// identity that two symbols can be compared against (`in_section == in_section`), and as a
// carrier of the section's vma and size. It is deliberately NOT `ELFSection` -- `ELFSection`
// holds a copy of the section bytes and is filtered (sections based at 0x0 are dropped),
// whereas containment queries must run over the whole section list the way bfd's did.
struct SectionRange {
  std::string sec_name;
  uint64_t vma;
  uint64_t size;
};

class ELFSymbol {
 public:
  enum SymbolType {
    SYM_TYPE_FUNC = 1,
    SYM_TYPE_LVAR = 2,
    SYM_TYPE_GVAR = 3,
    SYM_TYPE_UNKNOWN = 4,
  };

  ELFSymbol(SymbolType __sym_type, std::string __sym_name, uintptr_t __addr,
            const SectionRange *__in_section, uint64_t __size = 0)
      : sym_type(__sym_type),
        sym_name(__sym_name),
        addr(__addr),
        in_section(__in_section),
        size(__size) {}
  ELFSymbol::SymbolType sym_type;
  std::string sym_name;
  uintptr_t addr;
  const SectionRange *in_section;
  uint64_t size;  // Function size from symbol table
};

class ELFSection {
 public:
  enum SectionType {
    SEC_TYPE_CODE = 0,
    SEC_TYPE_DATA = 1,
    SEC_TYPE_READONLY = 2,
    SEC_TYPE_UNKNOWN = 3,
  };

  ELFSection(ELFObject *__elf_obj, ELFSection::SectionType __sec_type, std::string __sec_name,
             uint64_t __vma, uint64_t __size, uint8_t *__bytes)
      : elf_obj(__elf_obj),
        sec_type(__sec_type),
        sec_name(__sec_name),
        vma(__vma),
        size(__size),
        bytes(__bytes) {}
  ~ELFSection() {}

  ELFObject *elf_obj;
  ELFSection::SectionType sec_type;
  std::string sec_name;
  uint64_t vma;
  uint64_t size;
  uint8_t *bytes;
};

class ELFObject {
 public:
  enum BinaryType : uint8_t {
    BIN_TYPE_ELF = 0,
    BIN_TYPE_UNKNOWN = 1,
  };
  enum BinaryArch : uint8_t {
    ARCH_AARCH64 = 0,
    ARCH_AMD64 = 1,
    ARCH_UNKNOWN = 2,
  };

  struct CodeSection {
    std::string sec_name;
    uintptr_t vma;
    uint8_t *bytes;
    uint64_t size;
    CodeSection(std::string __sec_name, uintptr_t __vma, uint8_t *__bytes, uint64_t __size)
        : sec_name(__sec_name),
          vma(__vma),
          bytes(__bytes),
          size(__size) {}
    CodeSection() {}
  };

  void LoadELF();
  void SetCodeSection();
  const SectionRange *GetIncludedSection(uint64_t vma);
  void R2Detect();
  int GetSblFromEhFrame();
  void DebugSections();
  void DebugStaticSymbols();
  void DebugBinary();

  explicit ELFObject(std::string __file_name);
  ~ELFObject();

  std::string file_name;
  ELFObject::BinaryType bin_type;
  std::string bin_type_str;
  ELFObject::BinaryArch bin_arch;
  std::string bin_arch_str;
  uint32_t bits;
  uintptr_t entry;
  std::vector<ELFSection> sections;
  // Every section, unfiltered, in section-header order. Owns the identities handed out by
  // `GetIncludedSection`, so it must not be resized after symbol loading begins.
  std::vector<SectionRange> all_sections;
  std::unordered_map<uint64_t, ELFSymbol> func_symbols_map;
  std::vector<ELFSymbol> func_symbols;
  std::unordered_map<std::string, CodeSection> code_sections;
  // Number of `.symtab` entries, excluding the reserved null entry. Zero means the binary is
  // stripped. (This previously held bfd's `bfd_get_symtab_upper_bound`, a byte count that was
  // tested against 8 -- one `asymbol *` -- to mean the same thing.)
  unsigned long symbol_table_size;

  uint64_t e_phent;
  uint64_t e_phnum;
  uint8_t *e_ph;

  bool is_stripped;
  bool able_vrp_opt;

 private:
  void OpenELF();
  void LoadELFObject();
  void LoadStaticSymbols();
  void LoadSections();
  void GetEhdr();

  std::unique_ptr<ELFObjectImpl> impl;
};
}  // namespace BinaryLoader
