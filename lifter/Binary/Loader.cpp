#include <bfd.h>
#include <cassert>
#include <cstdint>
#include <cstdlib>
#include <sstream>
#define PACKAGE
#include "Loader.h"

#include <cstdlib>
#include <fstream>
#include <iostream>
#include <stdlib.h>
#include <string>
#include <thirdparty/nlohmann/json.hpp>
#include <unistd.h>
#include <utils/Util.h>
#include <utils/elfconv.h>

#define ERROR_LEN 1000

using namespace BinaryLoader;

int ReadEhdr(const char *file_name, uint64_t *e_phent, uint64_t *e_phnum, uint8_t *e_ph[]) {

  /* confirme ELF library version */
  if (elf_version(EV_CURRENT) == EV_NONE) {
    elfconv_runtime_error("ELF library initialization failed.");
  }

  /* get file descriptor of target ELF file */
  int fd = open(file_name, O_RDONLY);
  if (fd < 0) {
    elfconv_runtime_error("Failed to open ELF.");
  }

  /* get Elf* object */
  auto _elf = elf_begin(fd, ELF_C_READ, NULL);
  if (!_elf) {
    close(fd);
    elfconv_runtime_error("Failed to read ELF.");
  }

  /* confirm that the target file is ELF */
  if (elf_kind(_elf) != ELF_K_ELF) {
    elf_end(_elf);
    close(fd);
    elfconv_runtime_error("%s is not an ELF file\n", file_name);
  }

  auto _ehdr = elf64_getehdr(_elf);
  /* set e_phentsize */
  *e_phent = _ehdr->e_phentsize;
  /* set e_phnum */
  *e_phnum = _ehdr->e_phnum;

  /* get phder array */
  auto e_phdrs = elf64_getphdr(_elf);
  if (!e_phdrs) {
    elf_end(_elf);
    close(fd);
    elfconv_runtime_error("Failed to get program headers.\n");
  }

  /* copy e_phdrs */
  auto e_ph_size = *e_phent * *e_phnum;
  *e_ph = (uint8_t *) malloc(e_ph_size);
  memcpy(*e_ph, e_phdrs, e_ph_size);

  elf_end(_elf);
  close(fd);

  return 0;
}

void ELFObject::GetEhdr() {
  ReadEhdr(file_name.c_str(), &e_phent, &e_phnum, &e_ph);
}

void ELFObject::OpenELF() {

  // init binary file descriptor
  if (bfd_inited) {
    bfd_init();
    bfd_inited = true;
  }

  bfd_h = bfd_openr(file_name.c_str(), nullptr);
  // confirm file_name is opened
  if (!bfd_h) {
    elfconv_runtime_error("failed to open binary file: %s, ERROR: %s\n", file_name.c_str(),
                          bfd_errmsg(bfd_get_error()));
  }
  // confirm file_name is an object file
  if (!bfd_check_format(bfd_h, bfd_object)) {
    elfconv_runtime_error("file \"%s\" does not look like an executable file.\n",
                          file_name.c_str());
  }

  bfd_set_error(bfd_error_no_error);
  // confirm file_name is an ELF binary
  if (!(bfd_get_flavour(bfd_h) == bfd_target_elf_flavour)) {
    elfconv_runtime_error("file \"%s\" is not an ELF binary.\n", file_name.c_str());
  }

  /* get ELF header info */
  GetEhdr();
}

void ELFObject::LoadELF() {
  LoadELFBFD();
}

void ELFObject::LoadELFBFD() {
  // get binary handler
  OpenELF();
  // get entry point
  entry = bfd_get_start_address(bfd_h);
  // get binary format
  bin_type_str = std::string(bfd_h->xvec->name);
  switch (bfd_h->xvec->flavour) {
    case bfd_target_elf_flavour: bin_type = BIN_TYPE_ELF; break;
    case bfd_target_unknown_flavour:
    default: elfconv_runtime_error("file \"%s\" is not an ELF binary.\n", file_name.c_str());
  }
  // get architecture
  bfd_arch_info = bfd_get_arch_info(bfd_h);
  bin_arch_str = std::string(bfd_arch_info->arch_name);
  switch (bfd_arch_info->mach) {
    case bfd_mach_aarch64:
      bin_arch = BinaryArch::ARCH_AARCH64;
      bits = 64;
      break;
    case bfd_mach_x86_64:
      bin_arch = BinaryArch::ARCH_AMD64;
      bits = 64;
      break;
    default: elfconv_runtime_error("unknown architecture\n"); break;
  }

  // get every section
  LoadSectionsBFD();

  // functions detection.
  symbol_table_size = bfd_get_symtab_upper_bound(bfd_h);
  if (symbol_table_size <= 8) {
    // The ELF binary is stripped. we use 'radare2' to detect the function boundaries.
    stripped = true;
    R2Detect();
  } else {
    // we can detect all functions by watching the symbol table.
    LoadStaticSymbolsBFD();
  }

  /* get every dynamic symbol table */
  // LoadDynamicSymbolsBFD(); /* FIXME */
}

void ELFObject::LoadStaticSymbolsBFD() {

  asymbol **bfd_symtab = nullptr;
  // get symbol table space
  bfd_symtab = reinterpret_cast<asymbol **>(malloc(symbol_table_size));
  if (!bfd_symtab) {
    elfconv_runtime_error("failed to allocate symtab memory.\n");
  }
  // read symbol table
  long sym_num = bfd_canonicalize_symtab(bfd_h, bfd_symtab);
  if (sym_num < 0) {
    elfconv_runtime_error("failed to read symtab.\n");
  }
  for (int i = 0; i < sym_num; i++) {
    ELFSymbol::SymbolType sym_type;
    if (bfd_symtab[i]->flags & BSF_FUNCTION ||
        std::memcmp(bfd_symtab[i]->name, "_start", sizeof("_start")) == 0) {
      sym_type = ELFSymbol::SymbolType::SYM_TYPE_FUNC;
    } else if (bfd_symtab[i]->flags & BSF_LOCAL) {
      sym_type = ELFSymbol::SymbolType::SYM_TYPE_LVAR;
      continue;
    } else if (bfd_symtab[i]->flags & BSF_GLOBAL) {
      sym_type = ELFSymbol::SymbolType::SYM_TYPE_GVAR;
      continue;
    } else {
      continue;
    }
    symbols.emplace_back(sym_type, std::string(bfd_symtab[i]->name),
                         bfd_asymbol_value(bfd_symtab[i]), UINT64_MAX);
  }
}

void ELFObject::LoadDynamicSymbolsBFD() {

  asymbol **bfd_symtab = nullptr;
  // get symbol table space
  assert(symbol_table_size > 0);
  long table_size = bfd_get_dynamic_symtab_upper_bound(bfd_h);
  if (table_size < 0) {
    elfconv_runtime_error("failed to read symtab. gotten table_size: %ld\n", table_size);
  } else if (table_size > 0) {
    bfd_symtab = reinterpret_cast<asymbol **>(malloc(table_size));
    if (!bfd_symtab) {
      elfconv_runtime_error("failed to allocate symtab memory.\n");
    }
    // read symbol table
    long sym_num = bfd_canonicalize_dynamic_symtab(bfd_h, bfd_symtab);
    if (sym_num < 0) {
      elfconv_runtime_error("failed to read symtab.\n");
    }
    for (int i = 0; i < sym_num; i++) {
      ELFSymbol::SymbolType sym_type;
      if (bfd_symtab[i]->flags & BSF_FUNCTION ||
          std::memcmp(bfd_symtab[i]->name, "_start", sizeof("_start")) == 0) {
        sym_type = ELFSymbol::SymbolType::SYM_TYPE_FUNC;
      } else if (bfd_symtab[i]->flags & BSF_LOCAL) {
        sym_type = ELFSymbol::SymbolType::SYM_TYPE_LVAR;
        continue;
      } else if (bfd_symtab[i]->flags & BSF_GLOBAL) {
        sym_type = ELFSymbol::SymbolType::SYM_TYPE_GVAR;
        continue;
      } else {
        continue;
      }
      symbols.emplace_back(sym_type, std::string(bfd_symtab[i]->name),
                           bfd_asymbol_value(bfd_symtab[i]), UINT64_MAX);
    }
  } else {
    printf("[INFO] static symbol table is not found.\n");
  }
}

void ELFObject::SetCodeSection() {
  if (sections.empty()) {
    elfconv_runtime_error("[BUG] GetTextSection is called but sections is empty\n");
  } else {
    for (auto &section : sections) {
      if (section.sec_type == ELFSection::SectionType::SEC_TYPE_CODE) {
        code_sections[section.sec_name] =
            CodeSection(section.sec_name, section.vma, section.bytes, section.size);
      }
    }
  }
}

std::vector<ELFObject::FuncEntry> ELFObject::GetFuncEntry() {

  std::vector<ELFObject::FuncEntry> func_entrys;
  if (symbols.empty()) {
    elfconv_runtime_error("[BUG] GetFuncEntry is called but symbols is empty\n");
  } else {
    for (auto &symbol : symbols) {
      if (symbol.sym_type == ELFSymbol::SymbolType::SYM_TYPE_FUNC) {
        func_entrys.emplace_back(FuncEntry(symbol.addr, symbol.sym_name, symbol.sym_size));
      }
    }
  }
  return func_entrys;
}

void ELFObject::LoadSectionsBFD() {

  asection *bfd_sec;

  for (bfd_sec = bfd_h->sections; bfd_sec; bfd_sec = bfd_sec->next) {

    ELFSection::SectionType sec_type;
    flagword bfd_flags;
    bfd_vma vma;
    bfd_size_type size;
    std::string sec_name;
    uint8_t *sec_bytes;

    // get bfd flags
    bfd_flags = bfd_section_flags(bfd_sec);
    if (bfd_flags & SEC_CODE) {
      sec_type = ELFSection::SEC_TYPE_CODE;
    } else if (bfd_flags & (SEC_DATA | SEC_ALLOC)) {
      sec_type = ELFSection::SEC_TYPE_DATA;
    } else if (bfd_flags & SEC_READONLY) {
      sec_type = ELFSection::SEC_TYPE_READONLY;
    } else {
      sec_type = ELFSection::SEC_TYPE_UNKNOWN;
    }
    // get vma, section size, section name, section contents
    vma = bfd_section_vma(bfd_sec);
    size = bfd_section_size(bfd_sec);
    sec_name = std::string(bfd_section_name(bfd_sec));
    if (sec_name.empty()) {
      sec_name = std::string("<unnamed>");
    }
    sec_bytes = reinterpret_cast<uint8_t *>(malloc(size));
    if (!sec_bytes) {
      elfconv_runtime_error("failed to allocate section bytes.\n");
    }
    if (!bfd_get_section_contents(bfd_h, bfd_sec, sec_bytes, 0, size)) {
      elfconv_runtime_error("failed to read and copy section bytes.\n");
    }

    sections.emplace_back(this, sec_type, sec_name, vma, size, sec_bytes);
  }
}

void ELFObject::R2Detect() {
  std::string cmd = "r2 -q -c \"e anal.nopskip=true; e anal.hasnext=true;aaa; aflj\" " + file_name +
                    " > " + "/tmp/elfconv_func_detection.json";

  int ret = system(cmd.c_str());
  if (ret != 0) {
    std::cerr << "failed to execute r2. err_code: " << ret << std::endl;
    exit(EXIT_FAILURE);
  }

  std::ifstream json_file("/tmp/elfconv_func_detection.json");
  nlohmann::json data = nlohmann::json::parse(json_file);

  for (auto j_data : data) {
    uint64_t offset, minbound, maxbound, sym_size;
    std::stringstream fun_offset_name, fun_minbound_name;

    offset = j_data["offset"].get<uint64_t>();
    minbound = j_data["minbound"].get<uint64_t>();
    maxbound = j_data["maxbound"].get<uint64_t>();
    sym_size = j_data["size"].get<uint64_t>();
    fun_offset_name << "__fcn_0x" << std::hex << offset;
    symbols.emplace_back(ELFSymbol::SymbolType::SYM_TYPE_FUNC, fun_offset_name.str(), offset,
                         sym_size);

    // There is the case whose offset is not equal to the minbound for the analysis results of radare2.
    // In the case, we make new function of the range of minbound to maxbound.
    if (minbound != offset) {
      fun_minbound_name << "__fcn_0x" << std::hex << minbound;
      symbols.emplace_back(ELFSymbol::SymbolType::SYM_TYPE_FUNC, fun_minbound_name.str(), minbound,
                           maxbound - minbound);
    }
  }
}

void ELFObject::DebugBinary() {

  printf("[DEBUG]\n");
  printf("File Name: %s\n", file_name.c_str());
  printf("Binary Format Type: %s\n", bin_type_str.c_str());
  printf("CPU Architecture: %s\n", bin_arch_str.c_str());
  printf("Bits: %d\n", bits);
  printf("Entry Address: 0x%08lX\n", entry);
  // debug sections
  DebugSections();
  // debug static symbols
  DebugStaticSymbols();
}

void ELFObject::DebugSections() {

  for (auto &section : sections) {
    char sec_type[100];
    if (section.sec_type == ELFSection::SectionType::SEC_TYPE_CODE) {
      std::memcpy(sec_type, "CODE", sizeof("CODE"));
    } else if (section.sec_type == ELFSection::SectionType::SEC_TYPE_DATA) {
      std::memcpy(sec_type, "DATA", sizeof("DATA"));
    } else if (section.sec_type == ELFSection::SectionType::SEC_TYPE_READONLY) {
      std::memcpy(sec_type, "READONLY", sizeof("READONLY"));
    } else {
      std::memcpy(sec_type, "UNKNOWN", sizeof("UNKNOWN"));
    }
    printf("Section 0x%08lX\t%s\t\t%lu\t%s\n", section.vma, section.sec_name.c_str(), section.size,
           sec_type);
  }
}

void ELFObject::DebugStaticSymbols() {

  char s[250];
  for (auto &symbol : symbols) {
    std::memset(s, ' ', 250);
    // copy "Symbol"
    std::strncpy(s, "Symbol", std::strlen("Symbol"));
    // copy address
    char addr_ss[20];
    std::snprintf(addr_ss, 11, "0x%08lX", symbol.addr);
    std::strncpy(s + 10, addr_ss, 10);
    // copy symbol name
    std::strncpy(s + 25, symbol.sym_name.c_str(), std::strlen(symbol.sym_name.c_str()));
    // copy symbol type
    std::strncpy(s + 100,
                 symbol.sym_type == ELFSymbol::SymbolType::SYM_TYPE_FUNC ? "FUNC " : "OTHER", 5);
    s[105] = '\0';
    printf("%s\n", s);
  }
}
