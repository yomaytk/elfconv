#include "Loader.h"

#include <cassert>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <glog/logging.h>
#include <iostream>
#include <llvm/BinaryFormat/ELF.h>
#include <llvm/DebugInfo/DWARF/DWARFContext.h>
#include <llvm/DebugInfo/DWARF/DWARFDebugFrame.h>
#include <llvm/Object/ELF.h>
#include <llvm/Object/ELFObjectFile.h>
#include <llvm/Object/ObjectFile.h>
#include <llvm/Support/Casting.h>
#include <llvm/Support/Error.h>
#include <llvm/Support/MemoryBuffer.h>
#include <sstream>
#include <string>
#include <thirdparty/nlohmann/json.hpp>
#include <unistd.h>
#include <utils/Util.h>
#include <utils/elfconv.h>

using namespace BinaryLoader;

// elfconv lifts only 64-bit little-endian ELF (AArch64 and amd64), which is the same set the
// bfd-based loader accepted -- it raised "unknown architecture" for anything else.
using ECVELFT = llvm::object::ELF64LE;
using ECVELFObjectFile = llvm::object::ELFObjectFile<ECVELFT>;

namespace BinaryLoader {

// Holds the LLVM objects backing the load. It lives in the .cpp so that no LLVM header reaches
// `Loader.h`, and therefore none reaches `TraceManager.h` -- which used to pull in <bfd.h>.
struct ELFObjectImpl {
  std::unique_ptr<llvm::MemoryBuffer> buffer;
  std::unique_ptr<llvm::object::ObjectFile> object;
  const ECVELFObjectFile *elf = nullptr;

  const llvm::object::ELFFile<ECVELFT> &File() const {
    return elf->getELFFile();
  }
};

}  // namespace BinaryLoader

ELFObject::ELFObject(std::string __file_name)
    : file_name(__file_name),
      bin_type(BIN_TYPE_UNKNOWN),
      bin_arch(ARCH_UNKNOWN),
      bits(0),
      entry(0),
      symbol_table_size(0),
      e_phent(0),
      e_phnum(0),
      e_ph(nullptr),
      is_stripped(false),
      able_vrp_opt(false),
      impl(std::make_unique<ELFObjectImpl>()) {}

ELFObject::~ELFObject() = default;

// Read the size of every function symbol, keyed by name, from `.symtab` and `.dynsym`.
//
// Kept as a name-keyed map rather than reading each symbol's own st_size inline, because the
// original walked BOTH tables and let a later table overwrite an earlier one's entry for the
// same name. Reading st_size directly per symbol would be cleaner and would not reproduce that.
static std::unordered_map<std::string, uint64_t>
ReadSymbolSizes(const llvm::object::ELFFile<ECVELFT> &elf_file) {
  std::unordered_map<std::string, uint64_t> sym_sizes;

  auto sections = elf_file.sections();
  if (!sections) {
    llvm::consumeError(sections.takeError());
    return sym_sizes;
  }

  for (const auto &shdr : *sections) {
    if (shdr.sh_type != llvm::ELF::SHT_SYMTAB && shdr.sh_type != llvm::ELF::SHT_DYNSYM) {
      continue;
    }

    auto symbols = elf_file.symbols(&shdr);
    if (!symbols) {
      llvm::consumeError(symbols.takeError());
      continue;
    }
    auto str_table = elf_file.getStringTableForSymtab(shdr);
    if (!str_table) {
      llvm::consumeError(str_table.takeError());
      continue;
    }

    for (const auto &sym : *symbols) {
      // Only store function symbols.
      const auto sym_type = sym.getType();
      if (sym_type != llvm::ELF::STT_FUNC && sym_type != llvm::ELF::STT_NOTYPE) {
        continue;
      }
      auto name = sym.getName(*str_table);
      if (!name) {
        llvm::consumeError(name.takeError());
        continue;
      }
      if (!name->empty() && sym.st_size > 0) {
        sym_sizes[name->str()] = sym.st_size;
      }
    }
  }

  return sym_sizes;
}

void ELFObject::GetEhdr() {
  const auto &elf_file = impl->File();
  const auto &ehdr = elf_file.getHeader();

  /* set e_phentsize */
  e_phent = ehdr.e_phentsize;
  /* set e_phnum */
  e_phnum = ehdr.e_phnum;

  /* get phdr array */
  auto phdrs = elf_file.program_headers();
  if (!phdrs) {
    llvm::consumeError(phdrs.takeError());
    elfconv_runtime_error("Failed to get program headers.\n");
  }

  /* copy e_phdrs */
  auto e_ph_size = e_phent * e_phnum;
  e_ph = (uint8_t *) malloc(e_ph_size);
  if (!e_ph) {
    elfconv_runtime_error("failed to allocate program header memory.\n");
  }
  memcpy(e_ph, phdrs->begin(), e_ph_size);
}

void ELFObject::OpenELF() {

  auto buffer = llvm::MemoryBuffer::getFile(file_name, /*IsText=*/false,
                                            /*RequiresNullTerminator=*/false);
  // confirm file_name is opened
  if (!buffer) {
    elfconv_runtime_error("failed to open binary file: %s, ERROR: %s\n", file_name.c_str(),
                          buffer.getError().message().c_str());
  }
  impl->buffer = std::move(*buffer);

  // confirm file_name is an object file
  auto object = llvm::object::ObjectFile::createELFObjectFile(impl->buffer->getMemBufferRef());
  if (!object) {
    auto err = llvm::toString(object.takeError());
    elfconv_runtime_error("file \"%s\" does not look like an executable file. ERROR: %s\n",
                          file_name.c_str(), err.c_str());
  }
  impl->object = std::move(*object);

  // confirm file_name is a 64-bit little-endian ELF binary
  impl->elf = llvm::dyn_cast<ECVELFObjectFile>(impl->object.get());
  if (!impl->elf) {
    elfconv_runtime_error("file \"%s\" is not an ELF binary.\n", file_name.c_str());
  }

  /* get ELF header info */
  GetEhdr();
}

void ELFObject::LoadELF() {
  LoadELFObject();
}

void ELFObject::LoadELFObject() {
  // get binary handler
  OpenELF();

  const auto &elf_file = impl->File();
  const auto &ehdr = elf_file.getHeader();

  // get entry point
  entry = ehdr.e_entry;
  // get binary format
  bin_type = BIN_TYPE_ELF;
  // get architecture
  switch (ehdr.e_machine) {
    case llvm::ELF::EM_AARCH64:
      bin_arch = BinaryArch::ARCH_AARCH64;
      bin_arch_str = "aarch64";
      bin_type_str = "elf64-littleaarch64";
      bits = 64;
      break;
    case llvm::ELF::EM_X86_64:
      bin_arch = BinaryArch::ARCH_AMD64;
      bin_arch_str = "i386:x86-64";
      bin_type_str = "elf64-x86-64";
      bits = 64;
      break;
    default: elfconv_runtime_error("unknown architecture\n"); break;
  }

  // get every section
  LoadSections();

  // functions detection.
  //
  // `symbol_table_size` counts `.symtab` entries excluding the reserved null entry, so zero
  // means there is no static symbol table to read.
  auto sections = elf_file.sections();
  if (!sections) {
    llvm::consumeError(sections.takeError());
    elfconv_runtime_error("failed to read section headers.\n");
  }
  for (const auto &shdr : *sections) {
    if (shdr.sh_type == llvm::ELF::SHT_SYMTAB && shdr.sh_entsize > 0) {
      symbol_table_size = (shdr.sh_size / shdr.sh_entsize) - 1;
      break;
    }
  }

  if (symbol_table_size == 0) {
    // The ELF binary is stripped.
    is_stripped = true;
    // The ELF binary generated from gcc or clang has `eh_frame` section even if it is stripped,
    // and we can detect the function entry and length from the section if the section exists.
    int eh_frame_anal = GetSblFromEhFrame();
#if defined(R2_ANALYSIS)
    R2Detect();
#endif
    if (eh_frame_anal == 0) {
      able_vrp_opt = true;
    } else {
      // If the ELF binary doesn't have the `eh_frame` section or failed to analyze the section,
      // elfconv uses `radare2` reverse engineering framework to detect many functions.
      // However, this method possibly has miss detection, so it is difficult to execute VRP optimization.
      able_vrp_opt = false;
      elfconv_runtime_error(
          "elfconv cannot convert the ELF binary if it is stripped and doesn't have `eh_frame` section because elfconv has some bugs. Please see the issues of the repository.");
    }
  } else {
    // we can detect all functions by watching the symbol table.
    LoadStaticSymbols();
    is_stripped = false;
    able_vrp_opt = true;
  }

  func_symbols.reserve(func_symbols_map.size());
  for (auto &[_, symbol] : func_symbols_map) {
    func_symbols.emplace_back(symbol);
  }
  std::sort(func_symbols.begin(), func_symbols.end(),
            [](auto const &lhs, auto const &rhs) { return lhs.addr < rhs.addr; });
}

const SectionRange *ELFObject::GetIncludedSection(uint64_t vma) {
  for (auto &sec : all_sections) {
    if (sec.vma <= vma && vma < sec.vma + sec.size) {
      return &sec;
    }
  }
  return nullptr;
}

void ELFObject::LoadStaticSymbols() {

  // Read symbol sizes from ELF symbol table
  auto sym_sizes = ReadSymbolSizes(impl->File());

  const auto &elf_file = impl->File();

  auto sections = elf_file.sections();
  if (!sections) {
    llvm::consumeError(sections.takeError());
    elfconv_runtime_error("failed to read symtab.\n");
  }

  for (const auto &shdr : *sections) {
    if (shdr.sh_type != llvm::ELF::SHT_SYMTAB) {
      continue;
    }

    auto symbols = elf_file.symbols(&shdr);
    if (!symbols) {
      llvm::consumeError(symbols.takeError());
      elfconv_runtime_error("failed to read symtab.\n");
    }
    auto str_table = elf_file.getStringTableForSymtab(shdr);
    if (!str_table) {
      llvm::consumeError(str_table.takeError());
      elfconv_runtime_error("failed to read symtab.\n");
    }

    for (const auto &sym : *symbols) {
      auto name_or_err = sym.getName(*str_table);
      if (!name_or_err) {
        llvm::consumeError(name_or_err.takeError());
        continue;
      }
      std::string sym_name = name_or_err->str();

      // STT_FUNC only -- deliberately NOT STT_GNU_IFUNC.
      //
      // Measured against the bfd loader this replaces, on a static-glibc aarch64 binary holding
      // exactly 10 STT_GNU_IFUNC symbols (memcpy, memmove, memset, memchr, strlen and their
      // __libc_/__ aliases): bfd did not raise BSF_FUNCTION for them, so the original filter
      // admitted none. Admitting them shifted every later symbol index by 10 and, because the
      // sort below is by address and std::sort is NOT stable, re-scrambled which name won at the
      // 96 addresses where glibc puts several aliases on one function. The emitted bitcode
      // changed as a result. The `_start` clause caught binaries declaring the entry point
      // STT_NOTYPE; here `_start` is already STT_FUNC, so it is carried for other binaries.
      const auto sym_type = sym.getType();
      if (sym_type == llvm::ELF::STT_FUNC || sym_name == "_start") {
      } else {
        continue;
      }

      // Get symbol size if available
      uint64_t sym_size = 0;
      if (sym_sizes.count(sym_name) > 0) {
        sym_size = sym_sizes[sym_name];
      }
      func_symbols.emplace_back(ELFSymbol::SYM_TYPE_FUNC, sym_name, sym.st_value,
                                GetIncludedSection(sym.st_value), sym_size);
    }
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

void ELFObject::LoadSections() {

  const auto &elf_file = impl->File();

  auto shdrs = elf_file.sections();
  if (!shdrs) {
    llvm::consumeError(shdrs.takeError());
    elfconv_runtime_error("failed to read section headers.\n");
  }

  // `all_sections` must not reallocate after `GetIncludedSection` starts handing out pointers
  // into it, and symbol loading runs after this function returns -- but reserve up front anyway
  // so that the invariant does not depend on when the caller asks.
  all_sections.reserve(shdrs->size());

  for (const auto &shdr : *shdrs) {

    ELFSection::SectionType sec_type;
    uint64_t vma;
    uint64_t size;
    std::string sec_name;
    uint8_t *sec_bytes;

    // bfd's section list has no entry for the reserved null section header.
    if (shdr.sh_type == llvm::ELF::SHT_NULL) {
      continue;
    }

    // map ELF section flags the way bfd did when it set its own section flags
    if (shdr.sh_flags & llvm::ELF::SHF_EXECINSTR) {
      sec_type = ELFSection::SEC_TYPE_CODE;
    } else if (shdr.sh_flags & llvm::ELF::SHF_ALLOC) {
      sec_type = ELFSection::SEC_TYPE_DATA;
    } else if (!(shdr.sh_flags & llvm::ELF::SHF_WRITE)) {
      sec_type = ELFSection::SEC_TYPE_READONLY;
    } else {
      sec_type = ELFSection::SEC_TYPE_UNKNOWN;
    }

    // get vma, section size, section name, section contents
    vma = shdr.sh_addr;
    size = shdr.sh_size;
    auto name_or_err = elf_file.getSectionName(shdr);
    if (name_or_err) {
      sec_name = name_or_err->str();
    } else {
      llvm::consumeError(name_or_err.takeError());
    }
    if (sec_name.empty()) {
      sec_name = std::string("<unnamed>");
    }

    // Every section is a candidate for a containment query, including the ones dropped below.
    all_sections.push_back(SectionRange{sec_name, vma, size});

    // The section starting from 0x0 is unused.
    if (vma == 0x0) {
      continue;
    }

    sec_bytes = reinterpret_cast<uint8_t *>(malloc(size));
    if (!sec_bytes) {
      elfconv_runtime_error("failed to allocate section bytes.\n");
    }
    if (shdr.sh_type == llvm::ELF::SHT_NOBITS) {
      // `.bss` and friends occupy no file space; bfd_get_section_contents zero-filled them.
      memset(sec_bytes, 0, size);
    } else {
      auto contents = elf_file.getSectionContents(shdr);
      if (!contents) {
        llvm::consumeError(contents.takeError());
        elfconv_runtime_error("failed to read and copy section bytes.\n");
      }
      if (contents->size() < size) {
        elfconv_runtime_error("failed to read and copy section bytes.\n");
      }
      memcpy(sec_bytes, contents->data(), size);
    }

    sections.emplace_back(this, sec_type, sec_name, vma, size, sec_bytes);
  }
}

// We can get function entry address and function size (but not necessary for elfconv) by watching the `eh_frame` section.
// In order to parse eh_frame, we use LLVM's own DWARF reader.
int ELFObject::GetSblFromEhFrame() {

  auto dwarf_ctx = llvm::DWARFContext::create(*impl->object);
  if (!dwarf_ctx) {
    LOG(INFO) << "[INFO] failed to create a DWARF context.\n";
    return -1;
  }

  auto eh_frame = dwarf_ctx->getEHFrame();
  if (!eh_frame) {
    llvm::consumeError(eh_frame.takeError());
    LOG(WARNING) << "Error reading frame data.\n";
    return -1;
  }

  if ((*eh_frame)->empty()) {
    LOG(INFO) << "[INFO] No frame data on the ELF.\n";
    return -1;
  }

  // Get every function entry address from the parsed data.
  for (const llvm::dwarf::FrameEntry &entry : (*eh_frame)->entries()) {
    const auto *fde = llvm::dyn_cast<llvm::dwarf::FDE>(&entry);
    if (!fde) {
      continue;
    }

    uint64_t ehf_fun_entry = fde->getInitialLocation();
    std::stringstream ehf_fun_name;
    ehf_fun_name << "_ecv_lifted_fun_0x" << std::hex << ehf_fun_entry;
    func_symbols_map.insert({ehf_fun_entry,
                             {ELFSymbol::SYM_TYPE_FUNC, ehf_fun_name.str(), ehf_fun_entry,
                              GetIncludedSection(ehf_fun_entry)}});
  }

  return 0;
}

// In the current implementation, we use radare2 analysis only for noopt mode.
void ELFObject::R2Detect() {
  printf("[\x1b[33mINFO\x1b[0m] R2 analyzing function boundaries... ");
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
    uint64_t offset, minbound;
    std::stringstream fun_offset_name, fun_minbound_name;

    offset = j_data["offset"].get<uint64_t>();
    minbound = j_data["minbound"].get<uint64_t>();
    fun_offset_name << "__r2fcn_0x" << std::hex << offset << "_noopt";
    auto inc_sec = GetIncludedSection(offset);
    if (inc_sec) {
      func_symbols_map.insert(
          {offset, {ELFSymbol::SymbolType::SYM_TYPE_FUNC, fun_offset_name.str(), offset, inc_sec}});
    } else {
      printf("[WARN] r2 detect strange func entry: 0x%lx\n", offset);
    }

    // There is the case whose offset is not equal to the minbound for the analysis results of radare2.
    // In the case, we make new function of the range of minbound to maxbound.
    if (minbound != offset) {
      auto inc_sec = GetIncludedSection(minbound);
      if (inc_sec) {
        fun_minbound_name << "__r2fcn_minbound_0x" << std::hex << minbound << "_noopt";
        func_symbols_map.insert(
            {minbound,
             {ELFSymbol::SymbolType::SYM_TYPE_FUNC, fun_minbound_name.str(), minbound, inc_sec}});
      } else {
        printf("[WARN] r2 detect strage func entry: 0x%lx\n", minbound);
      }
    }
  }
  printf("finished.\n");
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
  for (auto &symbol : func_symbols) {
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
