#pragma once

#include <cstdint>
#include <string>
#include <cstring>
#include <vector>
#include <bfd.h>
#include <vector>
#include <iostream>
#include <memory>
#include <algorithm>
#include <queue>
#include <map>
#include <list>
#include <libelf.h>
#include <fcntl.h>

namespace BinaryLoader {

	class ELFSymbol;
	class ELFSection;
	class ELFObject;

	class ELFSymbol {
	public:
		enum SymbolType {
			SYM_TYPE_FUNC = 1,
			SYM_TYPE_LVAR = 2,
			SYM_TYPE_GVAR = 3,
			SYM_TYPE_UNKNOWN = 4,
		};

		ELFSymbol(SymbolType __sym_type, std::string __sym_name, uintptr_t __addr)
			: sym_type(__sym_type), sym_name(__sym_name), addr(__addr){}
		ELFSymbol::SymbolType sym_type;
		std::string sym_name;
		uintptr_t addr;
	};

	class ELFSection {
	public:
		enum SectionType {
			SEC_TYPE_CODE = 0,
			SEC_TYPE_DATA = 1,
			SEC_TYPE_READONLY = 2,
			SEC_TYPE_UNKNOWN = 3,
		};

		ELFSection(ELFObject* __elf_obj, ELFSection::SectionType __sec_type, std::string __sec_name, uint64_t __vma, uint64_t __size, uint8_t* __bytes) 
			: elf_obj(__elf_obj), sec_type(__sec_type), sec_name(__sec_name), vma(__vma), size(__size), bytes(__bytes) {}
		~ELFSection(){}

		ELFObject* elf_obj;
		ELFSection::SectionType sec_type;
		std::string sec_name;
		uint64_t vma;
		uint64_t size;
		uint8_t* bytes;
	};
    
	class ELFObject {
	public:
		enum BinaryType : uint8_t {
			BIN_TYPE_ELF = 0,
			BIN_TYPE_UNKNOWN = 1,
		};
		enum BinaryArch : uint8_t {
			ARCH_AARCH64 = 0,
			ARCH_UNKNOWN = 1,
		};
		
		struct FuncEntry {
			uintptr_t entry;
			std::string func_name;
			FuncEntry (uintptr_t __entry, std::string __func_name) : entry(__entry), func_name(__func_name) {}
			bool operator<(const FuncEntry &rhs) { return entry < rhs.entry; }
		};
		struct CodeSection { 
			std::string sec_name;
			uintptr_t vma;
			uint8_t *bytes;
			uint64_t size;
			CodeSection (std::string __sec_name, uintptr_t __vma, uint8_t *__bytes, uint64_t __size) : sec_name(__sec_name), vma(__vma), bytes(__bytes), size(__size) {}
			CodeSection () {}
		};

		void LoadELF();
		void SetCodeSection();
		std::vector<FuncEntry> GetFuncEntry();
		void DebugSections();
		void DebugStaticSymbols();
		void DebugBinary();

		ELFObject(std::string __file_name) : file_name(__file_name), bfd_inited(false) {}
		ELFObject() {}
		
		std::string file_name;
		bool bfd_inited;
		bfd* bfd_h;
		const bfd_arch_info_type* bfd_arch_info; 
		ELFObject::BinaryType bin_type;
		std::string bin_type_str;
		ELFObject::BinaryArch bin_arch;
		std::string bin_arch_str;
		uint32_t bits;
		uintptr_t entry;
		std::vector<ELFSection> sections;
		std::vector<ELFSymbol> symbols;
		std::unordered_map<std::string, CodeSection> code_sections;

		uint64_t e_phent;
		uint64_t e_phnum;
		uint8_t *e_ph;

	private:

		void OpenELF();
		void LoadELFBFD();
		void LoadStaticSymbolsBFD();
		void LoadDynamicSymbolsBFD();
		void LoadSectionsBFD();
		void GetEhdr();

	};
}