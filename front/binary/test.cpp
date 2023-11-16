#include "loader.h"

int main(int argc, char **argv) {

    BinaryLoader::ELFObject elf_obj;
    
    if (argc < 2) {
        printf("argument is lacking.\n");
        exit(EXIT_FAILURE);
    }

    elf_obj = BinaryLoader::ELFObject(std::string(argv[1]));
    elf_obj.LoadELF();

    elf_obj.DebugBinary();

    return 0;
}