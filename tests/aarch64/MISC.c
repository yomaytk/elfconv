
// PRFM  (<prfop>|#<imm5>), [<Xn|SP>{, #<pimm>}]
void prfm_pldl1keep(uint64_t *mem_ptr) {
  asm __volatile__("PRFM PLDL1KEEP, [%0, #8]" ::"r"(mem_ptr) : "memory");
}
