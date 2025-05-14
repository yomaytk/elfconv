import re
import argparse
import os

# Parse log for register entries and brk syscalls

def parse_log(file_path):
    """
    Parse the given log file and extract:
    - entries: list of register snapshots (dicts with keys 'PC', 'X00'...'X30', 'SP', 'PSTATE')
    - brk_nums: list of all brk syscall argument and return values (as integers)
    """
    entries = []
    brk_nums = []
    syscall_pattern = re.compile(r"\bbrk\((0x[0-9A-Fa-f]+)\) = (0x[0-9A-Fa-f]+)")
    with open(file_path) as f:
        block = {}
        for line in f:
            line = line.strip()
            # collect brk syscalls
            msys = syscall_pattern.search(line)
            if msys:
                brk_nums.append(int(msys.group(1), 16))
                brk_nums.append(int(msys.group(2), 16))
            # parse register blocks
            mpc = re.match(r"PC=([0-9A-Fa-f]+)", line)
            if mpc:
                if block:
                    entries.append(block)
                block = {'PC': mpc.group(1)}
                parts = line.split()
                for part in parts[1:]:
                    if '=' in part:
                        k, v = part.split('=', 1)
                        block[k] = v
                continue
            parts = line.split()
            for part in parts:
                if re.match(r"X\d{2}=[0-9A-Fa-f]+", part) or part.startswith('SP=') or part.startswith('PSTATE='):
                    k, v = part.split('=', 1)
                    block[k] = v
        if block:
            entries.append(block)
    return entries, brk_nums


# Generate C source with trace data and brk stats

def generate_c(entries, brk_nums, outc_path):
    """
    Generate C source and header into 'generated/' directory:
    - outc_path: filename for .c (header has same base .h)
    """
    regs = ['PC'] + [f"X{i:02d}" for i in range(31)] + ['SP', 'PSTATE']
    os.makedirs('generated', exist_ok=True)
    base, _ = os.path.splitext(outc_path)
    src_path = os.path.join('generated', outc_path)
    hdr_path = base + '.h'
    hdr_full = os.path.join('generated', hdr_path)

    # Compute brk stats if present
    if brk_nums:
        brk_min = min(brk_nums)
        brk_max = max(brk_nums)

    # Write header file
    with open(hdr_full, 'w') as h:
        guard = os.path.basename(base).upper() + '_H'
        h.write(f'#ifndef {guard}\n')
        h.write(f'#define {guard}\n\n')
        h.write('#include <stdint.h>\n\n')
        h.write('typedef struct {\n')
        h.write('    uint64_t pc;\n')
        h.write('    uint64_t x[31];\n')
        h.write('    uint64_t sp;\n')
        h.write('    uint64_t pstate;\n')
        h.write('} QemuState;\n\n')
        h.write(f'#define TRACE_DATA_COUNT {len(entries)}\n\n')
        h.write(f'#endif /* {guard} */\n')

    # Write source file
    with open(src_path, 'w') as f:
        f.write(f'#include "debugs/generated/{hdr_path}"\n\n')
        if brk_nums:
            f.write('/* brk syscall argument and return value statistics */\n')
            f.write(f'extern "C" const unsigned long BRK_MIN = 0x{brk_min:016x}ULL;\n')
            f.write(f'extern "C" const unsigned long BRK_MAX = 0x{brk_max:016x}ULL;\n\n')
        f.write('extern "C" const QemuState QemuStates[] = {\n')
        for e in entries:
            xs = [e.get(f'X{i:02d}', '0') for i in range(31)]
            sp = e.get('SP', '0')
            ps = e.get('PSTATE', '0')
            pc = e.get('PC', '0')
            values = [pc] + xs + [sp, ps]
            hex_vals = [f'0x{v}ULL' for v in values]
            f.write('    { ' + ', '.join(hex_vals) + ' },\n')
        f.write('};\n')


def main():
    parser = argparse.ArgumentParser(
        description='Parse a QEMU trace log and generate C code with CPU state and brk stats.',
        epilog='Outputs a .c and corresponding .h in the debugs/generated/ directory.'
    )
    parser.add_argument('logfile',
                        help='Path to the QEMU trace log file to parse.')
    parser.add_argument('outc',
                        help='Name for the output C file (e.g., trace.c).')
    parser.add_argument('--version', action='version', version='1.1',
                        help='Show script version and exit.')
    args = parser.parse_args()

    entries, brk_nums = parse_log(args.logfile)
    if not entries:
        print('No trace entries found; exiting.')
        return
    generate_c(entries, brk_nums, args.outc)

if __name__ == '__main__':
    main()
