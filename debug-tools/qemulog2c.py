import sys
import re
import argparse

def parse_log(file_path):
    entries = []
    with open(file_path) as f:
        block = {}
        for line in f:
            line = line.strip()
            if not line:
                continue
            # Start of a new block when PC= appears
            m = re.match(r"PC=([0-9A-Fa-f]+)", line)
            if m:
                if block:
                    entries.append(block)
                    block = {}
                block['PC'] = m.group(1)
                parts = line.split()
                for part in parts[1:]:
                    if '=' in part:
                        k, v = part.split('=', 1)
                        block[k] = v
                continue
            # Other lines containing register assignments
            parts = line.split()
            for part in parts:
                if re.match(r"X\d{2}=[0-9A-Fa-f]+", part) or part.startswith('SP=') or part.startswith('PSTATE='):
                    k, v = part.split('=', 1)
                    block[k] = v
        if block:
            entries.append(block)
    return entries

def generate_c(entries, out_path, only_pc=False):
    with open(out_path, 'w') as f:
        f.write('#include <stdint.h>\n\n')
        if only_pc:
            f.write('static const uint64_t QemuPCs[] = {\n')
            for e in entries:
                pc_val = e.get('PC', '0')
                f.write(f'    0x{pc_val}ULL,\n')
            f.write('};\n')
        else:
            regs = ['PC'] + [f"X{i:02d}" for i in range(31)] + ['SP', 'PSTATE']
            # struct definition
            f.write('typedef struct {\n')
            for r in regs:
                f.write(f'    uint64_t {r.lower()};\n')
            f.write('} trace_entry_t;\n\n')
            # data array
            f.write('static const trace_entry_t trace_data[] = {\n')
            for e in entries:
                vals = [e.get(r, '0') for r in regs]
                hex_vals = [f"0x{v}ULL" for v in vals]
                f.write('    { ' + ', '.join(hex_vals) + ' },\n')
            f.write('};\n')

def main():
    parser = argparse.ArgumentParser(
        description='Convert log file to C source with trace entries.'
    )
    parser.add_argument('logfile', help='Input log file path')
    parser.add_argument('outc', help='Output C file path')
    parser.add_argument('--only-pc', action='store_true',
                        help='Generate array of PCs only')
    args = parser.parse_args()

    entries = parse_log(args.logfile)
    generate_c(entries, args.outc, only_pc=args.only_pc)

if __name__ == '__main__':
    main()
