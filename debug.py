import sys

file_a = ''
file_b = ''

ignore_regs = {}
from_fun_name = ''

def extract_states(log_file):
    """Extracts states from the log file, ignoring lines starting with 'pc'."""
    states = []
    current_state = {}

    with open(log_file, 'r') as file:
        l_num = 1
        for line in file:
            if line.startswith("tpidr_el0:"):
                if current_state:
                    reg_val_pairs = [ pair.split(":") for pair in line.split(',') ]
                    current_state['registers'].update({key.strip(): value.strip() for key, value in reg_val_pairs})
                    states.append(current_state)
                    current_state = {}
                else:
                    raise RuntimeError("current state should be valid.")
            elif line.startswith("x") or line.startswith("sp"):
                reg_val_pairs = [ pair.split(":") for pair in line.split(',') ]
                if 'registers' in current_state:
                    current_state['registers'].update({key.strip(): value.strip() for key, value in reg_val_pairs})
                else:
                    current_state['registers'] = {key.strip(): value.strip() for key, value in reg_val_pairs}
            else:
                if "____" in line or "fn_plt" in line or "__wrap_main" in line:
                    assert current_state == {}
                    current_state['function'] = line.strip()
                    current_state['line'] = l_num
            l_num += 1
    return states

def extract_call_funcs(log_file):
    """Extracts the all called functions"""
    states = []

    with open(log_file, 'r') as file:
        l_num = 1
        for line in file:
            current_state = {}
            current_state['function'] = line.strip()
            current_state['line'] = l_num
            states.append(current_state)
            l_num += 1
    return states

def compare_states(states_a, states_b):
    """Compares states from two lists and prints differences."""
    min_len = min(len(states_a), len(states_b))
    threshold = 10
    debug_num = 0
    check = len(from_fun_name) == 0
    for i in range(min_len):
        state_a = states_a[i]
        state_b = states_b[i]
        out_str = ""
        different = False
        check |= state_a['function'] == from_fun_name
        if not check:
            continue
        if state_a['registers'] != state_b['registers']:
            out_str += f"Differences found in State {i + 1}:\n"
            out_str += f"{file_a}'s {state_a['function']} (line: {state_a['line']}) vs {file_b}'s {state_b['function']} (line: {state_b['line']})\n"
            for reg, l_val in state_a['registers'].items():
                if not (ignore_regs.__contains__(reg) and ignore_regs[reg] == l_val) and state_b['registers'][reg] != l_val:
                    different = True
                    out_str += f"Register {reg}: {l_val} vs {state_b['registers'].get(reg, 'N/A')}\n"
            out_str += "-" * 50 + "\n"
            if different:
                print(out_str)
                debug_num += 1
            if debug_num > threshold:
                print("...")
                return

def compare_call_funcs(states_a, states_b):
    """Compares the called functions order."""
    min_len = min(len(states_a), len(states_b))
    for i in range(min_len):
        state_a = states_a[i]
        state_b = states_b[i]
        if state_a['function'] != state_b['function']:
            print(f"Called functions is invalid. {file_a}: {state_a['function']} (line: {state_a['line']}), {file_b}: {state_b['function']} (line: {state_b['line']}).")
            return False
    if len(states_a) != len(states_b):
        print(f"len(state_{file_a}) != len(state_{file_b}).")
        return False
    return True
        
def main():
    
    if len(sys.argv) < 4:
        print("Usage: python3 app.py path/to/FA.log path/to/FB.log")
        sys.exit(1)

    mode = sys.argv[1]

    global file_a, file_b
    file_a = sys.argv[2]
    file_b = sys.argv[3]

    if mode == "--call-stack":
        call_funcs_fa = extract_call_funcs(file_a)
        call_funcs_fb = extract_call_funcs(file_b)
        res = compare_call_funcs(call_funcs_fa, call_funcs_fb)
        if res:
            print('[INFO] call stack is equal.')
    elif mode == "--all-regs":
        global ignore_regs
        index = 4
        if len(sys.argv) > 4:
            if sys.argv[index] == "--ignore":
                while True:
                    ignore_regs[sys.argv[index]] = sys.argv[index + 1]
                    index += 2
                    if len(sys.argv) <= index or not sys.argv[index].startswith("0x"):
                        break
            if sys.argv[index] == "--from-fun":
                global from_fun_name
                from_fun_name = sys.argv[index + 1]
                index += 2
            if len(sys.argv) != index:
                raise RuntimeError('invalid options.')
        # Extract states from both files
        states_fa = extract_states(file_a)
        states_fb = extract_states(file_b)
        
        called_func_order = compare_call_funcs(states_fa, states_fb)
        
        if called_func_order:
          print("[INFO] Called funcs order is correct!")
          compare_states(states_fa, states_fb)
    else:
        raise RuntimeError(f'invalid mode {mode}.')
        


if __name__ == "__main__":
    main()