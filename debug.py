import sys

file_a = ''
file_b = ''

def extract_states(log_file):
    """Extracts states from the log file, ignoring lines starting with 'pc'."""
    states = []
    current_state = {}
    keywords = ["Hello, World"]

    with open(log_file, 'r') as file:
        l_num = 0
        for line in file:
            l_num += 1
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
    return states

def compare_states(states_a, states_b):
    """Compares states from two lists and prints differences."""
    min_len = min(len(states_a), len(states_b))
    threshold = 5
    debug_num = 0
    for i in range(min_len):
        state_a = states_a[i]
        state_b = states_b[i]
        if state_a['registers'] != state_b['registers']:
            debug_num += 1
            print(f"Differences found in State {i + 1}:")
            print(f"{file_a}'s {state_a['function']} (line: {state_a['line']}) vs {file_b}'s {state_b['function']} (line: {state_b['line']})")
            for reg, value in state_a['registers'].items():
                if state_b['registers'][reg] != value:
                    print(f"Register {reg}: {value} vs {state_b['registers'].get(reg, 'N/A')}")
            print("-" * 50)
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
    if len(sys.argv) != 3:
        print("Usage: python app.py FA.log FB.log")
        sys.exit(1)

    global file_a, file_b
    file_a = sys.argv[1]
    file_b = sys.argv[2]
    
    # Extract states from both files
    states_fa = extract_states(file_a)
    states_fb = extract_states(file_b)
    
    called_func_order = compare_call_funcs(states_fa, states_fb)
    
    if called_func_order:
       print("[INFO] Called funcs order is correct!")
       compare_states(states_fa, states_fb)

if __name__ == "__main__":
    main()