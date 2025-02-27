#!/usr/bin/env python3
import re
import sys
import argparse
import subprocess
from typing import List, Dict, Optional

# Registers for gadget hunting
REGISTERS = ["eax", "ebx", "ecx", "edx", "esi", "edi", "ebp", "esp"]

def read_gadgets(file: str) -> List[str]:
    """Read gadgets from rp++ output, skipping header lines."""
    with open(file, "r") as f:
        lines = f.readlines()
        start = next((i for i, line in enumerate(lines) if "A total of " in line), 0) + 1
        return [line.strip() for line in lines[start:]]

def filter_badchars(gadgets: List[str], badchars: str, aslr: Optional[int] = None) -> List[str]:
    """Filter gadgets containing bad bytes in their addresses."""
    bad_bytes = [badchars[i:i+2] for i in range(0, len(badchars), 2)]
    start = aslr or 0
    return [
        gadget for gadget in gadgets
        if not any(gadget.split(":")[0][2 + start:][i:i+2] in bad_bytes 
                  for i in range(0, len(gadget.split(":")[0][2 + start:]), 2))
    ]

def filter_large_retns(gadgets: List[str]) -> List[str]:
    """Remove gadgets with retn offsets > 255 using a simple string check."""
    return [
        gadget for gadget in gadgets
        if "retn" not in gadget or int(gadget.split("retn ")[1].split()[0], 16) <= 255
    ]

def filter_calls_jumps(gadgets: List[str]) -> List[str]:
    """Filter out gadgets containing call or jump instructions."""
    call_jump_ops = [
        "call", "jmp", "je", "jne", "jz", "jnz", "jg", "jge", "jl", "jle",
        "ja", "jae", "jb", "jbe", "jo", "jno", "js", "jns", "jp", "jnp",
        "jc", "jnc", "jecxz", "loop", "loope", "loopne"
    ]
    return [
        gadget for gadget in gadgets
        if not any(op in gadget.split(":", 1)[1].lower() for op in call_jump_ops)
    ]

def write_gadgets(filename: str, gadgets: List[str], header: str, 
                  image_base: str, aslr: Optional[int] = None, dll_name: Optional[str] = None) -> None:
    """Write gadgets to file in ascending length order (shortest first)."""
    start = aslr or 0
    dll_name = dll_name or "dllbase"
    with open(filename, "a") as f:
        f.write(f"==================={header} ({len(gadgets)} found)===================\n")
        for gadget in gadgets:
            gadget = gadget.split(" ;  (1 found)")[0] if " ;  (1 found)" in gadget else gadget
            if start:
                addr = gadget.split(":")[0]
                offset = f"{int(addr, 16) - int(image_base, 16):08x}"
                f.write(f"{dll_name}+0x{offset}:{gadget[start+2:]}\n")
            else:
                f.write(f"{gadget}\n")
        f.write("\n")

def parse_gadget(gadget: str) -> List[str]:
    """Split a gadget into individual instructions."""
    instruction_part = gadget.split(":", 1)[1].split(" ;  (1 found)")[0].strip()
    return [instr.strip() for instr in instruction_part.split(";") if instr.strip()]

def simulate_gadget(gadget: str) -> Dict[str, str]:
    """Simulate stack/register changes and return final register states."""
    instructions = parse_gadget(gadget)
    registers = {reg: reg for reg in REGISTERS}
    stack = []
    
    for instr in instructions:
        parts = instr.split()
        if not parts:
            continue
        op = parts[0]
        
        if op == "push" and len(parts) > 1:
            arg = parts[1]
            stack.append(registers.get(arg, arg))
        elif op == "pop" and len(parts) > 1 and stack:
            arg = parts[1]
            registers[arg] = stack.pop() if stack else "stack_top"
        elif op == "mov" and len(parts) > 2:
            dest, src = parts[1].rstrip(","), parts[2]
            if src in REGISTERS:
                registers[dest] = registers[src]
        elif op == "xor" and len(parts) > 2:
            dest, src = parts[1].rstrip(","), parts[2].rstrip(",")
            if dest == src and dest in REGISTERS:
                registers[dest] = "0"
        elif op == "sub" and len(parts) > 2:
            dest, src = parts[1].rstrip(","), parts[2].rstrip(",")
            if dest == src and dest in REGISTERS:
                registers[dest] = "0"
        elif op == "and" and len(parts) > 2:
            dest, src = parts[1].rstrip(","), parts[2].rstrip(",")
            if src == "0" and dest in REGISTERS:
                registers[dest] = "0"
        elif op in ["add", "adc"] and len(parts) > 2:
            dest, src = parts[1].rstrip(","), parts[2].rstrip(",")
            if dest in REGISTERS and src in REGISTERS:
                registers[dest] = f"{dest}+{src}"
        elif op == "xchg" and len(parts) > 2:
            reg1, reg2 = parts[1].rstrip(","), parts[2].rstrip(",")
            if reg1 in REGISTERS and reg2 in REGISTERS:
                registers[reg1], registers[reg2] = registers[reg2], registers[reg1]
    
    return registers

def build_gadget_db(gadgets: List[str]) -> Dict[str, Dict[str, str]]:
    """Build a dictionary of gadgets and their final register states."""
    gadget_db = {}
    for gadget in gadgets:
        gadget_db[gadget] = simulate_gadget(gadget)
    return gadget_db

def filter_gadgets(gadgets: List[str], pattern: str) -> List[str]:
    """Filter gadgets matching a regex pattern, deduplicating by instruction sequence."""
    compiled_pattern = re.compile(pattern)
    matches = []
    seen_instructions = set()
    for gadget in gadgets:
        if compiled_pattern.match(gadget):
            instr = gadget.split(":", 1)[1].split(" ;  (1 found)")[0].strip()
            if instr not in seen_instructions:
                seen_instructions.add(instr)
                matches.append(gadget)
    return sorted(matches, key=len)

def query_gadgets(gadget_db: Dict[str, Dict[str, str]], condition) -> List[str]:
    """Return gadgets where the condition on final state is true, deduplicating by instruction sequence."""
    matches = []
    seen_instructions = set()
    for gadget, state in gadget_db.items():
        if condition(gadget, state):
            instr = gadget.split(":", 1)[1].split(" ;  (1 found)")[0].strip()
            if instr not in seen_instructions:
                seen_instructions.add(instr)
                matches.append(gadget)
    return sorted(matches, key=len)

def categorize_gadgets(gadgets: List[str]) -> Dict[str, List[str]]:
    """Categorize gadgets using a mix of regex and simulation."""
    gadget_db = build_gadget_db(gadgets)
    
    regex_patterns = {
        "pop": lambda reg: rf'^0x[0-9a-fA-F]{{8}}:\s*pop\s+{reg}\s*;\s*ret',
        "ropnops": r'^0x[0-9a-fA-F]{8}:\s*ret',
        "mem_write": lambda reg: rf'^0x[0-9a-fA-F]{{8}}:\s*mov\s+\[[^]]+\],\s*{reg}\s*;\s*ret',
        "add_val": lambda reg: rf'^0x[0-9a-fA-F]{{8}}:\s*(add|adc)\s+{reg},\s*0x[0-9a-fA-F]+\s*;\s*ret',
    }
    
    simulation_conditions = {
        "stack_pivot": lambda gadget, state: state["esp"] == "stack_top" or any(state["esp"] == r for r in REGISTERS if r != "esp"),
        "move": lambda reg1, reg2: lambda gadget, state: state[reg2] == reg1 and state[reg1] == reg1,
        "null": lambda reg: lambda gadget, state: state[reg] == "0",
        "add_reg": lambda reg1, reg2: lambda gadget, state: state[reg1] == f"{reg1}+{reg2}",
    }
    
    categories = {
        "pop": {},
        "stack_pivot": [],
        "ropnops": [],
        "null": {},
        "mem_write": {},
        "add_val": {},
        "add_reg": {},
        "move": {}
    }
    
    for reg in REGISTERS:
        categories["pop"][reg] = filter_gadgets(gadgets, regex_patterns["pop"](reg))
        categories["mem_write"][reg] = filter_gadgets(gadgets, regex_patterns["mem_write"](reg))
        categories["add_val"][reg] = filter_gadgets(gadgets, regex_patterns["add_val"](reg))
        categories["null"][reg] = query_gadgets(gadget_db, simulation_conditions["null"](reg))
        
        for reg2 in REGISTERS:
            if reg != reg2:
                categories["move"].setdefault(f"{reg} to {reg2}", []).extend(
                    query_gadgets(gadget_db, simulation_conditions["move"](reg, reg2))
                )
                categories["add_reg"].setdefault(f"{reg}+{reg2}", []).extend(
                    query_gadgets(gadget_db, simulation_conditions["add_reg"](reg, reg2))
                )
    
    categories["ropnops"] = filter_gadgets(gadgets, regex_patterns["ropnops"])
    categories["stack_pivot"] = query_gadgets(gadget_db, simulation_conditions["stack_pivot"])
    
    return categories

def process_q1(filename: str, gadgets: List[str], image_base: str, 
               aslr: Optional[int], dll_name: Optional[str], max_gadgets: int) -> List[str]:
    """Process and categorize high-quality gadgets, writing them to a file with pure gadget preference."""
    categories = categorize_gadgets(gadgets)
    
    remaining = gadgets.copy()
    
    with open(filename, "a") as f:
        f.write("======================CRITICAL OSED GADGETS======================\n")
    
    # Regex patterns for pure gadgets
    pure_patterns = {
        "pop": lambda reg: re.compile(rf'0x[0-9a-fA-F]{{8}}:\s*pop\s+{reg}\s*;\s*ret'),
        "ropnops": re.compile(r'0x[0-9a-fA-F]{8}:\s*ret'),
        "null_xor": lambda reg: re.compile(rf'0x[0-9a-fA-F]{{8}}:\s*xor\s+{reg},\s*{reg}\s*;\s*ret'),
        "null_sub": lambda reg: re.compile(rf'0x[0-9a-fA-F]{{8}}:\s*sub\s+{reg},\s*{reg}\s*;\s*ret'),
        "null_and": lambda reg: re.compile(rf'0x[0-9a-fA-F]{{8}}:\s*and\s+{reg},\s*0\s*;\s*ret'),
        "add_reg": lambda reg1, reg2: re.compile(rf'0x[0-9a-fA-F]{{8}}:\s*(add|adc)\s+{reg1},\s*{reg2}\s*;\s*ret'),
        "move_mov": lambda reg1, reg2: re.compile(rf'0x[0-9a-fA-F]{{8}}:\s*mov\s+{reg2},\s*{reg1}\s*;\s*ret'),
        "move_push_pop": lambda reg1, reg2: re.compile(rf'0x[0-9a-fA-F]{{8}}:\s*push\s+{reg1}\s*;\s*pop\s+{reg2}\s*;\s*ret'),
        "move_xchg": lambda reg1, reg2: re.compile(rf'0x[0-9a-fA-F]{{8}}:\s*xchg\s+{reg1},\s*{reg2}\s*;\s*ret'),
        "mem_write": lambda reg: re.compile(rf'0x[0-9a-fA-F]{{8}}:\s*mov\s+\[[^]]+\],\s*{reg}\s*;\s*ret'),
    }
    
    for category in ["pop", "stack_pivot", "ropnops", "null", "mem_write", "add_val", "add_reg", "move"]:
        if category in ["pop", "null", "mem_write", "add_val", "add_reg"]:
            if category == "add_reg":
                for add_key, add_gadgets in categories[category].items():
                    reg1, reg2 = add_key.split("+")
                    pure_gadget = next((g for g in add_gadgets if pure_patterns["add_reg"](reg1, reg2).match(g)), None)
                    if pure_gadget:
                        gadgets_to_write = [pure_gadget]
                    else:
                        gadgets_to_write = add_gadgets[:max_gadgets]
                    write_gadgets(filename, gadgets_to_write, f"{category} {add_key}", image_base, aslr, dll_name)
                    remaining = [g for g in remaining if g not in gadgets_to_write]
            elif category == "null":
                for reg in REGISTERS:
                    gadget_list = categories[category][reg]
                    pure_gadgets = []
                    for pattern_key in ["null_xor", "null_sub", "null_and"]:
                        pure_gadget = next((g for g in gadget_list if pure_patterns[pattern_key](reg).match(g)), None)
                        if pure_gadget:
                            pure_gadgets.append(pure_gadget)
                    if pure_gadgets:
                        gadgets_to_write = pure_gadgets
                    else:
                        gadgets_to_write = gadget_list[:max_gadgets]
                    write_gadgets(filename, gadgets_to_write, f"{category} {reg}", image_base, aslr, dll_name)
                    remaining = [g for g in remaining if g not in gadgets_to_write]
            else:  # pop, mem_write, add_val
                for reg in REGISTERS:
                    gadget_list = categories[category][reg]
                    if category in pure_patterns:
                        pure_gadget = next((g for g in gadget_list if pure_patterns[category](reg).match(g)), None)
                        if pure_gadget:
                            gadgets_to_write = [pure_gadget]
                        else:
                            gadgets_to_write = gadget_list[:max_gadgets]
                    else:
                        gadgets_to_write = gadget_list[:max_gadgets] 
                    write_gadgets(filename, gadgets_to_write, f"{category} {reg}", image_base, aslr, dll_name)
                    remaining = [g for g in remaining if g not in gadgets_to_write]
        elif category == "move":
            for move_key, move_gadgets in categories[category].items():
                reg1, reg2 = move_key.split(" to ")
                pure_gadgets = []
                for pattern_key in ["move_mov", "move_push_pop", "move_xchg"]:
                    pure_gadget = next((g for g in move_gadgets if pure_patterns[pattern_key](reg1, reg2).match(g)), None)
                    if pure_gadget:
                        pure_gadgets.append(pure_gadget)
                if pure_gadgets:
                    gadgets_to_write = pure_gadgets
                else:
                    gadgets_to_write = move_gadgets[:max_gadgets]
                write_gadgets(filename, gadgets_to_write, f"{category} {move_key}", image_base, aslr, dll_name)
                remaining = [g for g in remaining if g not in gadgets_to_write]
        else:  # stack_pivot, ropnops
            gadget_list = categories[category]
            if category == "ropnops":
                pure_gadget = next((g for g in gadget_list if pure_patterns[category].match(g)), None)
                if pure_gadget:
                    gadgets_to_write = [pure_gadget]
                else:
                    gadgets_to_write = gadget_list[:max_gadgets]
            else:  # stack_pivot
                gadgets_to_write = gadget_list[:max_gadgets]  # No pure preference for stack_pivot
            write_gadgets(filename, gadgets_to_write, category, image_base, aslr, dll_name)
            remaining = [g for g in remaining if g not in gadgets_to_write]
    
    return remaining

def main():
    """Main function to parse arguments and process gadgets."""
    parser = argparse.ArgumentParser(description="Filter rp++ output for gadgets")
    parser.add_argument("rop_output", type=str, help="rp++ output file to ingest")
    parser.add_argument("-b", "--bad-bytes", type=str, help="Bad bytes formatted as \"\\x00\\x0a\" or \"000a\"")
    parser.add_argument("-d", "--dll-name", type=str, help="DLL name for output formatting")
    parser.add_argument("-a", "--aslr", type=int, help="Hex characters to disregard for ASLR")
    parser.add_argument("-i", "--image-base", type=str, help="DLL image base for offset calculation")
    parser.add_argument("-m", "--max-gadgets", type=int, default=10, help="Maximum number of gadgets per category")

    args = parser.parse_args()
    if args.aslr and not args.image_base:
        sys.exit("[-] --image-base required with --aslr")

    subprocess.run(["dos2unix", args.rop_output], stdout=subprocess.PIPE)

    base = args.rop_output.rstrip(".txt")
    files = {"full": f"{base}-full.txt", "q1": f"{base}-high.txt"}
    for f in files.values():
        open(f, "w").close()

    gadgets = read_gadgets(args.rop_output)
    if args.bad_bytes:
        original_count = len(gadgets)
        gadgets = filter_badchars(gadgets, args.bad_bytes.replace("\\x", ""), args.aslr)
        filtered_count = len(gadgets)
        if filtered_count < 0.1 * original_count:
            print(f"[!] Warning: {filtered_count}/{original_count} gadgets remain after filtering")

    gadgets = filter_large_retns(gadgets)
    gadgets = filter_calls_jumps(gadgets)
    write_gadgets(files["full"], gadgets, "filtered gadgets", args.image_base, args.aslr, args.dll_name)
    print(f"[+] {len(gadgets)} gadgets written to {files['full']}")

    gadgets = process_q1(files["q1"], gadgets, args.image_base, args.aslr, args.dll_name, args.max_gadgets)
    print(f"[+] {len(gadgets)} high-quality gadgets written to {files['q1']}")

if __name__ == "__main__":
    main()
