#!/usr/bin/env python3
import re
import sys
import argparse
import subprocess
from functools import partial
from typing import List, Optional

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
    """Remove gadgets with retn offsets > 255."""
    pattern = re.compile(r'^0x[0-9a-fA-F]{8}:.* retn 0x[0-9a-fA-F]{4}')
    return [
        gadget for gadget in gadgets
        if not (pattern.match(gadget) and int(gadget.split("retn ")[1].split(" ;")[0], 16) > 255)
    ]


def write_gadgets(filename: str, gadgets: List[str], header: str, 
                  image_base: str, aslr: Optional[int] = None, dll_name: Optional[str] = None) -> None:
    """Write gadgets to file with offset adjustments if ASLR is used."""
    start       = aslr or 0
    dll_name    = dll_name or "dllbase"
    with open(filename, "a") as f:
        f.write(f"==================={header} ({len(gadgets)} found)===================\n")
        for gadget in gadgets:
            gadget = gadget.split(" ;  (1 found)")[0] if " ;  (1 found)" in gadget else gadget
            if start:
                addr    = gadget.split(":")[0]
                offset  = f"{int(addr, 16) - int(image_base, 16):08x}"
                f.write(f"{dll_name}+0x{offset}:{gadget[start+2:]}\n")
            else:
                f.write(f"{gadget}\n")
        f.write("\n")


def filter_gadgets(gadgets: List[str], pattern: str) -> List[str]:
    """Generic filter for gadgets matching a regex pattern, sorted by length."""
    return sorted(filter(re.compile(pattern).match, gadgets), key=len)


def q1_gadget_patterns(reg: str) -> dict:
    return {
        "stack_pivot": [
            rf"^0x[0-9a-fA-F]{{8}}: pop esp ; ret",
            rf"^0x[0-9a-fA-F]{{8}}: mov esp, {reg} ; ret"
        ],
        "pop": rf"^0x[0-9a-fA-F]{{8}}: pop {reg} ; ret",
        "mov_esp": [
            rf"^0x[0-9a-fA-F]{{8}}: mov {reg}, esp ; ret",
            rf"^0x[0-9a-fA-F]{{8}}:\s*push\s+esp\s*;((?:(?!push\s+[a-zA-Z]{{3}})[^;])*;)?\s*pop\s+{reg}\s*;.*ret"
            # rf"^0x[0-9a-fA-F]{{8}}:.*push esp.*pop {reg}.*ret"
        ],
        "mem_write": [
            rf"^0x[0-9a-fA-F]{{8}}: mov (dword|word|byte) \[{reg}(?:\+0x0[48C])?\], [a-zA-Z]{{3}} ; ret"
        ],
        "pushpop": rf"^0x[0-9a-fA-F]{{8}}:.*push {reg}.*pop [a-zA-Z]{{3}}.*ret",
        "null": [
            rf"^0x[0-9a-fA-F]{{8}}: (xor|sub|sbb) {reg}, {reg} ; ret",
            rf"^0x[0-9a-fA-F]{{8}}: (and|mov|mul) {reg}, 0x00000000 ; ret"
        ],
        "mov_to": [
            rf"^0x[0-9a-fA-F]{{8}}: mov {reg}, [a-zA-Z]{{3}} ; ret",
            rf"^0x[0-9a-fA-F]{{8}}: push [a-zA-Z]{{3}} ; pop {reg} ; ret"
        ],
        "mov_from": [
            rf"^0x[0-9a-fA-F]{{8}}: mov [a-zA-Z]{{3}}, {reg} ; ret",
            rf"^0x[0-9a-fA-F]{{8}}: push {reg} ; pop [a-zA-Z]{{3}} ; ret"
        ],
        "add_reg": rf"^0x[0-9a-fA-F]{{8}}: (add|adc) {reg}, [a-zA-Z]{{3}} ; ret",
        "add_val": rf"^0x[0-9a-fA-F]{{8}}: (add|adc) {reg}, 0xFFFFFF[0-9A-F]{{2}} ; ret",
        "sub_reg": rf"^0x[0-9a-fA-F]{{8}}: (sub|sbc) {reg}, [a-zA-Z]{{3}} ; ret",
        "sub_val": rf"^0x[0-9a-fA-F]{{8}}: (sub|sbc) {reg}, 0xFFFFFF[0-9A-F]{{2}} ; ret",
        "inc": rf"^0x[0-9a-fA-F]{{8}}: inc {reg} ; ret",
        "dec": rf"^0x[0-9a-fA-F]{{8}}: dec {reg} ; ret",
        "or_to": rf"^0x[0-9a-fA-F]{{8}}: or {reg}, [a-zA-Z]{{3}} ; ret",
        "or_from": rf"^0x[0-9a-fA-F]{{8}}: or [a-zA-Z]{{3}}, {reg} ; ret",
        "and_to": rf"^0x[0-9a-fA-F]{{8}}: and {reg}, [a-zA-Z]{{3}} ; ret",
        "and_from": rf"^0x[0-9a-fA-F]{{8}}: and [a-zA-Z]{{3}}, {reg} ; ret",
        "mem_read": rf"^0x[0-9a-fA-F]{{8}}: mov [a-zA-Z]{{3}}, dword \[{reg}(?:\+0x0[48C])?\] ; ret",
        "neg": rf"^0x[0-9a-fA-F]{{8}}: neg {reg}.*; ret",
        "shr": rf"^0x[0-9a-fA-F]{{8}}: (shr|sar) {reg}, .*; ret",
        "multi": (
            r"0x[0-9a-fA-F]{8}:.*(?:push|pop)\s+(?:eax|ebx|ecx|edx|esi|edi|ebp|esp)\s*;"
            r"(?:.*(?:push|pop)\s+(?:eax|ebx|ecx|edx|esi|edi|ebp|esp)\s*;)+.*ret"
        ),"xchg": [
            rf"^0x[0-9a-fA-F]{{8}}: xchg {reg}, [a-zA-Z]{{3}} ; ret",
            rf"^0x[0-9a-fA-F]{{8}}: xchg [a-zA-Z]{{3}}, {reg} ; ret"
        ]
    }


def extract_gadgets(gadgets: List[str], patterns, reg: str, limit: int = 5) -> List[str]:
    """Extract unique gadgets for a register using one or more patterns."""
    result = []
    seen_instructions = set()  
    pattern_list = patterns if isinstance(patterns, list) else [patterns]
    
    for pattern in pattern_list:
        matches = filter_gadgets(gadgets, pattern)
        for gadget in matches:
            instruction = gadget.split(":", 1)[1].split(" ;  (1 found)")[0].strip()
            if instruction not in seen_instructions:
                seen_instructions.add(instruction)
                result.append(gadget)
            if len(result) >= limit:
                break
        if len(result) >= limit:
            break
    
    return sorted(result, key=len)[:limit]  

def process_q1(filename: str, gadgets: List[str], image_base: str, 
               aslr: Optional[int], dll_name: Optional[str]) -> List[str]:
    """Extract high-quality gadgets, grouped by instruction type then register."""
    remaining = gadgets.copy()
    
    # Special case: multi-instruction gadgets (moved up)
    multi_pattern = r"^0x[0-9a-fA-F]{8}:\s*((push|pop)\s+[a-zA-Z]{3}\s*[^;]*;.*){2,}\s*ret"  # Adjusted
    multi_gadgets = extract_gadgets(remaining, multi_pattern, "", limit=15)
    if not multi_gadgets:
        print("[!] No multi-instruction gadgets found in initial list.")
        push_pop_count = sum(1 for g in remaining if re.search(r"(push|pop).*(push|pop).*ret", g))
        print(f"[!] {push_pop_count} gadgets with at least two push/pop in initial list")
        print("[!] First 5 gadgets with push/pop:")
        for g in [x for x in remaining if re.search(r"(push|pop)", x)][:5]:
            print(f"  {g}")
    write_gadgets(filename, multi_gadgets, "multi", image_base, aslr, dll_name)
    remaining = [g for g in remaining if g not in multi_gadgets]

    # Critical gadgets first
    critical_patterns = {
        "stack_pivot": lambda r: q1_gadget_patterns(r)["stack_pivot"],
        "pop": lambda r: q1_gadget_patterns(r)["pop"],
        "mov_esp": lambda r: q1_gadget_patterns(r)["mov_esp"]
    }
    with open(filename, "a") as f:
        f.write("======================CRITICAL OSED GADGETS======================\n")
    for instr_type, pattern_func in critical_patterns.items():
        for reg in REGISTERS:
            if reg == "esp" and instr_type == "mov_esp":
                continue
            found       = extract_gadgets(remaining, pattern_func(reg), reg)
            write_gadgets(filename, found[:5], f"{instr_type} {reg}", image_base, aslr, dll_name)
            remaining   = [g for g in remaining if g not in found]

    # Special case: ropnops (ret gadgets), not register-specific
    ropnops     = extract_gadgets(remaining, r"^0x[0-9a-fA-F]{8}: ret", "", limit=5)  
    write_gadgets(filename, ropnops, "ropnops", image_base, aslr, dll_name)
    remaining   = [g for g in remaining if g not in ropnops]
    
    patterns_by_type = {
        "null": lambda r: q1_gadget_patterns(r)["null"],
        "mov_to": lambda r: q1_gadget_patterns(r)["mov_to"],
        "mov_from": lambda r: q1_gadget_patterns(r)["mov_from"],
        "mem_write": lambda r: q1_gadget_patterns(r)["mem_write"],
        "mem_read": lambda r: q1_gadget_patterns(r)["mem_read"],
        "pushpop": lambda r: q1_gadget_patterns(r)["pushpop"],
        "xchg": lambda r: q1_gadget_patterns(r)["xchg"],
        "inc": lambda r: q1_gadget_patterns(r)["inc"],
        "dec": lambda r: q1_gadget_patterns(r)["dec"],
        "neg": lambda r: q1_gadget_patterns(r)["neg"],
        "add_val": lambda r: q1_gadget_patterns(r)["add_val"],
        "sub_val": lambda r: q1_gadget_patterns(r)["sub_val"],
    }

    # Group by instruction type
    for instr_type, pattern_func in patterns_by_type.items():
        for reg in REGISTERS:
            found = extract_gadgets(remaining, pattern_func(reg), reg, limit=15 if instr_type == "multi" else 10)
            write_gadgets(filename, found[:5], f"{instr_type} {reg}", image_base, aslr, dll_name)
            remaining = [g for g in remaining if g not in found]

    return remaining


def main():
    parser = argparse.ArgumentParser(description="Filter rp++ output for gadgets")
    parser.add_argument("rop_output", type=str, help="rp++ output file to ingest")
    parser.add_argument("-b", "--bad-bytes", type=str, help="Bad bytes formatted as \"\\x00\\x0a\" or \"000a\"")
    parser.add_argument("-d", "--dll-name", type=str, help="DLL name for output formatting")
    parser.add_argument("-a", "--aslr", type=int, help="Hex characters to disregard for ASLR")
    parser.add_argument("-i", "--image-base", type=str, help="DLL image base for offset calculation")

    args = parser.parse_args()
    if args.aslr and not args.image_base:
        sys.exit("[-] --image-base required with --aslr")

    # Ensure Unix line endings
    _ = subprocess.run(["dos2unix", args.rop_output], stdout=subprocess.PIPE)

    # Output files
    base    = args.rop_output.rstrip(".txt")
    files   = {
        "full": f"{base}-full.txt",
        "q1": f"{base}-high.txt",
    }
    for f in files.values():
        open(f, "w").close()  # Clear files

    # Process gadgets
    gadgets = read_gadgets(args.rop_output)
    if args.bad_bytes:
        original_count  = len(gadgets)
        gadgets         = filter_badchars(gadgets, args.bad_bytes.replace("\\x", ""), args.aslr)
        filtered_count  = len(gadgets)
        if filtered_count < 0.1 * original_count:
            print(f"[!] Warning: {filtered_count}/{original_count} gadgets remain after filtering for badchars") 

    gadgets = filter_large_retns(gadgets)
    write_gadgets(files["full"], gadgets, "filtered gadgets", args.image_base, args.aslr, args.dll_name)
    print(f"[+] {len(gadgets)} gadgets written to {files['full']}")

    gadgets = process_q1(files["q1"], gadgets, args.image_base, args.aslr, args.dll_name)
    print(f"[+] {len(gadgets)} high-quality gadgets written to {files['q1']}")

if __name__ == "__main__":
    main()
