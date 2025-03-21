#!/usr/bin/python

import numpy
import sys


def ror_str(byte, count):
    binb = numpy.base_repr(byte, 2).zfill(32)
    while count > 0:
        binb = binb[-1] + binb[0:-1]
        count -= 1
    return int(binb, 2)


def long_hash(esi, key):
    edx = 0x00
    ror_count = 0
    for eax in esi:
        edx = edx + ord(eax)
        if ror_count < len(esi) - 1:
            edx = ror_str(edx, key)
        ror_count += 1
    
    return edx


def short_hash(esi, key):
    dl = 0
    for char in esi:
        al = ord(char)
        al ^= key
        al &= 0xff
        dl -= al
        dl &= 0xff
    
    # null byte
    dl -= key
    dl &= 0xff
    return dl
    

def main():
    esi = sys.argv[1]

    long_key = 0xd
    kernel32_key    = 0xf8
    ws2_32_key      = 0xc0
    short_key       = 0x71

    print("+-------+------------+")
    print("| Key   | Hash Value |")
    print("+-------+------------+")
    print(f"| {hex(long_key)}   | {hex(long_hash(esi, long_key)):>10} |")
    print(f"| {hex(kernel32_key)}  | {hex(short_hash(esi, kernel32_key)):>10} |")
    print(f"| {hex(ws2_32_key)}  | {hex(short_hash(esi, ws2_32_key)):>10} |")
    print(f"| {hex(short_key)}  | {hex(short_hash(esi, short_key)):>10} |")
    print("+-------+------------+")

if __name__ == "__main__":
    main()

