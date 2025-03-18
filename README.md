# VRED Scripts
## About
This is a collection of scripts useful for anyone working in Vulnerability Research and Exploit Development (VRED).

## Egghunter.py
### Info
Generates shellcode that dynamically locates and jumps to a unique ASCII string (default w00tw00t). Can specify bad bytes to avoid.
### Usage
```
egghunter.py
```

## ROP_finder.py
### Info
Searches through a ROP++ output file and selects the most useful and pure gadgets. It filters out gadgets that contain bad bytes or opcodes that change the control flow (eg jmp/call). This script uses a combination of regex and stack simulation to classify gadgets and select the shortes and most elegant ones useful for common DEP bypasses.
### Usage
```
rop_finder.py rop.txt
```

## Hash.py
### Info
Generates a hash for the input string that is used by custom_shellcode.py to dynamically locate a library.
### Usage
```
hash.py wsa2_32.dll
```

## TCP_template.py
### Info
Template for making a TCP connection to a socket and sending a buffer.

## UDP_template.py
### Info
Template for making a UDP socket and sending a buffer.

## HTTP_POST_template.py
### Info
Template for sending an HTTP POST request.
