import socket
import sys
from time import sleep
from struct import pack

SLEEP_TIME  = 10
CRASH_TIME  = 60


def check_args():
    if len(sys.argv) != 3:
        print(f"[-] Usage: {sys.argv[0]} <ip_address> <port>")
        sys.exit(1)


def rconnect(server, port):
    while True:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.connect((server, port))
            print("[+] Socket connected")
            return s

        except socket.error:
            print("[-] Could not connect!")
            sleep(SLEEP_TIME)
            continue


def rsend(s, buf):
    s.send(buf)
    print("[+] Packet sent")


def rrecv(s):
    response = s.recv(1024)
    print(f"[+] Message received: {response}")
    return response


def main():

    check_args()

    server  = sys.argv[1]
    port    = int(sys.argv[2])

    size    = 1000
    buf     = b""

    s = rconnect(server, port)
    rsend(s, buf)
    s.close()


if __name__ == "__main__":
    main()
