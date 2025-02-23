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


def create_udp_socket():
    while True:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            print("[+] Socket created")
            return s

        except socket.error:
            print("[-] Could not connect!")
            sleep(SLEEP_TIME)
            continue


def rsend(s, buf, destination):
    s.sendto(buf, destination)
    print("[+] Packet sent")


def rrecv(s):
    response = s.recvfrom(1024)
    print(f"[+] Message received: {response}")
    return response


def main():

    check_args()

    server  = sys.argv[1]
    port    = int(sys.argv[2])

    size    = 1000
    buf     = b""

    buf += b"\41" * size

    s = create_udp_socket()
    rsend(s, buf, (server, port))
    s.close()


if __name__ == "__main__":
    main()
