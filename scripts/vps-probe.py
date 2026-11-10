import socket
import sys

ip = sys.argv[1]
port = int(sys.argv[2])
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
pkt = b"TRIRPN01" + b"A" * 32
for _ in range(5):
    sock.sendto(pkt, (ip, port))
print(f"sent 5 punch probes -> {ip}:{port}")
