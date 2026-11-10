"""NAT 打洞行为检测：
在 VPS 上监听一个 UDP 端口，收到客户端的包后，从**同一端口**往回打探测包。
- 客户端收到了 -> 端口限制型 NAT，双向同时发包可以打洞
- 客户端没收到 -> 更严格的 NAT（对称型），只能中继
"""
import socket
import sys
import time

port = int(sys.argv[1])
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.bind(("0.0.0.0", port))
sock.settimeout(30)
print(f"listening on udp/{port}", flush=True)

try:
    data, src = sock.recvfrom(2048)
    print(f"got {len(data)} bytes from {src[0]}:{src[1]}", flush=True)
    # 等客户端把 STUN 探测流程走完、节点数据面启动后再回打，
    # 否则回包会被 STUN 客户端收走丢弃
    time.sleep(9)
    pkt = b"TRIRPN01" + b"B" * 32
    for _ in range(5):
        sock.sendto(pkt, src)
        time.sleep(0.2)
    print(f"sent 5 probes back -> {src[0]}:{src[1]}", flush=True)
except socket.timeout:
    print("timeout: no packet from client", flush=True)
