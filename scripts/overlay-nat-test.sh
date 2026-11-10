#!/bin/bash
# 真实 NAT 环境验证：两个客户端各自在**不同的** NAT 后面，服务端在公网侧。
#
# 拓扑：
#   [cA 10.202.0.2] -- vA -- [natA 10.202.0.1 | 10.201.0.2] -- vRA --\
#                                                                     [root/server 10.201.0.1 / 10.201.1.1]
#   [cB 10.203.0.2] -- vB -- [natB 10.203.0.1 | 10.201.1.2] -- vRB --/
#
# 用法： bash overlay-nat-test.sh [true|false]   （true=允许直连，false=强制中继）
set -e

DIRECT="${1:-true}"
BIN=/root/trairi
DIR=/root/nattest
mkdir -p "$DIR"

cleanup() {
  pkill -f "$BIN" 2>/dev/null || true
  for n in natA natB cA cB; do ip netns del "$n" 2>/dev/null || true; done
  ip link del vRA 2>/dev/null || true
  ip link del vRB 2>/dev/null || true
}
trap cleanup EXIT
cleanup
sleep 1

echo "=== 模式 direct=$DIRECT ==="

cat > "$DIR/server.yaml" <<'EOF'
mode: server
log:
  level: info
server:
  bind_addr: 0.0.0.0
  bind_port: 28000
  token: nat-token
overlay:
  enable: true
  network_name: natnet
  network_secret: nat-secret-456
  ipv4_pool: 10.144.144.0/24
  udp_port: 28013
  relay_listen: 0.0.0.0:28012
EOF

mk_client() {
  local file="$1" ip="$2" iface="$3"
  cat > "$file" <<EOF
mode: client
log:
  level: debug
client:
  server_addr: $4
  server_port: 28000
  token: nat-token
overlay:
  enable: true
  network_name: natnet
  network_secret: nat-secret-456
  ipv4: $ip
  udp_port: 0
  interface: $iface
  direct: $DIRECT
EOF
}
# 客户端都通过各自的 NAT 公网口访问服务端
mk_client "$DIR/c1.yaml" 10.144.144.2 ta1 10.201.0.1
mk_client "$DIR/c2.yaml" 10.144.144.3 tb1 10.201.1.1

echo "=== 启动服务端（公网侧）==="
nohup "$BIN" server -c "$DIR/server.yaml" > "$DIR/server.log" 2>&1 &
sleep 2

echo "=== 建拓扑 ==="
ip netns add natA
ip netns add natB
ip netns add cA
ip netns add cB

# 公网段：root 两侧
ip link add vRA type veth peer name vRA2
ip link set vRA2 netns natA
ip addr add 10.201.0.1/24 dev vRA
ip link set vRA up
ip link add vRB type veth peer name vRB2
ip link set vRB2 netns natB
ip addr add 10.201.1.1/24 dev vRB
ip link set vRB up
sysctl -qw net.ipv4.ip_forward=1

# natA：公网口 + 内网口 + SNAT
ip netns exec natA ip addr add 10.201.0.2/24 dev vRA2
ip netns exec natA ip link set vRA2 up
ip netns exec natA ip link set lo up
ip link add vA type veth peer name vA2
ip link set vA2 netns natA
ip netns exec natA ip addr add 10.202.0.1/24 dev vA2
ip netns exec natA ip link set vA2 up
ip netns exec natA sysctl -qw net.ipv4.ip_forward=1
ip netns exec natA ip route add default via 10.201.0.1
ip netns exec natA iptables -t nat -A POSTROUTING -o vRA2 -j MASQUERADE
ip netns exec natA iptables -P FORWARD ACCEPT

# natB
ip netns exec natB ip addr add 10.201.1.2/24 dev vRB2
ip netns exec natB ip link set vRB2 up
ip netns exec natB ip link set lo up
ip link add vB type veth peer name vB2
ip link set vB2 netns natB
ip netns exec natB ip addr add 10.203.0.1/24 dev vB2
ip netns exec natB ip link set vB2 up
ip netns exec natB sysctl -qw net.ipv4.ip_forward=1
ip netns exec natB ip route add default via 10.201.1.1
ip netns exec natB iptables -t nat -A POSTROUTING -o vRB2 -j MASQUERADE
ip netns exec natB iptables -P FORWARD ACCEPT

# 内网客户端
ip link set vA netns cA
ip netns exec cA ip addr add 10.202.0.2/24 dev vA
ip netns exec cA ip link set vA up
ip netns exec cA ip link set lo up
ip netns exec cA ip route add default via 10.202.0.1

ip link set vB netns cB
ip netns exec cB ip addr add 10.203.0.2/24 dev vB
ip netns exec cB ip link set vB up
ip netns exec cB ip link set lo up
ip netns exec cB ip route add default via 10.203.0.1

echo "=== 启动两个 NAT 后的客户端 ==="
ip netns exec cA nohup "$BIN" client -c "$DIR/c1.yaml" > "$DIR/c1.log" 2>&1 &
ip netns exec cB nohup "$BIN" client -c "$DIR/c2.yaml" > "$DIR/c2.log" 2>&1 &
sleep 8

echo "=== 各自的 NAT 公网映射 ==="
grep -h "overlay NAT" "$DIR/c1.log" "$DIR/c2.log" 2>/dev/null | tail -2 || true

echo "=== 服务端看到的节点 ==="
grep -i "overlay 节点" "$DIR/server.log" | tail -3 || true

echo "=== 基础连通性（确认测试环境本身是通的）==="
ip netns exec cA ping -c1 -W2 10.201.0.1 >/dev/null 2>&1 && echo "cA -> 服务端公网 OK" || echo "cA -> 服务端公网 FAIL"
ip netns exec cA ping -c1 -W2 10.201.1.2 >/dev/null 2>&1 && echo "cA -> natB公网 OK" || echo "cA -> natB公网 FAIL"
ip netns exec cB ping -c1 -W2 10.201.0.2 >/dev/null 2>&1 && echo "cB -> natA公网 OK" || echo "cB -> natA公网 FAIL"

echo "=== conntrack（看 NAT 是否建立了双向映射）==="
ip netns exec natA conntrack -L 2>/dev/null | head -4 || echo "(conntrack 工具不可用)"

echo "=== 阶段一：启动后 8 秒（只可能靠直连/打洞）==="
if ip netns exec cA ping -c 2 -W 2 10.144.144.3 >/dev/null 2>&1; then
  echo "RESULT[$DIRECT]: PING_EARLY_OK（直连或打洞成功）"
else
  echo "RESULT[$DIRECT]: PING_EARLY_FAIL"
fi
grep -c "收到打洞探测包" "$DIR/c1.log" 2>/dev/null | sed "s/^/c1 收到打洞探测包次数: /" || true

echo "=== 阶段二：再等 20 秒（中继兜底应该生效）==="
sleep 20
if ip netns exec cA ping -c 3 -W 3 10.144.144.3 >/dev/null 2>&1; then
  echo "RESULT[$DIRECT]: PING_LATE_OK（中继兜底生效）"
else
  echo "RESULT[$DIRECT]: PING_LATE_FAIL"
fi

echo "=== cA -> cB 虚拟 IP ==="
if ip netns exec cA ping -c 3 -W 3 10.144.144.3 >/dev/null 2>&1; then
  echo "RESULT[$DIRECT]: PING_OK"
else
  echo "RESULT[$DIRECT]: PING_FAIL"
  ip netns exec cA ping -c 1 -W 2 10.144.144.3 || true
fi

echo "=== cB -> cA ==="
if ip netns exec cB ping -c 3 -W 3 10.144.144.2 >/dev/null 2>&1; then
  echo "RESULT[$DIRECT]: PING_BACK_OK"
else
  echo "RESULT[$DIRECT]: PING_BACK_FAIL"
fi

echo "=== 连接类型（握手/打洞/中继）==="
grep -iE "打洞|New session|中继" "$DIR/c1.log" | tail -5 || true
echo DONE
