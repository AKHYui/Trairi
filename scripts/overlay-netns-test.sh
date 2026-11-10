#!/bin/bash
# 真实环境验证：两个 network namespace 各跑一个 Trairi 客户端（真 TUN），
# 服务端在根 netns 做协调 + 中继。目标：ns1 能 ping 通 ns2 的虚拟 IP。
#
# 用法： bash overlay-netns-test.sh [true|false]
#   true（默认）—— 走直连
#   false        —— 忽略直连端点，强制走服务端 TCP 中继
set -e

DIRECT="${1:-true}"
BIN=/root/trairi
DIR=/root/ovtest
mkdir -p "$DIR"

echo "=== 模式：direct=$DIRECT ==="
echo "=== 清理旧环境 ==="
ip netns del ns1 2>/dev/null || true
ip netns del ns2 2>/dev/null || true
pkill -f "$BIN" 2>/dev/null || true
sleep 1

echo "=== 写配置 ==="
cat > "$DIR/server.yaml" <<'EOF'
mode: server
log:
  level: info
server:
  bind_addr: 0.0.0.0
  bind_port: 27000
  token: ov-token
overlay:
  enable: true
  network_name: testnet
  network_secret: test-secret-123
  ipv4_pool: 10.144.144.0/24
  udp_port: 27013
  relay_listen: 0.0.0.0:27012
EOF

mk_client() {
  local file="$1" ip="$2" iface="$3" gw="$4"
  cat > "$file" <<EOF
mode: client
log:
  level: debug
client:
  server_addr: $gw
  server_port: 27000
  token: ov-token
overlay:
  enable: true
  network_name: testnet
  network_secret: test-secret-123
  ipv4: $ip
  udp_port: 0
  interface: $iface
  direct: $DIRECT
EOF
}

mk_client "$DIR/c1.yaml" 10.144.144.2 tr1 10.200.0.1
mk_client "$DIR/c2.yaml" 10.144.144.3 tr2 10.200.1.1

echo "=== 启动服务端 ==="
nohup "$BIN" server -c "$DIR/server.yaml" > "$DIR/server.log" 2>&1 &
sleep 2

echo "=== 建 netns + veth ==="
ip netns add ns1
ip netns add ns2
ip link add v1 type veth peer name v1n
ip link set v1n netns ns1
ip link add v2 type veth peer name v2n
ip link set v2n netns ns2
ip addr add 10.200.0.1/24 dev v1
ip link set v1 up
ip addr add 10.200.1.1/24 dev v2
ip link set v2 up
ip netns exec ns1 ip addr add 10.200.0.2/24 dev v1n
ip netns exec ns1 ip link set v1n up
ip netns exec ns1 ip link set lo up
ip netns exec ns1 ip route add default via 10.200.0.1
ip netns exec ns2 ip addr add 10.200.1.2/24 dev v2n
ip netns exec ns2 ip link set v2n up
ip netns exec ns2 ip link set lo up
ip netns exec ns2 ip route add default via 10.200.1.1
sysctl -qw net.ipv4.ip_forward=1

echo "=== 启动两个客户端 ==="
ip netns exec ns1 nohup "$BIN" client -c "$DIR/c1.yaml" > "$DIR/c1.log" 2>&1 &
ip netns exec ns2 nohup "$BIN" client -c "$DIR/c2.yaml" > "$DIR/c2.log" 2>&1 &
sleep 8

echo "=== 虚拟网卡 ==="
ip netns exec ns1 ip -4 addr show tr1 2>&1 | head -3 || true
ip netns exec ns2 ip -4 addr show tr2 2>&1 | head -3 || true

echo "=== 服务端日志（overlay）==="
grep -i overlay "$DIR/server.log" | tail -n 6 || true

echo "=== ns1 -> ns2 ==="
if ip netns exec ns1 ping -c 3 -W 3 10.144.144.3 >/dev/null 2>&1; then
  echo "RESULT[$DIRECT]: PING_OK"
else
  echo "RESULT[$DIRECT]: PING_FAIL"
  ip netns exec ns1 ping -c 1 -W 2 10.144.144.3 || true
fi

echo "=== ns2 -> ns1 ==="
if ip netns exec ns2 ping -c 3 -W 3 10.144.144.2 >/dev/null 2>&1; then
  echo "RESULT[$DIRECT]: PING_BACK_OK"
else
  echo "RESULT[$DIRECT]: PING_BACK_FAIL"
fi

echo "=== 客户端日志尾部 ==="
grep -iE "中继|overlay|session" "$DIR/c1.log" | tail -n 6 || true
echo "---"
grep -iE "中继|overlay|session" "$DIR/c2.log" | tail -n 6 || true

echo "=== 清理 ==="
pkill -f "$BIN" 2>/dev/null || true
ip netns del ns1 2>/dev/null || true
ip netns del ns2 2>/dev/null || true
echo DONE
