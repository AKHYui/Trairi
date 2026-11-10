#!/bin/bash
# 以 root 重启 Trairi 服务端（服务端节点需要 root 建 TUN）
sudo pkill -f "trairi server" 2>/dev/null
pkill -f "trairi server" 2>/dev/null
sleep 1
sudo nohup "$HOME/trairi" server -c "$HOME/server.yaml" > "$HOME/server.log" 2>&1 &
sleep 4
echo "--- server.log ---"
sudo tail -25 "$HOME/server.log"
echo "--- 接口 ---"
ip -4 addr show | grep -E "trairi|srv" -A1 | head -6