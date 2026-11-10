#!/bin/bash
# 在 VPS 上停掉旧的服务端进程（等它真正退出，释放二进制）
sudo pkill -f "trairi server" 2>/dev/null
pkill -f "trairi server" 2>/dev/null
for _ in $(seq 1 15); do
  if ! pgrep -f "trairi server" >/dev/null 2>&1; then
    echo "stopped"
    exit 0
  fi
  sleep 1
done
echo "still running"
pgrep -af "trairi server"
exit 1
