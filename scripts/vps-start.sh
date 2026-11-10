#!/bin/bash
# 在 VPS 上重启 Trairi 服务端并打印状态
pkill -f "trairi server" 2>/dev/null
sleep 1
cd "$HOME"
nohup "$HOME/trairi" server -c "$HOME/server.yaml" > "$HOME/server.log" 2>&1 &
sleep 3
echo "--- server.log ---"
cat "$HOME/server.log"
echo "--- listening ---"
ss -lntup 2>/dev/null | grep -E "5600" || echo "(no listener)"
