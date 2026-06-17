#!/bin/sh

if [ -z "$UUID" ]; then
  UUID="90cd4a77-141a-43c9-991b-08263cfe9c10"
fi

WS_PATH="/ws/${UUID}"
XH_PATH="/xh/${UUID}"

cat > /app/cfg.json << CFGEOF
{
  "log": {"loglevel": "warning"},
  "inbounds": [
    {
      "port": 8080,
      "listen": "127.0.0.1",
      "protocol": "vless",
      "settings": {
        "clients": [{"id": "${UUID}", "level": 0}],
        "decryption": "none"
      },
      "streamSettings": {
        "network": "ws",
        "wsSettings": {"path": "${WS_PATH}"}
      }
    },
    {
      "port": 8081,
      "listen": "127.0.0.1",
      "protocol": "vless",
      "settings": {
        "clients": [{"id": "${UUID}", "level": 0}],
        "decryption": "none"
      },
      "streamSettings": {
        "network": "xhttp",
        "xhttpSettings": {
          "path": "${XH_PATH}",
          "mode": "auto"
        }
      }
    }
  ],
  "outbounds": [{"protocol": "freedom"}]
}
CFGEOF

echo "Starting Xray on 8080 (WS) and 8081 (XHTTP)..."
/usr/local/bin/xray -config /app/cfg.json &

echo "Starting panel on port ${PORT:-8000}..."
exec python3 /app/panel.py
