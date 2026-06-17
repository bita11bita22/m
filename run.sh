#!/bin/sh

if [ -z "$UUID" ]; then
  UUID="90cd4a77-141a-43c9-991b-08263cfe9c10"
fi

# پنل روی پورت اصلی (Railway/Render این رو set می‌کنن)
PANEL_PORT="${PORT:-8000}"

# Xray روی پورت‌های داخلی ثابت
XRAY_WS_PORT=18080
XRAY_XH_PORT=18081

WS_PATH="/ws/${UUID}"
XH_PATH="/xh/${UUID}"

cat > /app/cfg.json << CFGEOF
{
  "log": {"loglevel": "warning"},
  "inbounds": [
    {
      "port": ${XRAY_WS_PORT},
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
      "port": ${XRAY_XH_PORT},
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

echo "Starting Xray on WS:${XRAY_WS_PORT} XHTTP:${XRAY_XH_PORT}..."
/usr/local/bin/xray -config /app/cfg.json &

# کمی صبر کن Xray بالا بیاد
sleep 2

echo "Starting panel on port ${PANEL_PORT}..."
exec python3 /app/panel.py
