#!/bin/sh

# پنل روی پورت اصلی (Railway/Render این رو set می‌کنن)
PANEL_PORT="${PORT:-8000}"

# ایجاد یک کانفیگ موقت برای استارت اولیه Xray
echo '{"log":{"loglevel":"warning"},"inbounds":[],"outbounds":[{"protocol":"freedom"}]}' > /app/cfg.json

echo "Starting Xray..."
/usr/local/bin/xray -config /app/cfg.json &

# کمی صبر کن Xray بالا بیاد
sleep 2

echo "Starting panel on port ${PANEL_PORT}..."
exec python3 /app/panel.py