#!/bin/sh

export PORT=${PORT:-8000}
sed -i "s/PORT_PLACEHOLDER/$PORT/" /etc/nginx/nginx.conf

echo "Starting Nginx on port $PORT..."
nginx

sleep 1

# ساخت کانفیگ Cloudflare WARP در صورت عدم وجود
if [ ! -f /app/warp_profile.conf ]; then
    echo "Registering Cloudflare WARP..."
    cd /app
    /usr/local/bin/wgcf register --accept-tos
    /usr/local/bin/wgcf generate
    # تغییر نام فایل برای استفاده در پایتون
    mv wgcf-profile.conf /app/warp_profile.conf
    rm -f wgcf-account.toml
fi

echo "Starting Panel..."
exec python3 /app/panel.py