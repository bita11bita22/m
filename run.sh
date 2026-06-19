#!/bin/sh

export PORT=${PORT:-8000}
sed -i "s/PORT_PLACEHOLDER/$PORT/" /etc/nginx/nginx.conf

echo "Starting Nginx on port $PORT..."
nginx

sleep 1

# ساخت کانفیگ Cloudflare WARP در صورت عدم وجود
if [ ! -f /app/warp_key.txt ]; then
    echo "Registering Cloudflare WARP..."
    cd /app
    /usr/local/bin/wgcf register --accept-tos
    /usr/local/bin/wgcf generate
    
    # استخراج صحیح کلید خصوصی و آدرس‌های IPv4 و IPv6
    grep 'PrivateKey' wgcf-profile.conf | awk -F' = ' '{print $2}' > /app/warp_key.txt
    grep -m 1 'Address' wgcf-profile.conf | awk -F' = ' '{print $2}' >> /app/warp_key.txt
    grep -m 2 'Address' wgcf-profile.conf | tail -n 1 | awk -F' = ' '{print $2}' >> /app/warp_key.txt
    
    rm wgcf-account.toml wgcf-profile.conf
fi

echo "Starting Panel..."
exec python3 /app/panel.py