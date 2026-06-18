#!/bin/sh

export PORT=${PORT:-8000}
sed -i "s/PORT_PLACEHOLDER/$PORT/" /etc/nginx/nginx.conf

echo "Starting Nginx on port $PORT..."
nginx

sleep 1

echo "Starting Panel..."
exec python3 /app/panel.py