#!/bin/sh

# استارت Nginx در پس‌زمینه
echo "Starting Nginx..."
nginx

# استارت پنل پایتون (که درون خودش Xray را هم مدیریت می‌کند)
echo "Starting Panel..."
exec python3 /app/panel.py