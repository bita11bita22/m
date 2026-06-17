FROM python:3.11-slim

WORKDIR /app

# نصب curl و gcc برای ARM compatibility
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl unzip gcc python3-dev \
    && rm -rf /var/lib/apt/lists/*

# دانلود Xray-core
RUN curl -L -o /tmp/xray.zip \
    "https://github.com/XTLS/Xray-core/releases/latest/download/Xray-linux-64.zip" && \
    unzip /tmp/xray.zip -d /usr/local/bin/ && \
    rm /tmp/xray.zip && \
    chmod +x /usr/local/bin/xray

# نصب پکیج‌های Python
RUN pip install --no-cache-dir \
    fastapi \
    "uvicorn[standard]" \
    httpx \
    websockets

COPY panel.py /app/panel.py
COPY run.sh /app/run.sh
RUN chmod +x /app/run.sh

EXPOSE 8000

CMD ["/app/run.sh"]
