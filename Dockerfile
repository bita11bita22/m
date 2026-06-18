FROM python:3.11-slim

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    curl unzip gcc python3-dev nginx \
    && rm -rf /var/lib/apt/lists/*

RUN curl -L -o /tmp/xray.zip \
    "https://github.com/XTLS/Xray-core/releases/latest/download/Xray-linux-64.zip" && \
    unzip /tmp/xray.zip -d /usr/local/bin/ && \
    rm /tmp/xray.zip && \
    chmod +x /usr/local/bin/xray

RUN pip install --no-cache-dir \
    fastapi \
    "uvicorn[standard]" \
    httpx

COPY panel.py /app/panel.py
COPY run.sh /app/run.sh
COPY nginx.conf /etc/nginx/nginx.conf

RUN chmod +x /app/run.sh

EXPOSE 8000

CMD ["/app/run.sh"]