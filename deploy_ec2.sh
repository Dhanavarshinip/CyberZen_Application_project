#!/bin/bash
set -e

echo "[*] Setting up CyberZen on AWS EC2..."
cd /home/ubuntu/cyberzen

# 1. Create data directory
mkdir -p data logs

# 2. Setup Systemd Service
cat << 'EOF' | sudo tee /etc/systemd/system/cyberzen.service
[Unit]
Description=CyberZen Security Platform Backend API
After=network.target

[Service]
User=ubuntu
Group=ubuntu
WorkingDirectory=/home/ubuntu/cyberzen
Environment="PATH=/home/ubuntu/cyberzen/venv/bin:/usr/local/bin:/usr/bin"
Environment="PYTHONPATH=/home/ubuntu/cyberzen"
Environment="ENVIRONMENT=production"
Environment="CYBERTHREAT_DATA_DIR=/home/ubuntu/cyberzen/data"
ExecStart=/home/ubuntu/cyberzen/venv/bin/uvicorn backend.main:app --host 127.0.0.1 --port 8000 --workers 2
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
EOF

# 3. Reload and start systemd service
sudo systemctl daemon-reload
sudo systemctl enable cyberzen
sudo systemctl restart cyberzen

# 4. Setup Nginx Configuration
cat << 'EOF' | sudo tee /etc/nginx/sites-available/default
server {
    listen 80 default_server;
    listen [::]:80 default_server;
    server_name _;

    root /home/ubuntu/cyberzen;
    index index.html download.html;

    gzip on;
    gzip_types text/plain text/css application/json application/javascript text/xml application/xml application/xml+rss text/javascript;

    location /assets/ {
        alias /home/ubuntu/cyberzen/assets/;
        expires 30d;
        add_header Cache-Control "public, no-transform";
    }

    location /download {
        try_files /download.html =404;
    }

    location /api/ {
        proxy_pass http://127.0.0.1:8000/api/;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection 'upgrade';
        proxy_set_header Host $host;
        proxy_cache_bypass $http_upgrade;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }

    location / {
        try_files $uri $uri/ /index.html;
    }
}
EOF

# 5. Fix permissions for Nginx to read /home/ubuntu/cyberzen
chmod 755 /home/ubuntu
chmod -R 755 /home/ubuntu/cyberzen

# 6. Test and Reload Nginx
sudo nginx -t
sudo systemctl reload nginx

echo "[+] CyberZen Successfully Deployed on AWS EC2!"
