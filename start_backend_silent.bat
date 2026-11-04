@echo off
REM CyberZen - 24/7 Silent Background Host Telemetry & ML Monitor
cd /d "D:\CyberThreat_AI_System"
python -m uvicorn backend.main:app --host 127.0.0.1 --port 8000 >> "data\backend_monitor.log" 2>&1
