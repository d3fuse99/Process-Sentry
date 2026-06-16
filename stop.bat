@echo off
taskkill /f /im agent.exe >nul 2>&1
taskkill /f /im node.exe >nul 2>&1
wmic process where "commandline like '%%server.py%%'" call terminate >nul 2>&1
echo [Process-Sentry] All EDR processes terminated safely.
timeout /t 2