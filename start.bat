@echo off
net session >nul 2>&1
if %errorLevel% == 0 (
    goto :admin
) else (
    powershell -Command "Start-Process -FilePath '%0' -Verb RunAs"
    exit /b
)

:admin
cd /d "%~dp0"
start "Process-Sentry Backend" cmd /k python server.py
timeout /t 2
start "Process-Sentry Agent" cmd /k python agent.py
timeout /t 1
start "Process-Sentry Frontend" cmd /k npm run dev