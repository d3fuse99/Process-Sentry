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
if not exist "dist" (
    echo [Process-Sentry] Production build not found. Installing and compiling frontend...
    call npm.cmd install
    call npm.cmd run build
)
start "Process-Sentry Backend" cmd /k python server.py
timeout /t 2
start "Process-Sentry Agent" cmd /k agent.exe
timeout /t 1
start "Process-Sentry Frontend" cmd /k npm run dev
timeout /t 1
start http://localhost:3000