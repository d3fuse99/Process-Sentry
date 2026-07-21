@echo off
net session >nul 2>&1
if %errorLevel% == 0 (
    goto :admin
) else (
    powershell -Command "Start-Process -FilePath '%0' -Verb RunAs"
    exit /b
)

:admin
taskkill /IM agent.exe /F
taskkill /F /IM python.exe
taskkill /F /IM node.exe
netsh advfirewall firewall delete rule name="ProcessSentry_Isolate"