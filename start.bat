@echo off
openfiles >nul 2>&1
if %errorlevel% neq 0 (
    powershell start -verb runas '%0' am_admin
    exit /b
)
cd /d "%~dp0"
set PY_CMD=python
where python >nul 2>&1
if %errorlevel% neq 0 (
    where py >nul 2>&1
    if %errorlevel% == 0 (
        set PY_CMD=py
    )
)
if exist "agent.go" (
    where go >nul 2>&1
    if %errorlevel% == 0 (
        if not exist "go.mod" (
            go mod init process-sentry-agent
            go get github.com/secDre4mer/etw
            go get golang.org/x/sys/windows
            go mod tidy
        )
        go build -o agent.exe agent.go
    )
)
start "" %PY_CMD% server.py
if exist "agent.exe" (
    start "" agent.exe
)
timeout /t 2
start http://localhost:3000