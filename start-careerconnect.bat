@echo off
setlocal

set "ROOT=%~dp0"
set "API_URL=http://localhost:4000/api/health"

powershell -NoProfile -ExecutionPolicy Bypass -Command ^
  "try { Invoke-WebRequest -UseBasicParsing '%API_URL%' -TimeoutSec 2 | Out-Null; exit 0 } catch { exit 1 }"

if errorlevel 1 (
  echo Starting CareerConnect backend on port 4000...
  start "CareerConnect API" powershell -NoExit -Command "Set-Location '%ROOT%jbbackend'; npm start"
  timeout /t 4 /nobreak >nul
) else (
  echo CareerConnect backend is already running.
)

start "" "%ROOT%explore.html"

endlocal
