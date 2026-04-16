@echo off
setlocal

echo Stopping CareerConnect backend windows...
powershell -NoProfile -ExecutionPolicy Bypass -Command ^
  "Get-CimInstance Win32_Process | Where-Object { $_.Name -match 'powershell(.exe)?' -and $_.CommandLine -match 'jbbackend' -and $_.CommandLine -match 'npm start' } | ForEach-Object { Stop-Process -Id $_.ProcessId -Force }"

endlocal
