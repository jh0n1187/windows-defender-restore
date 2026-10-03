@echo off
REM Kit Restore-Defender: RESTAURA e HABILITA o Microsoft Defender. Duplo clique. (2 passagens: reparar, reiniciar, executar de novo)
net session >nul 2>&1
if errorlevel 1 (
  powershell -NoProfile -Command "Start-Process -FilePath \"%~f0\" -Verb RunAs"
  exit /b
)
cd /d "%~dp0Scripts"
if not exist ..\Logs mkdir ..\Logs
%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe -NoProfile -ExecutionPolicy Bypass -Command "& { & .\Repair-And-Enable.ps1 } *>&1 | Tee-Object -FilePath (\"..\Logs\Repair-And-Enable-\" + (Get-Date -Format yyyyMMdd-HHmmss) + \".log\")"
echo.
echo ===== FIM - log em %~dp0Logs =====
pause
