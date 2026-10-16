@echo off
setlocal
title WhatsApp Analyzer - Starting
set "BUNDLE_DIR=%~dp0"
set "PATH=%PATH%;C:\Program Files\Wireshark"

if not exist "%BUNDLE_DIR%project\.venv\Scripts\python.exe" (
    echo [ERROR] Offline environment not found. Run INSTALL.bat first.
    pause
    exit /b 1
)

echo Starting at http://127.0.0.1:5000 - press Ctrl+C to stop.
start "" /b "%BUNDLE_DIR%project\open_browser_after_delay.cmd"
call "%BUNDLE_DIR%project\run_offline.cmd"
set "APP_EXIT=%ERRORLEVEL%"
if not "%APP_EXIT%"=="0" pause
exit /b %APP_EXIT%
