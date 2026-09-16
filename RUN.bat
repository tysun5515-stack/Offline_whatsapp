@echo off
setlocal enabledelayedexpansion
title WhatsApp Analyzer - Starting...
color 0B

set "BUNDLE_DIR=%~dp0"
set "BUNDLE_DIR=%BUNDLE_DIR:~0,-1%"
set "PROJECT_DIR=%BUNDLE_DIR%\project"
set "VENV_DIR=%PROJECT_DIR%\.venv"

:: Ensure TShark is on PATH
set "PATH=%PATH%;C:\Program Files\Wireshark"

:: Check setup has been run
if not exist "%VENV_DIR%\Scripts\python.exe" (
    echo  [ERROR] Virtual environment not found!
    echo          Please run INSTALL.bat first.
    pause
    exit /b 1
)

echo.
echo ============================================================
echo   WhatsApp Offline Analyzer
echo   Starting server at http://localhost:5000
echo   Press Ctrl+C in this window to stop the server.
echo ============================================================
echo.

:: Open browser after 3 seconds
start /b cmd /c "timeout /t 3 /nobreak >nul && start http://localhost:5000"

:: Start Flask app
cd /d "%PROJECT_DIR%"
"%VENV_DIR%\Scripts\python.exe" src\webapp\app.py

pause
