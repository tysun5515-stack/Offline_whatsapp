@echo off
setlocal enabledelayedexpansion
title WhatsApp Analyzer - First Time Setup
color 0A

echo.
echo ============================================================
echo   WhatsApp Offline Analyzer  -  First Time Setup
echo   DO NOT CLOSE this window until setup is complete.
echo ============================================================
echo.

:: Detect where the bundle lives (works from any path / any username)
set "BUNDLE_DIR=%~dp0"
set "BUNDLE_DIR=%BUNDLE_DIR:~0,-1%"
set "PROJECT_DIR=%BUNDLE_DIR%\project"
set "WHEELS_DIR=%BUNDLE_DIR%\wheels"
set "VENV_DIR=%PROJECT_DIR%\.venv"

:: ??? STEP 1: Python ???????????????????????????????????????????????????????????
echo [1/5] Checking Python 3.12...
set "PYTHON_EXE="

:: Check common install locations
for %%P in (
    "python"
    "%LOCALAPPDATA%\Programs\Python\Python312\python.exe"
    "C:\Program Files\Python312\python.exe"
    "C:\Python312\python.exe"
) do (
    if "!PYTHON_EXE!"=="" (
        %%~P --version >nul 2>&1
        if !errorlevel!==0 (
            for /f "tokens=2" %%V in ('%%~P --version 2^>^&1') do (
                echo %%V | findstr /r "^3\.12" >nul
                if !errorlevel!==0 set "PYTHON_EXE=%%~P"
            )
        )
    )
)

if "!PYTHON_EXE!"=="" (
    echo       Python 3.12 not found. Installing silently...
    if not exist "%BUNDLE_DIR%\python-3.12.0-amd64.exe" (
        echo.
        echo  [ERROR] Python installer missing from bundle!
        echo          Expected: %BUNDLE_DIR%\python-3.12.0-amd64.exe
        pause & exit /b 1
    )
    "%BUNDLE_DIR%\python-3.12.0-amd64.exe" /quiet InstallAllUsers=0 PrependPath=1 Include_test=0
    if !errorlevel! neq 0 (echo  [ERROR] Python install failed. & pause & exit /b 1)
    :: Refresh PATH
    set "PATH=%LOCALAPPDATA%\Programs\Python\Python312;%LOCALAPPDATA%\Programs\Python\Python312\Scripts;%PATH%"
    set "PYTHON_EXE=%LOCALAPPDATA%\Programs\Python\Python312\python.exe"
    echo       Python 3.12 installed.
) else (
    echo       Python 3.12 found: !PYTHON_EXE!
)

:: ??? STEP 2: Wireshark / TShark ???????????????????????????????????????????????
echo.
echo [2/5] Checking Wireshark / TShark...
set "TSHARK_FOUND=0"
where tshark >nul 2>&1 && set "TSHARK_FOUND=1"
if exist "C:\Program Files\Wireshark\tshark.exe" set "TSHARK_FOUND=1"

if "!TSHARK_FOUND!"=="0" (
    echo       TShark not found. Installing Wireshark silently...
    if not exist "%BUNDLE_DIR%\Wireshark-x64.exe" (
        echo.
        echo  [ERROR] Wireshark installer missing from bundle!
        echo          Expected: %BUNDLE_DIR%\Wireshark-x64.exe
        pause & exit /b 1
    )
    "%BUNDLE_DIR%\Wireshark-x64.exe" /S /desktopicon=no /quicklaunchicon=no
    if !errorlevel! neq 0 (echo  [ERROR] Wireshark install failed. & pause & exit /b 1)
    set "PATH=%PATH%;C:\Program Files\Wireshark"
    echo       Wireshark installed.
) else (
    echo       TShark found. Skipping.
    set "PATH=%PATH%;C:\Program Files\Wireshark"
)

:: ??? STEP 3: Create Virtual Environment ??????????????????????????????????????
echo.
echo [3/5] Creating Python virtual environment in project folder...
if exist "%VENV_DIR%\Scripts\python.exe" (
    echo       Virtual environment already exists. Skipping.
) else (
    "!PYTHON_EXE!" -m venv "%VENV_DIR%"
    if !errorlevel! neq 0 (echo  [ERROR] Failed to create venv. & pause & exit /b 1)
    echo       Virtual environment created.
)

:: ??? STEP 4: Install Packages Offline ????????????????????????????????????????
echo.
echo [4/5] Installing Python packages from local wheels (100%% offline)...
"%VENV_DIR%\Scripts\pip.exe" install --no-index --find-links="%WHEELS_DIR%" -r "%PROJECT_DIR%\requirements.txt" -q
if !errorlevel! neq 0 (
    echo  [ERROR] Package installation failed. Showing details...
    "%VENV_DIR%\Scripts\pip.exe" install --no-index --find-links="%WHEELS_DIR%" -r "%PROJECT_DIR%\requirements.txt"
    pause & exit /b 1
)
echo       All packages installed.

:: ??? STEP 5: Verify ??????????????????????????????????????????????????????????
echo.
echo [5/5] Verifying packages...
"%VENV_DIR%\Scripts\python.exe" -c "import flask, pyshark, matplotlib, geoip2, plotly, scipy, numpy; print('      All imports OK')"
if !errorlevel! neq 0 (
    echo  [WARNING] Verification failed - check errors above.
) else (
    echo       All OK!
)

:: ??? Done ????????????????????????????????????????????????????????????????????
echo.
echo ============================================================
echo   SETUP COMPLETE!
echo   Double-click RUN.bat to launch the web app.
echo   Then go to: http://localhost:5000
echo ============================================================
echo.
pause
