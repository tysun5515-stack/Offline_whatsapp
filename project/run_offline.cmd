@echo off
setlocal
set "PROJECT_ROOT=%~dp0"
set "WA_OFFLINE=1"
if not exist "%PROJECT_ROOT%.venv\Scripts\python.exe" (
  echo Offline environment not found. Run install_offline.ps1 first.
  exit /b 1
)
pushd "%PROJECT_ROOT%" || exit /b 1
"%PROJECT_ROOT%.venv\Scripts\python.exe" -m src.webapp.app
set "APP_EXIT=%ERRORLEVEL%"
popd
exit /b %APP_EXIT%
