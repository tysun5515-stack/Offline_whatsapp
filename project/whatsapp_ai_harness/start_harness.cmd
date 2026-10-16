@echo off
setlocal
set "HARNESS_DIR=%~dp0"
set "WA_OFFLINE=1"
if not exist "%HARNESS_DIR%.venv\Scripts\python.exe" (
  echo Offline companion environment not found. Run the bundle-root INSTALL.bat first.
  exit /b 1
)
pushd "%HARNESS_DIR%.." || exit /b 1
"%HARNESS_DIR%.venv\Scripts\python.exe" -m whatsapp_ai_harness.serve
set "HARNESS_EXIT=%ERRORLEVEL%"
popd
exit /b %HARNESS_EXIT%
