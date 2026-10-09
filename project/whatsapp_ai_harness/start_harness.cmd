@echo off
setlocal
set "HARNESS_DIR=%~dp0"
pushd "%HARNESS_DIR%.." || exit /b 1
"%HARNESS_DIR%.venv\Scripts\python.exe" -m whatsapp_ai_harness.serve
set "HARNESS_EXIT=%ERRORLEVEL%"
popd
exit /b %HARNESS_EXIT%
