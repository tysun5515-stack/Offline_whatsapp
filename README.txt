========================================================
  WhatsApp Offline Analyzer  -  Quick Start Guide
========================================================

FIRST TIME SETUP (do this once only):
--------------------------------------
1. Copy this entire "WhatsApp_Offline_Bundle" folder
   from the USB drive to your Desktop (or anywhere).

NOTE: When move the offline_bundle to another system  delete virtual environment.

2. Make sure the following installer files are in the
   same folder as INSTALL.bat:
     - python-3.12.0-amd64.exe
     - Wireshark-x64.exe

   They are included in this complete bundle. If either file or the
   "wheels" folder is missing, the bundle is incomplete; do not attempt
   installation on the disconnected computer.

3. Right-click INSTALL.bat > "Run as Administrator"
   Wait for it to complete (2-5 minutes).

EVERY TIME YOU WANT TO RUN THE APP:
-------------------------------------
1. Double-click RUN.bat
2. A browser window will open at http://localhost:5000
3. To stop the app, close the black command window.

TROUBLESHOOTING:
-----------------
- "Python not found" error: Re-run INSTALL.bat as Administrator.
- "TShark not found" error: Re-run INSTALL.bat as Administrator
  to ensure Wireshark is installed.
- App doesnt open in browser: Manually go to http://localhost:5000
- Package installation error: Verify the full "wheels" folder was copied.
- The optional AI companion starts with project\whatsapp_ai_harness\start_harness.cmd.
  Its deterministic mode is offline. Ollama/model-assisted mode requires a
  separately installed local Ollama model, but does not require internet.

========================================================
