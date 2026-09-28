# Rollback

Set `WA_CRYPTO_ANALYSIS_ENABLED=false` and restart to disable new extraction.
The source snapshot and SQLite backups are in `C:\Users\Test3\Music\WhatsApp_Offline_Bundle\crypto-rollback-20260928`.
Stop the app before restoring changed source files from that snapshot. Remove the new crypto_service.py module. Do not reset the dirty worktree: it contains earlier user changes.
New database tables have the `_v3` suffix and may remain unused. Database restoration is optional and removes later uploads/results. Preserve current DB/WAL/SHM files together before restoring backups.
