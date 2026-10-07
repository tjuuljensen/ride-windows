@echo off
rem Apply the declarative default profile.
@powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0ride.ps1" apply -Profile "%~dp0profiles\default.psd1"
