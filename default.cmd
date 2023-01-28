@echo off
rem Command to start RIDE configuration using default library and default preset
@powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0ride.ps1" -include "%~dp0lib-windows.psm1" -preset "%~dpn0.preset"

rem The following are examples of other run profiles:

rem RIDE using default library & default preset and with logging enabled
rem @powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0ride.ps1" -include "%~dp0lib-windows.psm1" -preset "%~dpn0.preset" -log "%~dp0install-log.log" -ini "%~dp0config.ini"

rem RIDE using default library, default preset, logging enabled and with loading of custom config from ini file 
rem @powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0ride.ps1" -include "%~dp0lib-windows.psm1" -preset "%~dpn0.preset" -log "%~dp0install-log.log" -ini "%~dp0config.ini"
