# Disposable VM integration suite

Run these checks only on a disposable Windows 11 or Windows Server 2025 VM with a clean checkpoint. The suite installs and uninstalls 7-Zip and Notepad++ from their upstream sources. Set `RIDE_INTEGRATION_VM=1` inside the guest before running the script; this guard prevents accidental execution on a daily workstation.

From an elevated PowerShell session in the repository:

```powershell
$env:RIDE_INTEGRATION_VM = '1'
.\tests\integration\Invoke-RideVmSuite.ps1
```

The suite captures the initial Explorer registry value, applies the analyst group twice, confirms status, restores the first run's saved state, applies `profiles/baseline.psd1`, removes the group in reverse order, and confirms both packages are absent. Restore the VM checkpoint after the run.

The unit suite tests partial failure reporting with mocked handlers. A failed VM run prints the run ID and the operations with saved state so an operator can inspect or restore the completed portion.
