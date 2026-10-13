# Mouse jigglers, Caffeine and lock blockers

Standalone helpers and native alternatives for an already unlocked Windows session.

## Behavior and limitations

The intended outcome is to preserve an already unlocked interactive Windows
session during an investigation when a physical mouse jiggler or another
suitable option is unavailable. Preventing sleep and preventing idle screen
locking are distinct outcomes. A power request alone is not an equivalent
replacement for the accepted screen-lock blocker.

Keep different execution options available rather than assuming one is usable
on every host. Prioritize minimal memory use, disk writes and persistent
configuration. Retain upstream notices and assess applicable product terms.

- `components/scripts/caffeine.ps1`, version 0.2.2, retains a visible console
  color/title by default. `-NoConsoleCustomization` skips those changes.
  `-IntervalSeconds` defaults to 120; the old `sleep` parameter has no alias.
  Execution remains indefinite by default. `-StopAfterSeconds` optionally limits
  duration. `-ReportIntervalSeconds` defaults to 3600; 0 disables periodic reports.
  Console clearing remains; resizing was removed. Captured color/title properties
  are restored in cleanup, but cleared history cannot be restored. One COM object
  is used, and initialization/input failures
  stop execution. The launcher resolves its own script path and forwards arguments.
- `components/scripts/caffeine-light.ps1`, version 0.1.0, is a separate standalone
  fallback. It intentionally has no parameters or time limit. It sends a pair
  immediately, then sleeps 60 seconds between pairs until Ctrl+C. It has only
  start/stop messages, no console customization, stopwatch or periodic reports,
  and no dependency on the full script or RIDE modules. Native `Get-Help` provides
  documentation and the version; the zero-parameter design is an explicit
  exception to the usual help/version/preview command-line switches.
- Both scripts use one `WScript.Shell` object and send
  `{SCROLLLOCK}{SCROLLLOCK}` in one call, with terminating operational errors and
  COM cleanup in `finally`. No explicit file, registry, startup or power-plan
  writes appear in their current operational code. This is source inspection,
  not proof that execution leaves no artifacts or uses less RAM.
- Zhorn Caffeine is a distinct executable product, catalog ID `package.caffeine`.
  Its x86/x64 executables and legacy installer are one product, not separate
  solutions. Catalog deployment does not automatically start it. See the
  [existing package evidence](archive/migrations/application-follow-up-2026-10-11.md).
- Arkane Mouse Jiggler remains an evaluation candidate, not an accepted new
  catalog package. Move Mouse was discussed but is outside this four-tool
  measurement request. Hardware jigglers are also outside the benchmark.

Neither script unlocks a locked session or guarantees that every lock mechanism
accepts its input. Keystrokes reach the foreground application. A pair reduces
the interruption window but is not atomic; interruption or concurrent input can
leave Scroll Lock changed. Forced process termination bypasses script cleanup.
PowerShell, Windows and security software may create execution artifacts.

## Usage and evaluation

Run `components/scripts/caffeine-light.cmd` for the fixed fallback. Use
`Get-Help .\components\scripts\caffeine.ps1 -Full` for full-script parameters
and examples. Launch helpers in the intended interactive desktop session; a
WinRM job does not establish foreground input or idle-lock prevention.

The [impact evaluation](screen-lock-impact.md) owns the comparison method,
current findings and remaining acceptance. Preliminary pilots do not establish
a relative memory/write ranking, artifact-free execution or complete target
support. Its acceptance table retains the outstanding controls, repetitions,
foreground/key-state and cleanup checks.

The [development record](archive/evidence/screen-lock-helper-development-2026-10-11.md)
retains implementation tests and earlier preparation history. Do not use its
dated VM state as a current execution instruction.
