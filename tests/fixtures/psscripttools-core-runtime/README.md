# Optional PSScriptTools Core runtime fixture

The disposable Windows PSScriptTools scenario can use the exact publisher
`PowerShell-7.6.5-win-x64.zip` staged in this directory when the guest has no
`pwsh.exe`. Obtain it from the
[PowerShell 7.6.5 release](https://github.com/PowerShell/PowerShell/releases/tag/v7.6.5).
The ZIP is a local test input; do not commit it or include it in RIDE releases.

Expected SHA-256:
`32EB8F6CDCE08F86E987D625A2733E54AC3E289AE7E1621B14C0B5BCEC2434EA`.
It has 106,319,290 bytes, 661 ZIP entries and 256,592,846 expanded bytes.
The guest verifies these bounds, paths, upstream notices, Microsoft signature
and executable version before launching it. No download fallback, installation,
machine PATH edit or persistent module registration occurs.

Stage only for the selected PSScriptTools run from the repository root. The host
captures this input in its source snapshot. The guest expands into the fresh
`C:\RIDE\PortableAcceptance\<run-id>\core-runtime` directory, outside exported
runtime evidence. Evidence records its identity and runtime results. Verified
checkpoint reset recovers the fixture; it is not a package-installation result.
After the run and snapshot complete, remove only the locally staged ZIP.
