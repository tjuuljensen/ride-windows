# MAC vendor lookup

`components/scripts/mac-vendor.ps1` looks up an IEEE registry assignee for a
MAC address or prefix. It is a standalone utility; it does not change Windows
network settings or require elevation. A registry assignee is not proof of a
device's manufacturer or authenticity.

From the repository root in PowerShell on Windows:

```powershell
.\components\scripts\mac-vendor.ps1 00:1A:2B:33:44:55
Get-Content -LiteralPath .\macs.txt | .\components\scripts\mac-vendor.ps1 -Offline
.\components\scripts\mac-vendor.ps1 -Update
.\components\scripts\mac-vendor.ps1 -Update -WhatIf
.\components\scripts\mac-vendor.ps1 -Quiet -Json 00-1A-2B
```

Use the `Get-Content` command for a file of addresses, one per line. A bare
string or comma-separated PowerShell array also works. With no addresses and no
pipeline, the script prompts for one. `-Help` gives quick usage;
`Get-Help .\components\scripts\mac-vendor.ps1 -Full` shows native help.

The script downloads public [IEEE registry CSV files](https://standards.ieee.org/products-programs/regauth/)
for MA-L (24 bits), MA-M (28 bits), MA-S (36 bits) and IAB (36 bits). It keeps
`ieee-mac-vendors.tsv` and `metadata.json` under `%LOCALAPPDATA%\mac-vendor`
by default. Use `-CacheDir <directory>` to select another folder, including a
cache shared with [mac-vendor.sh](https://github.com/tjuuljensen/linux-scripts/blob/master/mac-vendor.sh).
Online invocations refresh a cache older than seven days; `-MaxAgeDays` changes
that threshold. `-Update` forces a refresh, while `-Offline` requires an existing
cache and makes no network request. `-Update` and `-Offline` cannot be combined.
Each registry download has a 30-second timeout by default; use
`-TimeoutSeconds` to change it. Refresh builds files in the cache directory and
replaces the old cache only after all four registries parse successfully. If a
download or parse fails, rerun with `-Offline` to use the previous cache. To rebuild a
bad cache, remove this utility's two cache files and run `-Update`.

Lookups normalize common colon, hyphen, dotted and bare MAC formats, then choose
the longest matching prefix. They use only the local TSV: queried MAC addresses
are never sent to an online lookup service. Normal output shows the assignee,
registry and prefix; `-ShowAddress` adds the registry's address. `-Quiet` prints
only assignee names or `Unknown`. `-Json` prints one array with the query,
normalized value, match and local/multicast flags; combined with `-Quiet`, each
array item contains only `organization` (null when unknown).

Locally administered or randomized addresses and multicast addresses may have
no meaningful vendor match. The script is intended for Windows PowerShell 5.1
and PowerShell 7 on Windows. Parser, offline lookup and mocked refresh checks
have run under PowerShell 7 outside Windows; native Windows acceptance is still
pending.
