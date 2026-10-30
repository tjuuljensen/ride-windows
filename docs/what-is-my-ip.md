# Public IP comparison

`components/scripts/whatismyip.ps1` compares the public IPv4 and IPv6 addresses
reported by DNS and HTTPS providers with the local source address chosen by
the routing table. It is a standalone, read-only network diagnostic for
PowerShell on Windows. No elevation or extra executable is required.

From the repository root in PowerShell on Windows:

```powershell
.\components\scripts\whatismyip.ps1
.\components\scripts\whatismyip.ps1 -IPv4 -Quiet
.\components\scripts\whatismyip.ps1 -IPv6 -Json
.\components\scripts\whatismyip.ps1 -Json -Debug
.\components\scripts\whatismyip.ps1 -NoIpify -Verbose
```

`-IPv4` and `-IPv6` each select one family; without either, both are checked.
`-Quiet` prints only resolved public addresses, one per line. `-Json` emits a
single result object; with `-Quiet`, it contains only available `ipv4` and
`ipv6` keys. `-Json -Debug` adds provider statuses, options and warnings.
`-Verbose` gives progress in text mode and does not change JSON. Use `-Help`
for quick usage, `-Version` for the script version, or
`Get-Help .\components\scripts\whatismyip.ps1 -Full` for native help.

The DNS providers use the Windows `Resolve-DnsName` command: OpenDNS for IPv4
and Google DNS TXT for IPv4 and IPv6. HTTPS uses the
[ipify endpoints](https://www.ipify.org/) for each family. `-NoIpify`
(`-NoHttps` is an alias) disables those HTTPS requests. If `Resolve-DnsName`
is unavailable, DNS providers are skipped. At least one public-IP method must
be available and enabled. Provider failures do not stop the other checks.
`-TimeoutSeconds` controls HTTPS requests (default 8); DNS uses Windows' quick
timeout behavior. DNS resolution inside an HTTPS request can exceed a shorter
PowerShell timeout.

The local route source is selected by connecting a UDP socket to an IP address
without sending a datagram. It may be a private address and is never counted
as a public provider. The script makes DNS queries and HTTPS requests to the
named providers, which can see the network egress used for those queries.
Proxy, VPN, split tunneling and IPv4/IPv6 routing may make the views differ.
No files or Windows settings are changed, so no recovery step is needed.

One successful public provider yields `single_provider`. Two or more matching
providers yield `consistent`; conflicting results yield `provider_mismatch`.
`consistent` is null in JSON when fewer than two public providers succeeded.
When providers disagree, `public` is the first sorted distinct value for
compatibility with [whatismyip.sh](https://github.com/tjuuljensen/linux-scripts/blob/master/whatismyip.sh);
inspect `values` and the provider fields before treating it as definitive.
The script is intended for Windows PowerShell 5.1 and PowerShell 7 on Windows.
Parser and mocked provider checks have run under PowerShell 7 outside Windows;
native Windows acceptance remains pending.
