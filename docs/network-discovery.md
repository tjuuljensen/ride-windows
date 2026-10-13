# Network discovery

Use native Windows 11 controls to review discovery for the intended network.
This handoff is separate from the retired Computer Browser `Hidden` selectors;
their existing values remain untouched. A maintained discovery backend and
bounded saved-run recovery remain pending.

## Select the connected network and profile

Open **Settings > Network & internet** and identify the intended Wi-Fi or
Ethernet connection and its current network profile. Review other active
connections, including VPN/virtual adapters; a PC can participate in more than
one network. Do not assume one profile switch describes every connection.

Only choose Private when the connected network and its devices are trusted and
discovery/sharing is intended. Public remains appropriate for untrusted networks.
A work/domain-managed category or policy is not an invitation to reclassify it.
Use the organization's network administrator when the required choice is managed
or unavailable. Microsoft documents the connection-specific public/private
selection in [essential network settings](https://support.microsoft.com/en-us/windows/experience/connectivity-networking/essential-network-settings-and-tasks-in-windows).

Connection categories and discovery/sharing controls affect machine networking;
they are not merely a private preference of the person opening Settings. Changes
may require administrator authorization and affect other users of that PC.
Record the connection and profile before any manual change, and preserve unrelated
adapters/profile choices. No extra RIDE account, cloud subscription or domain join
is required for this native handoff.

## Change only the intended discovery control

Open the native **Advanced sharing settings** through Network & internet
(**Advanced network settings** on Windows 11 layouts that expose it there).
Find the intended profile section and review **Network discovery** before
selecting its desired On or Off state. Verify labels on the installed build;
missing or managed controls remain unavailable/pending. This is a deliberate
manual action, not a RIDE apply or saved-run restore.

Discovery allows devices to find one another; it does not by itself grant a
particular user access to a folder/printer or establish authenticated sharing.
Microsoft's [file-sharing guidance](https://support.microsoft.com/en-us/windows/experience/connectivity-networking/file-sharing-over-a-network-in-windows)
describes discovery and sharing as separate parts of setup. This focused handoff
does not reproduce its broader troubleshooting recipe. Keep file/printer sharing,
password-protected sharing, public-folder sharing and automatic device setup at
their prior values unless separately selected and reviewed. No Everyone grant,
guest access, SMB1 installation or sharing-service startup change is implied.

Turning discovery Off is not a network-invisibility guarantee, a disconnect or
removal of existing shares. Other protocols, configured firewall rules and
authorized direct connections have their own behavior. Stopping SMB hosting,
protocol bindings, NetBIOS and inbound access are separate migration outcomes.

## Verify the selected outcome

Keep Windows Firewall enabled. The [profile controls](firewall-profiles.md)
separate local configuration from effective managed policy; changing a profile's
Enabled flag is not configuration of discovery rules. Do not disable the firewall
or enable broad rule wildcards as a troubleshooting shortcut.

Use a known peer on the selected network in an authorized acceptance environment
and record discovery On/Off results separately from an authenticated connection
to an explicitly selected share. Verify the active connection/profile, local
versus managed settings, GUI refresh and effect on unrelated profiles/users. A
GUI toggle or registry round trip alone does not establish this outcome.

If discovery is blocked by policy, missing services/components or network
isolation, record that condition rather than automatically modifying prerequisites.
Returning a manually recorded toggle does not undo share access, transferred
files or every possible side effect. A future handler needs captured bounded
configuration, dependency/partial-failure reporting and conflict-aware recovery.

Actual peer, profile, multi-user and Server/Core applicability evidence remains
pending in the [remaining settings ledger](migrations/remaining-settings-decisions.md).
The native handoff adds no equivalent Hidden mapping or supported target.
