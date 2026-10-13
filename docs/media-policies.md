# Conditional media policies

Two experimental operations retain separate omitted components of the legacy
`DisableMediaOnlineAccess` / `EnableMediaOnlineAccess` bundle. Neither appears in
recommended profiles or the metadata-only outcome guidance. Normal apply is
blocked because supported targets remain empty.

| Operation | Physical scope and value | Policy |
| --- | --- | --- |
| `windows.media-radio-preset-retrieval-policy` | Current user, no administrator; `HKCU\SOFTWARE\Policies\Microsoft\WindowsMediaPlayer\PreventRadioPresetsRetrieval` | Prevent Radio Station Preset Retrieval |
| `windows.media-drm-online-access-policy` | Machine, administrator; `HKLM\SOFTWARE\Policies\Microsoft\WMDRM\DisableOnline` | Prevent Windows Media DRM Internet Access |

Both use `Blocked=1`, `PolicyDisabled=0` and `WindowsDefault` for value removal.
Enabling these negatively worded policies blocks the declared behavior; disabling
the policy is an explicit value and differs from removal. The legacy reverse
removed overrides. Saved-run restore preserves the literal prior value, type or
absence; it does not reconstruct licenses or remote services. Normal discovery
shows local configured policy, with effective policy/source explicitly uninspected.

The [radio policy reference](https://learn.microsoft.com/en-us/windows/client-management/mdm/policy-csp-admx-windowsmediaplayer#preventradiopresetsretrieval)
describes preset retrieval and display/update effects, rather than generic app
radio privacy or all Windows Media Player network access. The installed
`WindowsMediaPlayer.admx` declares **pre-Vista** applicability for this policy,
while the CSP lists Windows 11 policy delivery. Policy delivery and template
presence do not establish a working current radio feature. Missing components
are not automatically installed or interpreted as successful suppression.

The [DRM policy reference](https://learn.microsoft.com/en-us/windows/client-management/mdm/policy-csp-admx-windowsmediadrm#disableonline)
describes Windows Media DRM Internet/intranet access for licenses, security
upgrades and license restoration. Blocking can prevent these functions; it is
not a universal PlayReady/media/network block and does not assert that content
with an existing local license stops playing. WMDRM deprecation is not evidence
that every current Windows installation lacks all consuming backends. Current
component and service availability remain acceptance requirements. No playback,
license acquisition, security-component update or license-store change is run by
these operations or local tests.

## Mapping evidence and remaining acceptance

Read-only local templates on build 26200.9550 confirmed both DWORD mappings,
their User/Machine classes, enabled value 1 and disabled value 0:

| Template | SHA-256 |
| --- | --- |
| `WindowsMediaPlayer.admx` | `3245240CFC768E6660176A1C7E83C2B15A9E6F9E3F21BED98940D9413D655FB7` |
| `WindowsMediaDRM.admx` | `90EA32ED96670418A3376811075AD783B78A4DECF992CEA99CEA8B7249ADAF9A` |

These are source-mapping evidence only. Current player/backend effects,
intended-user execution, effective managed precedence, partial failure, GUI,
content consequences and exact typed recovery still require target acceptance.
Windows 11 is a candidate; Home and Server support are not declared. Microsoft
lists policy delivery for Pro, Enterprise, Education and IoT Enterprise. Local
configuration needs no extra RIDE/cloud subscription; content licenses and
external service availability are separate requirements. Disposable VM tests
remain held for manual user confirmation. No broad retirement or completed
legacy-bundle claim is made from registry round trips.
