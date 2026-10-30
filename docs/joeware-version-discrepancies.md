# JoeWare version and archive discrepancies

This record tracks differences among the JoeWare product pages, its collection
version list, and downloaded archives. JoeWare acquisition follows the latest
version currently offered for each selected product; it does not pin a
collection-wide release. Record the source pages and observed version at each
acquisition so the downloaded bytes remain attributable.

## JoeWare selected-product DNS acquisition preflight, 2026-10-28 19:55 UTC

A read-only `Resolve-DnsName -Name www.joeware.net -Type A` attempt returned `Access is denied.` The selected UserDump, DNSSrvRec and ELDLLEx archives were not requested; no bytes or files were received. AdFind remains excluded. Exact archive identity and selected-product lifecycle remain deferred pending publisher DNS access.

See [DNS preflight evidence](archive/evidence/joeware-selected-source-dns-preflight-block-2026-10-28-1955.json).
## 2026-10-28 official page and version-list recheck, 19:54 UTC

The current available official `versions.txt` snapshot remains marked Updated 2023.05.06. The UserDump product page still says Current Version 1.01.00 while its Version History separately lists 2.02.00 on the same date; `versions.txt` lists 01.01.00. DNSSrvRec's product page says January 15, 2005, whereas `versions.txt` says January 15, 2006 and its usage page identifies January 2006. ELDLLEx's `versions.txt` row still says 01.00.00 dated February 17, 2002 with no digests, while the usage page identifies ELDLLExInstall V01.00.00cpp in July 2004; the product page could not be fetched in this recheck. Preserve the existing discrepancies. No artifacts were downloaded, and no product version or archive identity was inferred. See [recheck evidence](archive/evidence/joeware-download-preview-winps51-and-version-source-recheck-2026-10-28-1954.json).

Sources: [UserDump page](https://www.joeware.net/freetools/tools/userdump/index.htm), [DNSSrvRec page](https://joeware.net/freetools/tools/dnssrvrec/index.htm), [DNSSrvRec usage](https://joeware.net/freetools/tools/dnssrvrec/usage.htm), [ELDLLEx usage](https://joeware.net/freetools/tools/eldllex/usage.htm), [JoeWare version list](https://www.joeware.net/freetools/versions.txt).
## `rdp-sec-check`

The publisher product and usage pages identify the currently offered download
as version `0.9-beta` / JoeWare `V02.00.00`, dated 2014-11-17. The publisher's
`versions.txt` row remains `V01.00.00`, dated 2011-02-11, with MD5
`835b662d44b251dfd0c89c51da3da63d` and SHA-1
`9a6bde20e329d57456d35917c5a1d9cdcaf915ac`. These are distinct version
observations; do not associate the older digests with V02.00.00.

The exact download archive has not yet been acquired or inspected. On the next
authorized acquisition, record the response URL, filename, size and SHA-256;
inspect the archive's file list and version-bearing content without executing
the included executable. If the response or ZIP content differs from the
product-page identity, add the observed difference here and add a short warning
to the corresponding package description. Preserve the observed bytes and
source response as evidence. Do not silently relabel the artifact or discard
the discrepancy.

Sources:

- [JoeWare product page](https://joeware.net/freetools/tools/rdp-sec-check/index.htm)
- [JoeWare usage page](https://joeware.net/freetools/tools/rdp-sec-check/usage.htm)
- [JoeWare version list](https://joeware.net/freetools/versions.txt)
- [JoeWare update note for V02.00.00](https://blog.joeware.net/2014/11/17/5553/)

Current source reconciliation evidence: [2026-10-24 review](archive/evidence/joeware-rdp-sec-check-current-version-reconciliation-2026-10-24-0724.json).

## `UserDump`, `DNSSrvRec` and `ELDLLEx`

The official UserDump page's Current Version section says `1.01.00`, dated
January 28, 2001, and the publisher's `versions.txt` row independently agrees
with `01.01.00` and the date. The page's Version History lists `1.00.00` on
April 13, 2000 as the original, then `2.02.00` on January 28, 2001 with
"Added banner". Preserve this internal version conflict; do not infer the
version from the change note. The version list records executable MD5
`a14ac214dd83ecf75c5032ba1098c416` and SHA-1
`d263cd402c4d203c17aa0274c9082ddbac1240b3`; these are not archive SHA-256
evidence. The page describes enumerating account status fields on a specified
NT-based machine and lists only Windows NT, Windows 2000, Windows Server 2003
and Windows XP. Those legacy platforms are not RIDE support declarations. Do
not assign an exact archive identity until the ZIP is acquired and its inert
contents are reviewed.

The DNSSrvRec product page's official snapshot says version `1.00.00` dated
January 15, 2005. The publisher's `versions.txt` row says `01.00.00` dated
January 15, 2006, with MD5 `2d36802ffe70e3328e62dd3094123af2` and SHA-1
`a25663bf9db368247aba79ef381830943932f1da`. The usage page labels the utility
`AddSrvRec V01.00.00cpp` January 2006. The one-year date difference is confirmed
across the publisher's product, digest-list and usage pages. Preserve it as a
source discrepancy; matching version digits and executable digests do not
identify or verify exact ZIP bytes.

The publisher's Current Version section records ELDLLEx `1.00.0` dated
February 17, 2002, matching the version-list row `01.00.00` on that date after
numeric formatting; the row contains no publisher MD5/SHA-1 values. The same
product page's Version History lists `1.00.00` dated July 1, 2004 as the
original, and the usage page identifies `ELDLLExInstall V01.00.00cpp` in July
2004. Preserve both date observations rather than inferring an archive version.
The usage page documents a two-DLL event-source installation/removal model.
Require exact archive/member evidence before registration.

Sources:

- [UserDump product page](https://www.joeware.net/freetools/tools/userdump/index.htm)
- [DNSSrvRec product page](https://www.joeware.net/freetools/tools/dnssrvrec/index.htm)
- [ELDLLEx product page](https://www.joeware.net/freetools/tools/eldllex/index.htm)
- [JoeWare version list](https://www.joeware.net/freetools/versions.txt)
- [DNSSrvRec usage page](https://joeware.net/freetools/tools/dnssrvrec/usage.htm)
- [ELDLLEx usage page](https://joeware.net/freetools/tools/eldllex/usage.htm)

Current source evidence: [2026-10-28 publisher page and version-list reconciliation](archive/evidence/joeware-administration-version-source-reconciliation-2026-10-28-0610.json), [2026-10-28 version-list recheck](archive/evidence/joeware-version-list-administration-tools-recheck-2026-10-28-0534.json), [2026-10-28 detail review](archive/evidence/joeware-administration-tools-source-review-2026-10-28-0350.json), [2026-10-27 UserDump page recheck](archive/evidence/joeware-userdump-dnssrvrec-eldllex-source-recheck-2026-10-27-2132.json), [2026-10-28 current page/acquisition recheck](archive/evidence/joeware-userdump-current-source-and-acquisition-recheck-2026-10-28-1142.json), and [2026-10-28 acquisition retry/DNS blocker](archive/evidence/joeware-userdump-acquisition-dns-retry-2026-10-28-1154.json).
