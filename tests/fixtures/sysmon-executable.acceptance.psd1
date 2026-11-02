# Retained Microsoft payload for disposable fixture preparation; no binary is distributed here.
@{
  SchemaVersion = 1
  SysmonVersion = '15.22'
  Executable = @{
    FileName = 'Sysmon64.exe'
    Bytes = 3203368
    Sha256 = '83D31F2478DC6716CFDBF69E5C384BF043072B5F0D8D7B2EEA365F709FDA4352'
    PeMachine = '0x8664'
    SignerThumbprint = 'CDCC1456D261BC0EB00975F46DFFB2E24592EDAD'
  }
  Notices = @(
    @{ FileName = 'Eula.txt'; Bytes = 7490; Sha256 = '8329BCBADC7F81539A4969CA13F0BE5B8EB7652B912324A1926FC9BFB6EC005A' }
    @{ FileName = 'readme.txt'; Bytes = 7903; Sha256 = '0F2FF4D516AA1D265C13805CEBC2FE9042556C1BB7E8EB2E6C289D5255242AC9' }
  )
  Source = @{
    CollectionId = 'sysinternals-suite'
    SnapshotId = 'snapshot-20261017-e1e75de5'
    ReviewPath = 'docs/archive/evidence/sysinternals-suite-source-review-2026-10-17.json'
    ArchiveSha256 = 'E1E75DE5CDB12116B0A4ECA83725DC7C7A1645266196025CBE5CA6C167161AED'
    DownloadUri = 'https://download.sysinternals.com/files/SysinternalsSuite.zip'
    ProductUri = 'https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon'
    LicenseUri = 'https://learn.microsoft.com/en-us/sysinternals/license-terms'
  }
}
