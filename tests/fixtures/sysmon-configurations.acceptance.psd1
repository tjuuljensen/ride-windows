@{
  SchemaVersion = 1
  ReleaseTag = 'configs-a45dedb13a43'
  TargetSysmonVersion = '15.21'
  License = @{ Path = 'license.md'; Sha256 = 'FD80A26FBB3F644AF1FA994134446702932968519797227E07A1368DEA80F0BC' }
  Configurations = @(
    @{ ArtifactId = 'sysmon-modular-balanced-15-21'; Path = 'sysmon-modular-balanced-15-21/a45dedb13a43/sysmonconfig.xml'; Sha256 = '64BEC37BA849C5F2934A55D2A29E7DDFAE46A30D56F7F2908D1F8A454898797E' }
    @{ ArtifactId = 'sysmon-modular-balanced-filedelete-15-21'; Path = 'sysmon-modular-balanced-filedelete-15-21/a45dedb13a43/sysmonconfig-with-filedelete.xml'; Sha256 = 'A7832F4423AAE16E39342E08F3A2962291EAFB7972EB9DFB070009781FDE50D9' }
    @{ ArtifactId = 'sysmon-modular-excludes-only-15-21'; Path = 'sysmon-modular-excludes-only-15-21/a45dedb13a43/sysmonconfig-excludes-only.xml'; Sha256 = '4C7D27BC2847F7DE816DDDE90E7DE37D5B9473461B27424882E9B93F00CD28A4' }
  )
}
