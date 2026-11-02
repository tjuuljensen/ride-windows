<#
.SYNOPSIS
  Verify machine-font lifecycle using inert files and mocked Windows writers.
.DESCRIPTION
  Uses real TestDrive bytes, private state, file ACLs and timestamps. Registry,
  target identity and all GDI/notification calls are mocked. Machine-state ACL
  providers use private current-user test files so no elevation is needed. No font is loaded.
.EXAMPLE
  Invoke-Pester ./tests/MachineFonts.Tests.ps1
.NOTES
  Pester 5, native PowerShell 5.1/7. Version: 0.1.0.
#>
BeforeDiscovery {Import-Module (Join-Path $PSScriptRoot '../modules/RIDE.MachineFonts.psm1') -Force}
Describe 'Machine font source identity' {
  BeforeAll {
    Import-Module (Join-Path $PSScriptRoot '../modules/RIDE.FontFiles.psm1') -Force
    . (Join-Path $PSScriptRoot 'fixtures/New-RideSyntheticTrueType.ps1')
  }
  It 'reads embedded names and a stable hash without trusting the filename or loading a font' {
    $path=Join-Path $TestDrive 'misleading-filename.ttf'
    [IO.File]::WriteAllBytes($path,(New-RideSyntheticTrueTypeBytes -Name 'RIDE Embedded Name'))
    $result=Get-RideTrueTypeMetadata -Path $path -ExpectedSha256 (Get-FileHash -LiteralPath $path).Hash
    $result.FullName|Should -BeExactly 'RIDE Embedded Name'
    $result.RegistryName|Should -BeExactly 'RIDE Embedded Name (TrueType)'
    $result.FontLoadPerformed|Should -BeFalse
    $result.InstallationPerformed|Should -BeFalse
    {Get-RideTrueTypeMetadata -Path $path -ExpectedSha256 ('0'*64)}|Should -Throw '*hash differs*'
  }
  It 'refuses ambiguous names, missing identities and out-of-bounds naming tables' {
    $path=Join-Path $TestDrive 'invalid.ttf'
    [IO.File]::WriteAllBytes($path,(New-RideSyntheticTrueTypeBytes -Ambiguous))
    {Get-RideTrueTypeMetadata -Path $path}|Should -Throw '*Ambiguous*'
    $bytes=New-RideSyntheticTrueTypeBytes;$bytes[76]=0;$bytes[77]=5
    [IO.File]::WriteAllBytes($path,$bytes)
    {Get-RideTrueTypeMetadata -Path $path}|Should -Throw '*identity is missing*'
    $bytes=New-RideSyntheticTrueTypeBytes;$bytes[20]=127
    [IO.File]::WriteAllBytes($path,$bytes)
    {Get-RideTrueTypeMetadata -Path $path}|Should -Throw '*outside the file*'
  }
}
Describe 'Owned machine-font lifecycle' {
  InModuleScope RIDE.MachineFonts {
    BeforeAll {. (Join-Path (Split-Path (Get-Module RIDE.MachineFonts).Path -Parent) '../tests/fixtures/New-RideSyntheticTrueType.ps1')}
    BeforeEach {
      $script:root=Join-Path $TestDrive ([guid]::NewGuid().ToString('N'))
      $script:fontRoot=Join-Path $script:root 'WindowsFonts';$script:stateRoot=Join-Path $script:root 'MachineState'
      $null=New-Item -ItemType Directory -Path $script:root,$script:fontRoot,$script:stateRoot
      $script:sourceA=Join-Path $script:root 'SyntheticA.ttf';$script:sourceB=Join-Path $script:root 'SyntheticB.ttf'
      [IO.File]::WriteAllBytes($script:sourceA,(New-RideSyntheticTrueTypeBytes -Name 'RIDE Synthetic A'))
      [IO.File]::WriteAllBytes($script:sourceB,(New-RideSyntheticTrueTypeBytes -Name 'RIDE Synthetic B'))
      $script:license=Join-Path $script:root 'LICENSE.txt';[IO.File]::WriteAllText($script:license,'Synthetic unit-test data only. Not a renderable font.')
      $script:manifest=Join-Path $script:root 'fonts.psd1'
      $data="@{SchemaVersion=1;Fonts=@(@{Path='SyntheticA.ttf';Sha256='"+(Get-FileHash $script:sourceA).Hash+"'},@{Path='SyntheticB.ttf';Sha256='"+(Get-FileHash $script:sourceB).Hash+"'});License=@{Path='LICENSE.txt';Sha256='"+(Get-FileHash $script:license).Hash+"'}}"
      [IO.File]::WriteAllText($script:manifest,$data)
      $script:registry=@{'Unrelated Font (TrueType)'=[pscustomobject]@{Name='Unrelated Font (TrueType)';Kind='String';Value='Unrelated.ttf'}}
      $script:native=[Collections.Generic.List[string]]::new()
      $script:context=[pscustomobject]@{ComputerName='RIDE-Synthetic-VM';Build='26300';EditionId='EnterpriseEval';Revision=9711;InstallationType='Client';NativeProcess=$true;Architecture='AMD64';UserSid='S-1-5-21-123-456-789-1001';SessionId=0;FontDirectory=$script:fontRoot;Administrator=$true}
      $script:selection=@{ManifestPath=$script:manifest;StateDirectory=$script:stateRoot;ExpectedComputerName='RIDE-Synthetic-VM';ExpectedBuild='26300';ExpectedEditionId='EnterpriseEval';AllowCandidate=$true;Confirm=$false}
      Mock Get-RideMachineFontContext {$script:context}
      Mock Get-RideMachineFontRegistry {[pscustomobject]@{Security='synthetic-unchanged-key-security';Rows=@($script:registry.Values|Sort-Object Name)}}
      Mock Set-RideMachineFontRegistration {param($Name,$FileName);$script:registry[$Name]=[pscustomobject]@{Name=$Name;Kind='String';Value=$FileName}}
      Mock Remove-RideMachineFontRegistration {param($Name);$script:registry.Remove($Name)}
      Mock Invoke-RideMachineFontNative {param($Action,$Path);$script:native.Add($Action)}
      Mock New-RideMachineFontStateStream {param($Path);New-RidePrivateFileStream -Path $Path}
      Mock Read-RideMachineFontStateBytes {param($Path);Read-RidePrivateFileBytes -Path $Path -MaximumBytes 16777216}
    }
    It 'installs, repeats, removes, restores removal and recovers initial absence without touching other fonts' {
      $installed=Install-RideMachineFonts @script:selection
      $installed.Status|Should -Be Applied
      $installed.ChangedFonts|Should -Be 2
      $intent=Read-RideMachineFontRun $script:stateRoot $installed.RunId intent
      $after=Read-RideMachineFontRun $script:stateRoot $installed.RunId applied
      $intent.License.Sha256|Should -Be (Get-FileHash $script:license).Hash
      (Get-Acl (Get-RideMachineFontRunPath $script:stateRoot $installed.RunId intent)).AreAccessRulesProtected|Should -BeTrue
      (Install-RideMachineFonts @script:selection).Status|Should -Be AlreadyDesired
      @($script:native|Where-Object {$_ -eq 'Add'}).Count|Should -Be 2
      $removed=Remove-RideMachineFonts -OwnerRunId $installed.RunId -StateDirectory $script:stateRoot -AllowCandidate -Confirm:$false
      $removed.Status|Should -Be Applied
      (Remove-RideMachineFonts -OwnerRunId $installed.RunId -StateDirectory $script:stateRoot -AllowCandidate -Confirm:$false).Status|Should -Be AlreadyAbsent
      (Restore-RideMachineFontRun -RunId $removed.RunId -StateDirectory $script:stateRoot -AllowCandidate -Confirm:$false).Status|Should -Be Restored
      $registry=Get-RideMachineFontRegistry
      $current=@(foreach($entry in $intent.Entries){Get-RideMachineFontSnapshot $script:context $entry $registry})
      Test-RideMachineFontEqual $current @($after.After)|Should -BeTrue
      (Restore-RideMachineFontRun -RunId $installed.RunId -StateDirectory $script:stateRoot -AllowCandidate -Confirm:$false).Status|Should -Be Restored
      (Restore-RideMachineFontRun -RunId $installed.RunId -StateDirectory $script:stateRoot -AllowCandidate -Confirm:$false).Status|Should -Be AlreadyRestored
      @(Get-ChildItem -LiteralPath $script:fontRoot -File).Count|Should -Be 0
      $script:registry.Count|Should -Be 1
      $script:registry['Unrelated Font (TrueType)'].Value|Should -BeExactly 'Unrelated.ttf'
    }
    It 'preflights the whole batch before the first write and never replaces a colliding font' {
      $target=Join-Path $script:fontRoot 'SyntheticB.ttf';[IO.File]::WriteAllText($target,'unrelated existing bytes')
      {Install-RideMachineFonts @script:selection}|Should -Throw '*whole batch is refused*'
      Test-Path (Join-Path $script:fontRoot 'SyntheticA.ttf')|Should -BeFalse
      [IO.File]::ReadAllText($target)|Should -BeExactly 'unrelated existing bytes'
      @(Get-ChildItem -LiteralPath $script:stateRoot -File).Count|Should -Be 0
      $script:native.Count|Should -Be 0
      $script:selection.StateDirectory=Join-Path $script:root 'missing-state'
      {Install-RideMachineFonts @script:selection -WhatIf}|Should -Throw '*existing local directory*'
    }
    It 'preserves existing matching fonts without adopting them into removal ownership' {
      [IO.File]::Copy($script:sourceA,(Join-Path $script:fontRoot 'SyntheticA.ttf'))
      $script:registry['RIDE Synthetic A (TrueType)']=[pscustomobject]@{Name='RIDE Synthetic A (TrueType)';Kind='String';Value='SyntheticA.ttf'}
      $installed=Install-RideMachineFonts @script:selection
      $installed.ChangedFonts|Should -Be 1
      $removed=Remove-RideMachineFonts -OwnerRunId $installed.RunId -StateDirectory $script:stateRoot -AllowCandidate -Confirm:$false
      $removed.ChangedFonts|Should -Be 1
      Test-Path (Join-Path $script:fontRoot 'SyntheticA.ttf')|Should -BeTrue
      $script:registry.ContainsKey('RIDE Synthetic A (TrueType)')|Should -BeTrue
    }
    It 'refuses registration aliases and destination directory collisions before writing' {
      $script:registry['Foreign alias']=[pscustomobject]@{Name='Foreign alias';Kind='String';Value='SyntheticB.ttf'}
      {Install-RideMachineFonts @script:selection}|Should -Throw '*collision*'
      $script:registry.Remove('Foreign alias')
      $null=New-Item -ItemType Directory -Path (Join-Path $script:fontRoot 'SyntheticB.ttf')
      {Install-RideMachineFonts @script:selection}|Should -Throw '*directory collides*'
      $script:native.Count|Should -Be 0
    }
    It 'validates source and license hashes and rejects duplicate selected identities' {
      $original=[IO.File]::ReadAllText($script:manifest)
      [IO.File]::WriteAllText($script:manifest,$original.Replace('SchemaVersion=1;',"SchemaVersion=1;Scope='User';"))
      {Install-RideMachineFonts @script:selection}|Should -Throw '*manifest schema*'
      [IO.File]::WriteAllText($script:manifest,$original)
      [IO.File]::AppendAllText($script:license,' changed')
      {Install-RideMachineFonts @script:selection}|Should -Throw '*License source hash differs*'
      [IO.File]::WriteAllBytes($script:sourceB,(New-RideSyntheticTrueTypeBytes -Name 'Changed identity'))
      {Install-RideMachineFonts @script:selection}|Should -Throw '*Font source hash differs*'
      $data=[IO.File]::ReadAllText($script:manifest).Replace('SyntheticB.ttf','SyntheticA.ttf').Replace((Get-RideFontHash (New-RideSyntheticTrueTypeBytes -Name 'RIDE Synthetic B')),(Get-FileHash $script:sourceA).Hash)
      [IO.File]::WriteAllText($script:manifest,$data)
      {Install-RideMachineFonts @script:selection}|Should -Throw '*duplicate font identities*'
      $script:native.Count|Should -Be 0
    }
    It 'previews without elevation or file, registration and journal changes' {
      $script:context.Administrator=$false;$script:selection.AllowCandidate=$false
      Install-RideMachineFonts @script:selection -WhatIf
      @(Get-ChildItem -LiteralPath $script:fontRoot -File).Count|Should -Be 0
      @(Get-ChildItem -LiteralPath $script:stateRoot -File).Count|Should -Be 0
      $script:registry.Count|Should -Be 1
      $script:native.Count|Should -Be 0
    }
    It 'refuses candidate, privilege and target mismatches before a writer' {
      $script:selection.AllowCandidate=$false
      {Install-RideMachineFonts @script:selection}|Should -Throw '*AllowCandidate*'
      $script:selection.AllowCandidate=$true;$script:context.Administrator=$false
      {Install-RideMachineFonts @script:selection}|Should -Throw '*existing elevation*'
      $script:context.Administrator=$true;$script:selection.ExpectedBuild='26100'
      {Install-RideMachineFonts @script:selection}|Should -Throw '*target differs*'
      $script:native.Count|Should -Be 0
    }
    It 'refuses changed bytes instead of overwriting them during recovery' {
      $installed=Install-RideMachineFonts @script:selection
      $target=Join-Path $script:fontRoot 'SyntheticA.ttf'
      [IO.File]::AppendAllText($target,' foreign edit')
      {Remove-RideMachineFonts -OwnerRunId $installed.RunId -StateDirectory $script:stateRoot -AllowCandidate -Confirm:$false}|Should -Throw '*changed*'
      {Restore-RideMachineFontRun -RunId $installed.RunId -StateDirectory $script:stateRoot -AllowCandidate -Confirm:$false}|Should -Throw '*recovery conflict*'
      [IO.File]::ReadAllText($target)|Should -Match 'foreign edit'
      @($script:native|Where-Object {$_ -eq 'Remove'}).Count|Should -Be 0
    }
    It 'refuses changed file permissions without repairing or deleting the font' {
      $installed=Install-RideMachineFonts @script:selection
      $target=Join-Path $script:fontRoot 'SyntheticA.ttf'
      $acl=Get-Acl -LiteralPath $target;$acl.SetAccessRuleProtection($true,$true);Set-Acl -LiteralPath $target -AclObject $acl
      {Remove-RideMachineFonts -OwnerRunId $installed.RunId -StateDirectory $script:stateRoot -AllowCandidate -Confirm:$false}|Should -Throw '*permissions or registration changed*'
      {Restore-RideMachineFontRun -RunId $installed.RunId -StateDirectory $script:stateRoot -AllowCandidate -Confirm:$false}|Should -Throw '*recovery conflict*'
      (Get-Acl -LiteralPath $target).AreAccessRulesProtected|Should -BeTrue
      @($script:native|Where-Object {$_ -eq 'Remove'}).Count|Should -Be 0
    }
    It 'refuses changed registry value kinds and values instead of treating them as owned' {
      $installed=Install-RideMachineFonts @script:selection
      $script:registry['RIDE Synthetic A (TrueType)'].Kind='ExpandString'
      {Remove-RideMachineFonts -OwnerRunId $installed.RunId -StateDirectory $script:stateRoot -AllowCandidate -Confirm:$false}|Should -Throw '*changed*'
      $script:registry['RIDE Synthetic A (TrueType)'].Kind='String';$script:registry['RIDE Synthetic A (TrueType)'].Value='Foreign.ttf'
      {Restore-RideMachineFontRun -RunId $installed.RunId -StateDirectory $script:stateRoot -AllowCandidate -Confirm:$false}|Should -Throw '*recovery conflict*'
      @($script:native|Where-Object {$_ -eq 'Remove'}).Count|Should -Be 0
    }
    It 'retains intent and reports a run ID after partial write without inventing a completed run' {
      Mock Invoke-RideMachineFontNative {param($Action,$Path);if($Action -eq 'Add'){throw 'synthetic load failure'}}
      {Install-RideMachineFonts @script:selection}|Should -Throw '*Run ID:*Retain private state*'
      @(Get-ChildItem -LiteralPath $script:stateRoot -Filter '*.intent.json').Count|Should -Be 1
      @(Get-ChildItem -LiteralPath $script:stateRoot -Filter '*.applied.json').Count|Should -Be 0
      Test-Path (Join-Path $script:fontRoot 'SyntheticA.ttf')|Should -BeTrue
      Test-Path (Join-Path $script:fontRoot 'SyntheticB.ttf')|Should -BeFalse
    }
    It 'does not write fonts if private intent persistence fails' {
      Mock Save-RideMachineFontRun {throw 'synthetic state-write failure'}
      {Install-RideMachineFonts @script:selection}|Should -Throw '*state-write failure*'
      @(Get-ChildItem -LiteralPath $script:fontRoot -File).Count|Should -Be 0
      $script:native.Count|Should -Be 0
    }
    It 'retains files and registration when native unloading cannot be confirmed' {
      $installed=Install-RideMachineFonts @script:selection
      Mock Invoke-RideMachineFontNative {throw 'Synthetic active font consumer'} -ParameterFilter {$Action -eq 'Remove'}
      {Remove-RideMachineFonts -OwnerRunId $installed.RunId -StateDirectory $script:stateRoot -AllowCandidate -Confirm:$false}|Should -Throw '*removal did not complete*'
      Test-Path (Join-Path $script:fontRoot 'SyntheticA.ttf')|Should -BeTrue
      Test-Path (Join-Path $script:fontRoot 'SyntheticB.ttf')|Should -BeTrue
      $script:registry.ContainsKey('RIDE Synthetic A (TrueType)')|Should -BeTrue
      $script:registry.ContainsKey('RIDE Synthetic B (TrueType)')|Should -BeTrue
      Should -Invoke Remove-RideMachineFontRegistration -Times 0 -Exactly
      @(Get-ChildItem -LiteralPath $script:stateRoot -Filter '*.intent.json').Count|Should -Be 2
      @(Get-ChildItem -LiteralPath $script:stateRoot -Filter '*.applied.json').Count|Should -Be 1
    }
    It 'requires fresh candidate approval and unchanged target context for recovery' {
      $installed=Install-RideMachineFonts @script:selection
      {Restore-RideMachineFontRun -RunId $installed.RunId -StateDirectory $script:stateRoot -Confirm:$false}|Should -Throw '*fresh -AllowCandidate*'
      $script:context.Revision++
      {Restore-RideMachineFontRun -RunId $installed.RunId -StateDirectory $script:stateRoot -AllowCandidate -Confirm:$false}|Should -Throw '*context drift*'
      @($script:native|Where-Object {$_ -eq 'Remove'}).Count|Should -Be 0
    }
    It 'completes saved run IDs without reading records or inspecting live font state' {
      $installed=Install-RideMachineFonts @script:selection
      Mock Read-RideMachineFontRun {throw 'Completion must not read records'}
      Mock Get-RideMachineFontRegistry {throw 'Completion must not inspect Windows'}
      $matches=@(& $script:FontRunCompleter 'Restore-RideMachineFontRun' RunId $installed.RunId.Substring(0,5) $null @{StateDirectory=$script:stateRoot})
      $matches.Count|Should -Be 1
      $matches[0].CompletionText|Should -BeExactly $installed.RunId
    }
  }
}

Describe 'Machine private-state security contract' {
  InModuleScope RIDE.PrivateFiles {
    It 'uses Administrators ownership and only Administrators and SYSTEM full access' {
      $security=New-RidePrivateFileSecurity -Scope Machine
      $security.AreAccessRulesProtected|Should -BeTrue
      $security.GetOwner([Security.Principal.SecurityIdentifier]).Value|Should -BeExactly 'S-1-5-32-544'
      $rules=@($security.GetAccessRules($true,$true,[Security.Principal.SecurityIdentifier]))
      $rules.Count|Should -Be 2
      @($rules.IdentityReference.Value|Sort-Object)|Should -Be @('S-1-5-18','S-1-5-32-544')
      @($rules|Where-Object {$_.AccessControlType -ne 'Allow' -or $_.FileSystemRights -ne 'FullControl' -or $_.IsInherited}).Count|Should -Be 0
    }
  }
}
