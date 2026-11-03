<#
.SYNOPSIS
  Verify retained first-logon wallpaper guest phases without changing Windows policy.
.DESCRIPTION
  Mocks guest identity, lifecycle, machine directories and native snapshots.
  Private report bytes are real TestDrive files with current-user-only test ACLs.
.EXAMPLE
  Invoke-Pester ./tests/DefaultWallpaperAcceptance.Tests.ps1
.NOTES
  Native PowerShell 5.1/7 and Pester 5. Version: 0.1.0.
#>
BeforeDiscovery {Import-Module (Join-Path $PSScriptRoot 'integration/RIDE.DefaultWallpaperAcceptance.psm1') -Force}
Describe 'Retained first-logon wallpaper guest acceptance phases' {
  InModuleScope RIDE.DefaultWallpaperAcceptance {
    BeforeEach {
      $script:id=[guid]::NewGuid().ToString('N');$script:ownerId='1'*32
      $script:root=Join-Path $TestDrive ([guid]::NewGuid().ToString('N').Substring(0,8));$null=New-Item -ItemType Directory -Path $script:root
      $script:directory=Join-Path $script:root $script:id
      $script:assetPath=Join-Path (Join-Path $script:directory 'images') ($script:ownerId+'.png')
      $script:themePath=[IO.Path]::ChangeExtension($script:assetPath,'theme')
      $script:theme=& (Get-Module RIDE.DefaultWallpaper) {param($p) New-RideDefaultWallpaperTheme $p} $script:assetPath
      $script:applyParameters=@{Phase='Apply';RunId=$script:id;SourcePath='synthetic-source.png';ExpectedComputerName='RIDE-Synthetic-VM';ExpectedBuild='26300';ExpectedEditionId='EnterpriseEval';EvidenceRoot=$script:root;DisposableVm=$true;Confirm=$false}
      $script:restoreParameters=@{Phase='Restore';RunId=$script:id;ExpectedComputerName='RIDE-Synthetic-VM';ExpectedBuild='26300';ExpectedEditionId='EnterpriseEval';EvidenceRoot=$script:root;DisposableVm=$true;Confirm=$false}
      $script:context=[pscustomobject]@{ComputerName='RIDE-Synthetic-VM';Build='26300';EditionId='EnterpriseEval';Revision=9711;InstallationType='Client';NativeProcess=$true;Architecture='AMD64';Guest=$true;Administrator=$true;RunMarker=$script:id}
      $script:source=[pscustomobject]@{Path='synthetic-source.png';Sha256=('A'*64);Bytes=100;Width=2;Height=3}
      $script:active=$false;$script:restoreFailure=$false;$script:events=[Collections.Generic.List[string]]::new()
      Mock Get-RideDefaultWallpaperAcceptanceContext {$script:context}
      Mock Assert-RideDefaultWallpaperAcceptanceRoot {param($Path);[IO.Path]::GetFullPath($Path)}
      Mock Read-RideDefaultWallpaperAcceptanceSource {$script:source}
      Mock New-RideDefaultWallpaperAcceptanceDirectory {param($Path,$PublicRead);$null=New-Item -ItemType Directory -Path $Path}
      Mock New-RidePrivateFileStream {param($Path,$Scope);if($Scope -cne 'Machine'){throw 'Machine scope required.'};& (Get-Module RIDE.PrivateFiles) {param($p) New-RidePrivateFileStream -Path $p -Scope User} $Path}
      Mock Read-RidePrivateFileBytes {param($Path,$Scope,$MaximumBytes);if($Scope -cne 'Machine'){throw 'Machine scope required.'};& (Get-Module RIDE.PrivateFiles) {param($p,$max) Read-RidePrivateFileBytes -Path $p -Scope User -MaximumBytes $max} $Path $MaximumBytes}
      Mock Assert-RideDefaultWallpaperAcceptanceRecords {}
      Mock Get-RideDefaultWallpaperAcceptanceSnapshot {
        if($script:active){[pscustomobject]@{Registry='applied';PolicyValue=$script:themePath;File=[pscustomobject]@{Sha256=('A'*64);Bytes=100};Theme=$script:theme;Profiles=@('existing-profile')}}
        else{[pscustomobject]@{Registry='prior';PolicyValue=$null;File=$null;Theme=$null;Profiles=@('existing-profile')}}
      }
      Mock Set-RideDefaultWallpaperImage {
        param($StateDirectory,$WhatIf)
        if($WhatIf){$script:events.Add('Preview');return [pscustomobject]@{SchemaVersion=1;Status='Preview';RunId=$null;NativeVisualAcceptance=$false}}
        if($script:active){$script:events.Add('Repeat');return [pscustomobject]@{SchemaVersion=1;Status='AlreadyDesired';RunId=$script:ownerId;NativeVisualAcceptance=$false}}
        $script:events.Add('Apply');$script:active=$true
        [IO.File]::WriteAllText((Join-Path $StateDirectory ($script:ownerId+'.default-wallpaper.intent.json')),'inert state fixture')
        [IO.File]::WriteAllBytes($script:assetPath,(New-Object byte[] 100))
        [IO.File]::WriteAllBytes($script:themePath,$script:theme.Content)
        [pscustomobject]@{SchemaVersion=1;Status='Applied';RunId=$script:ownerId;AssetPath=$script:assetPath;ThemePath=$script:themePath;NativeVisualAcceptance=$false}
      }
      Mock Restore-RideDefaultWallpaperRun {
        param($RunId,$WhatIf)
        if($RunId -cne $script:ownerId){throw 'Wrong lifecycle owner.'}
        if($WhatIf){$script:events.Add('RestorePreview');return [pscustomobject]@{SchemaVersion=1;Status=if($script:active){'Preview'}else{'AlreadyRestored'};RunId=$RunId;NativeVisualAcceptance=$false}}
        if($script:restoreFailure){throw 'Synthetic recovery failure.'}
        $status=if($script:active){'Restored'}else{'AlreadyRestored'}
        $script:events.Add($status);$script:active=$false
        if([IO.File]::Exists($script:assetPath)){[IO.File]::Delete($script:assetPath)}
        if([IO.File]::Exists($script:themePath)){[IO.File]::Delete($script:themePath)}
        [pscustomobject]@{SchemaVersion=1;Status=$status;RunId=$RunId;NativeVisualAcceptance=$false}
      }
    }
    It 'retains the applied image and private evidence without claiming visual or full lifecycle acceptance' {
      $report=Invoke-RideDefaultWallpaperAcceptance @script:applyParameters
      $report.Status|Should -Be AwaitingVisualVerification;$report.Checks.Count|Should -Be 3
      $report.RecoveryRequired|Should -BeTrue;$script:active|Should -BeTrue
      $report.NativeLifecycleAcceptancePassed|Should -BeFalse;$report.NativeVisualAcceptancePassed|Should -BeFalse;$report.NativeAcceptancePassed|Should -BeFalse;$report.NativeFirstLogonAcceptancePassed|Should -BeFalse
      $report.LifecycleRunId|Should -BeExactly $script:ownerId
      $report.StateRunIds|Should -Contain $script:ownerId
      $saved=Read-RideDefaultWallpaperAcceptanceRecord (Join-Path $script:directory 'apply.json')
      $saved.Status|Should -BeExactly $report.Status
      (Get-Acl -LiteralPath (Join-Path $script:directory 'apply.json')).AreAccessRulesProtected|Should -BeTrue
      Should -Invoke Restore-RideDefaultWallpaperRun -Times 0 -Exactly
    }
    It 'restores in a separate phase and leaves visible recovery unverified' {
      $null=Invoke-RideDefaultWallpaperAcceptance @script:applyParameters
      $report=Invoke-RideDefaultWallpaperAcceptance @script:restoreParameters
      $report.Status|Should -Be LifecyclePassedVisualPending;$report.Checks.Count|Should -Be 3
      $report.NativeLifecycleAcceptancePassed|Should -BeTrue;$report.NativeVisualAcceptancePassed|Should -BeFalse;$report.NativeAcceptancePassed|Should -BeFalse;$report.NativeFirstLogonAcceptancePassed|Should -BeFalse
      $report.RecoveryRequired|Should -BeFalse;$script:active|Should -BeFalse
      @(Get-ChildItem -LiteralPath $script:directory -Filter 'restore.*.json').Count|Should -Be 1
      ($script:events -join ';')|Should -BeExactly 'Preview;Apply;Repeat;RestorePreview;Restored;AlreadyRestored'
    }
    It 'can recheck completed recovery without overwriting earlier attempt evidence' {
      $null=Invoke-RideDefaultWallpaperAcceptance @script:applyParameters
      $null=Invoke-RideDefaultWallpaperAcceptance @script:restoreParameters
      (Invoke-RideDefaultWallpaperAcceptance @script:restoreParameters).Status|Should -Be LifecyclePassedVisualPending
      @(Get-ChildItem -LiteralPath $script:directory -Filter 'restore.*.json').Count|Should -Be 2
    }
    It 'previews either phase without new directories, records or lifecycle calls' {
      (Invoke-RideDefaultWallpaperAcceptance @script:applyParameters -WhatIf).Status|Should -Be Preview
      Test-Path -LiteralPath $script:directory|Should -BeFalse
      Should -Invoke Set-RideDefaultWallpaperImage -Times 0 -Exactly
      $null=Invoke-RideDefaultWallpaperAcceptance @script:applyParameters
      $count=@(Get-ChildItem -LiteralPath $script:directory -File).Count
      (Invoke-RideDefaultWallpaperAcceptance @script:restoreParameters -WhatIf).Status|Should -Be Preview
      @(Get-ChildItem -LiteralPath $script:directory -File).Count|Should -Be $count
      Should -Invoke Restore-RideDefaultWallpaperRun -Times 0 -Exactly
    }
    It 'refuses mismatched requests, unmarked guests and unsupported editions before writes' {
      $script:context.RunMarker='0'*32
      {Invoke-RideDefaultWallpaperAcceptance @script:applyParameters}|Should -Throw '*correlated*'
      $script:context.RunMarker=$script:id;$script:context.Guest=$false
      {Invoke-RideDefaultWallpaperAcceptance @script:applyParameters}|Should -Throw '*Hyper-V guest*'
      $script:context.Guest=$true;$script:context.EditionId='Professional'
      {Invoke-RideDefaultWallpaperAcceptance @script:applyParameters}|Should -Throw '*Enterprise/Education*'
      Test-Path -LiteralPath $script:directory|Should -BeFalse
    }
    It 'requires existing elevation for changes but allows a no-write preview without it' {
      $script:context.Administrator=$false
      {Invoke-RideDefaultWallpaperAcceptance @script:applyParameters}|Should -Throw '*Existing elevation*'
      (Invoke-RideDefaultWallpaperAcceptance @script:applyParameters -WhatIf).Status|Should -Be Preview
      Should -Invoke New-RideDefaultWallpaperAcceptanceDirectory -Times 0 -Exactly
    }
    It 'refuses a missing or incorrect source before creating the request directory' {
      Mock Read-RideDefaultWallpaperAcceptanceSource {throw 'Synthetic source digest mismatch.'}
      {Invoke-RideDefaultWallpaperAcceptance @script:applyParameters}|Should -Throw '*digest mismatch*'
      Should -Invoke New-RideDefaultWallpaperAcceptanceDirectory -Times 0 -Exactly
    }
    It 'refuses an overlong theme destination before creating any evidence directories' {
      Mock Assert-RideDefaultWallpaperAcceptanceRoot {return ('C:\'+('x'*200))}
      {Invoke-RideDefaultWallpaperAcceptance @script:applyParameters}|Should -Throw '*canonical local PNG path*'
      Should -Invoke New-RideDefaultWallpaperAcceptanceDirectory -Times 0 -Exactly
      Should -Invoke Set-RideDefaultWallpaperImage -Times 0 -Exactly
    }
    It 'accepts phase spelling case-insensitively while recording the canonical phase' {
      $script:applyParameters.Phase='apply';$script:restoreParameters.Phase='RESTORE'
      $applied=Invoke-RideDefaultWallpaperAcceptance @script:applyParameters
      $applied.Phase|Should -BeExactly Apply;$applied.Status|Should -Be AwaitingVisualVerification
      $restored=Invoke-RideDefaultWallpaperAcceptance @script:restoreParameters
      $restored.Phase|Should -BeExactly Restore;$restored.Status|Should -Be LifecyclePassedVisualPending
    }
    It 'refuses irrelevant source input during recovery and duplicate apply request IDs' {
      $script:restoreParameters.SourcePath='unused.png'
      {Invoke-RideDefaultWallpaperAcceptance @script:restoreParameters}|Should -Throw '*omitted for Restore*'
      $null=Invoke-RideDefaultWallpaperAcceptance @script:applyParameters
      {Invoke-RideDefaultWallpaperAcceptance @script:applyParameters}|Should -Throw '*already exists*'
    }
    It 'retains failed apply evidence and refuses to turn it into an automatic restore phase' {
      Mock Assert-RideDefaultWallpaperAcceptanceRecords {throw 'Synthetic private recovery failure.'}
      $report=Invoke-RideDefaultWallpaperAcceptance @script:applyParameters
      $report.Status|Should -Be Failed;$report.Stage|Should -Be Apply;$report.RecoveryRequired|Should -BeTrue
      $report.Error|Should -BeExactly 'Synthetic private recovery failure.'
      $script:active|Should -BeTrue
      {Invoke-RideDefaultWallpaperAcceptance @script:restoreParameters}|Should -Throw '*Completed apply-phase*'
      Should -Invoke Restore-RideDefaultWallpaperRun -Times 0 -Exactly
    }
    It 'detects mutation during preview and never starts actual apply' {
      Mock Set-RideDefaultWallpaperImage {
        param($StateDirectory,$WhatIf)
        [IO.File]::WriteAllText((Join-Path $StateDirectory 'unexpected.txt'),'synthetic preview mutation')
        [pscustomobject]@{SchemaVersion=1;Status='Preview';RunId=$null;NativeVisualAcceptance=$false}
      }
      $report=Invoke-RideDefaultWallpaperAcceptance @script:applyParameters
      $report.Status|Should -Be Failed;$report.Stage|Should -Be Preview
      Should -Invoke Set-RideDefaultWallpaperImage -Times 0 -Exactly -ParameterFilter {-not $WhatIf}
    }
    It 'rejects independent policy readback that differs from the applied result' {
      Mock Get-RideDefaultWallpaperAcceptanceSnapshot {
        if($script:active){[pscustomobject]@{Registry='applied';PolicyValue='different image';File=[pscustomobject]@{Sha256=('A'*64);Bytes=100}}}
        else{[pscustomobject]@{Registry='prior';PolicyValue=$null;File=$null;Theme=$null;Profiles=@('existing-profile')}}
      }
      $report=Invoke-RideDefaultWallpaperAcceptance @script:applyParameters
      $report.Status|Should -Be Failed;$report.Stage|Should -Be Apply;$report.NativeAcceptancePassed|Should -BeFalse;$report.NativeFirstLogonAcceptancePassed|Should -BeFalse
      Should -Invoke Restore-RideDefaultWallpaperRun -Times 0 -Exactly
    }
    It 'retains failed restore evidence and allows a later unchanged recovery retry' {
      $null=Invoke-RideDefaultWallpaperAcceptance @script:applyParameters
      $script:restoreFailure=$true
      $failed=Invoke-RideDefaultWallpaperAcceptance @script:restoreParameters
      $failed.Status|Should -Be Failed;$failed.RecoveryRequired|Should -BeTrue;$script:active|Should -BeTrue
      $script:restoreFailure=$false
      (Invoke-RideDefaultWallpaperAcceptance @script:restoreParameters).Status|Should -Be LifecyclePassedVisualPending
      @(Get-ChildItem -LiteralPath $script:directory -Filter 'restore.*.json').Count|Should -Be 2
    }
    It 'refuses invalid theme or profile readback after apply: <Fault>' -TestCases @(@{Fault='MissingTheme'},@{Fault='ThemeHash'},@{Fault='Profiles'}) {
      param($Fault)
      $script:fault=$Fault
      Mock Get-RideDefaultWallpaperAcceptanceSnapshot {
        if(-not $script:active){return [pscustomobject]@{Registry='prior';PolicyValue=$null;File=$null;Theme=$null;Profiles=@('existing-profile')}}
        $theme=[pscustomobject]@{Sha256=$script:theme.Sha256;Bytes=$script:theme.Bytes}
        $profiles=@('existing-profile')
        switch($script:fault){MissingTheme {$theme=$null};ThemeHash {$theme.Sha256='B'*64};Profiles {$profiles+=@('new-profile')}}
        [pscustomobject]@{Registry='applied';PolicyValue=$script:themePath;File=[pscustomobject]@{Sha256=('A'*64);Bytes=100};Theme=$theme;Profiles=$profiles}
      }
      $report=Invoke-RideDefaultWallpaperAcceptance @script:applyParameters
      $report.Status|Should -Be Failed;$report.Stage|Should -Be Apply
      $report.RecoveryRequired|Should -BeTrue;$report.NativeFirstLogonAcceptancePassed|Should -BeFalse
      Test-Path -LiteralPath $script:themePath|Should -BeTrue
      Should -Invoke Restore-RideDefaultWallpaperRun -Times 0 -Exactly
    }
    It 'retains a newly created profile and both assets instead of attempting recovery' {
      $null=Invoke-RideDefaultWallpaperAcceptance @script:applyParameters
      Mock Get-RideDefaultWallpaperAcceptanceSnapshot {
        [pscustomobject]@{Registry='applied';PolicyValue=$script:themePath;File=[pscustomobject]@{Sha256=('A'*64);Bytes=100};Theme=$script:theme;Profiles=@('existing-profile','new-first-logon-profile')}
      }
      $report=Invoke-RideDefaultWallpaperAcceptance @script:restoreParameters
      $report.Status|Should -Be Failed;$report.Stage|Should -Be RestorePreview;$report.RecoveryRequired|Should -BeTrue
      Test-Path -LiteralPath $script:themePath|Should -BeTrue
      Test-Path -LiteralPath $script:assetPath|Should -BeTrue
      Should -Invoke Restore-RideDefaultWallpaperRun -Times 0 -Exactly
    }
    It 'refuses a forged saved theme path before invoking recovery' {
      $null=Invoke-RideDefaultWallpaperAcceptance @script:applyParameters
      $path=Join-Path $script:directory 'apply.json';$record=Read-RideDefaultWallpaperAcceptanceRecord $path
      $record.ThemePath='C:\Unrelated\desktop.theme';[IO.File]::WriteAllText($path,($record|ConvertTo-Json -Depth 15))
      {Invoke-RideDefaultWallpaperAcceptance @script:restoreParameters}|Should -Throw '*mismatched*'
      Should -Invoke Restore-RideDefaultWallpaperRun -Times 0 -Exactly
    }
    It 'refuses a changed target or forged saved asset path before recovery' {
      $null=Invoke-RideDefaultWallpaperAcceptance @script:applyParameters
      $script:context.Revision=9999
      {Invoke-RideDefaultWallpaperAcceptance @script:restoreParameters}|Should -Throw '*target changed*'
      $script:context.Revision=9711
      $path=Join-Path $script:directory 'apply.json';$record=Read-RideDefaultWallpaperAcceptanceRecord $path
      $record.AssetPath='C:\Unrelated\image.png';[IO.File]::WriteAllText($path,($record|ConvertTo-Json -Depth 15))
      {Invoke-RideDefaultWallpaperAcceptance @script:restoreParameters}|Should -Throw '*mismatched*'
      Should -Invoke Restore-RideDefaultWallpaperRun -Times 0 -Exactly
    }
    It 'completes only saved request directories without reading reports or Windows state' {
      $null=New-Item -ItemType Directory -Path $script:directory
      $result=@(& $script:DefaultWallpaperAcceptanceCompleter 'Invoke-RideDefaultWallpaperAcceptance' 'RunId' $script:id.Substring(0,2) $null @{Phase='Restore';EvidenceRoot=$script:root})
      $result.Count|Should -Be 1;$result[0].CompletionText|Should -BeExactly $script:id
      $wrapper=Join-Path (Split-Path (Get-Module RIDE.DefaultWallpaperAcceptance).Path -Parent) 'Invoke-RideDefaultWallpaperAcceptance.ps1'
      $attribute=@((Get-Command $wrapper).Parameters.RunId.Attributes|Where-Object {$_ -is [Management.Automation.ArgumentCompleterAttribute]})
      $attribute.Count|Should -Be 1
      $wrapperResult=@(& $attribute[0].ScriptBlock $wrapper 'RunId' $script:id.Substring(0,2) $null @{Phase='Restore';EvidenceRoot=$script:root})
      $wrapperResult.Count|Should -Be 1;$wrapperResult[0].CompletionText|Should -BeExactly $script:id
      Should -Invoke Get-RideDefaultWallpaperAcceptanceContext -Times 0 -Exactly
      Should -Invoke Read-RidePrivateFileBytes -Times 0 -Exactly
    }
  }
}
Describe 'Pinned first-logon wallpaper acceptance source gate' {
  InModuleScope RIDE.DefaultWallpaperAcceptance {
    It 'checks pinned metadata as well as the selected digest' {
      $fixture=Import-PowerShellDataFile -LiteralPath (Join-Path (Split-Path (Get-Module RIDE.DefaultWallpaperAcceptance).Path -Parent) '../fixtures/default-wallpaper.acceptance.psd1')
      Mock Get-RidePngSource {[pscustomobject]@{Bytes=1;Width=1;Height=1}}
      {Read-RideDefaultWallpaperAcceptanceSource 'inert.png'}|Should -Throw '*metadata differs*'
      Should -Invoke Get-RidePngSource -Times 1 -Exactly -ParameterFilter {$ExpectedSha256 -ceq $fixture.Sha256}
    }
  }
}
Describe 'Default-image acceptance directory preparation' {
  InModuleScope RIDE.DefaultWallpaperAcceptance {
    It 'separates administrator-only state from public-read image directories in memory' {
      foreach($public in @($false,$true)){
        $acl=New-RideDefaultWallpaperAcceptanceDirectorySecurity $public
        $acl.AreAccessRulesProtected|Should -BeTrue
        $acl.GetOwner([Security.Principal.SecurityIdentifier]).Value|Should -BeExactly 'S-1-5-32-544'
        $rules=@($acl.GetAccessRules($true,$true,[Security.Principal.SecurityIdentifier]))
        $rules.Count|Should -Be $(if($public){3}else{2})
        $users=@($rules|Where-Object {$_.IdentityReference.Value -ceq 'S-1-5-32-545'})
        if($public){
          ($users[0].FileSystemRights -band [Security.AccessControl.FileSystemRights]::Write)|Should -Be 0
          ($users[0].FileSystemRights -band [Security.AccessControl.FileSystemRights]::ReadAndExecute)|Should -Be ([Security.AccessControl.FileSystemRights]::ReadAndExecute)
        }else{$users.Count|Should -Be 0}
        foreach($rule in $rules){$rule.PropagationFlags|Should -Be ([Security.AccessControl.PropagationFlags]::None)}
      }
    }
    It 'refuses existing directories before any native ACL creation' {
      $path=Join-Path $TestDrive 'existing';$null=New-Item -ItemType Directory -Path $path
      $before=(Get-Acl -LiteralPath $path).Sddl
      {New-RideDefaultWallpaperAcceptanceDirectory $path $true}|Should -Throw '*will not be adopted*'
      (Get-Acl -LiteralPath $path).Sddl|Should -BeExactly $before
    }
  }
}
