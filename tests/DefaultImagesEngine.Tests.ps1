<#
.SYNOPSIS
  Verify catalog image selection, dispatch, preview and recovery contracts.
.NOTES
  Version: 0.1.0. Pester 5 on Windows PowerShell 5.1/7.
  Machine handlers are mocked; no live Windows configuration is changed.
#>
BeforeDiscovery {
  Import-Module (Join-Path $PSScriptRoot '../modules/RIDE.Engine.psm1') -Force
}
Describe 'Default image catalog integration' {
  InModuleScope RIDE.Engine {
    BeforeEach {
      Mock Get-RidePlatform {'Windows 11'}
      Mock Test-RideAdministrator {$true}
      Mock Get-RideDefaultImageState {[pscustomobject]@{Available=$true;PolicyPath=$null;Owned=$false;SourceSha256=$null;Context=[pscustomobject]@{Build='26300';EditionId='EnterpriseEval';Revision=9711}}}
      Mock Assert-RideDefaultImageTarget {}
      Mock Get-RidePngSource {[pscustomobject]@{Sha256=('A'*64)}}
      Mock Save-RideRunManifest {}
      Mock Save-RideOperationSnapshot {}
      Mock Set-RideRunOperationProgress {}
      Mock Set-RideDefaultImageState {}
    }
    It 'creates a direct catalog selection without mutating the catalog' {
      $plan=@(Get-RideSingleOperationPlan -Id windows.default-wallpaper -Action Set -State Configured -ImagePath 'C:\Inputs\wall.png' -ImageSha256 ('a'*64))
      $plan.Count|Should -Be 1
      $plan[0].Operation.ImageSha256|Should -Be ('A'*64)
      (Get-RideOperation windows.default-wallpaper).ContainsKey('ImagePath')|Should -BeFalse
      (Get-RideOperationValue $plan[0].Operation Configured)|Should -Match 'C:\\Inputs\\wall.png'
    }
    It 'rejects absent, remote and malformed pins before planning' {
      {Get-RideSingleOperationPlan windows.default-wallpaper Set Configured}|Should -Throw '*ImagePath*'
      {Get-RideSingleOperationPlan windows.default-wallpaper Set Configured -ImagePath '\\server\wall.png' -ImageSha256 ('A'*64)}|Should -Throw
      {Get-RideSingleOperationPlan windows.default-wallpaper Set Configured -ImagePath 'C:\wall.png' -ImageSha256 bad}|Should -Throw
      {Get-RideSingleOperationPlan windows.default-wallpaper Unset}|Should -Throw '*no generic unset*'
    }
    It 'previews the example image profile without snapshots, directories or handler dispatch' {
      $profile=Get-RideProfile -Path (Join-Path $script:RideRoot 'profiles/default-images.psd1')
      foreach ($selection in $profile.Operations) { $selection.ImageSha256='A'*64 }
      $plan=@(Get-RidePlan $profile)
      Invoke-RidePlan $plan -WhatIf
      Should -Invoke Set-RideDefaultImageState -Times 0 -Exactly
      Should -Invoke Save-RideOperationSnapshot -Times 0 -Exactly
      Should -Invoke Save-RideRunManifest -Times 0 -Exactly
    }
    It 'preflights all selected image payloads before any apply' {
      $profile=@{SchemaVersion=1;Name='Synthetic';Operations=@(
        @{Id='windows.default-wallpaper';State='Configured';ImagePath='C:\wall.png';ImageSha256=('A'*64)},
        @{Id='windows.default-lock-screen';State='Configured';ImagePath='C:\lock.png';ImageSha256=('B'*64)})}
      Mock Get-RidePngSource {throw 'bad second hash'} -ParameterFilter {$Path -eq 'C:\lock.png'}
      {Invoke-RidePlan @(Get-RidePlan $profile) -Confirm:$false}|Should -Throw '*bad second hash*'
      Should -Invoke Set-RideDefaultImageState -Times 0 -Exactly
      Should -Invoke Save-RideRunManifest -Times 0 -Exactly
    }
    It 'dispatches a setting with the outer saved run ID and captures first' {
      $plan=@(Get-RideSingleOperationPlan windows.default-lock-screen Set Configured -ImagePath 'C:\lock.png' -ImageSha256 ('A'*64))
      Invoke-RidePlan $plan -Confirm:$false
      Should -Invoke Save-RideOperationSnapshot -Times 1 -Exactly -ParameterFilter {$Operation.Id -eq 'windows.default-lock-screen' -and $RunId -match '^[a-f0-9]{32}$'}
      Should -Invoke Set-RideDefaultImageState -Times 1 -Exactly -ParameterFilter {$Operation.ImagePath -eq 'C:\lock.png' -and $RunId -match '^[a-f0-9]{32}$'}
    }
    It 'does not snapshot or reapply an unchanged owned image' {
      Mock Get-RideDefaultImageState {[pscustomobject]@{Available=$true;PolicyPath='C:\owned.png';Owned=$true;SourceSha256=('A'*64);Context=$null}}
      Invoke-RidePlan @(Get-RideSingleOperationPlan windows.default-wallpaper Set Configured -ImagePath 'C:\wall.png' -ImageSha256 ('A'*64)) -Confirm:$false
      Should -Invoke Set-RideDefaultImageState -Times 0 -Exactly
      Should -Invoke Save-RideOperationSnapshot -Times 0 -Exactly
    }
    It 'compares default policy absence and selected image hashes independently' {
      @(Get-RideStatus -OperationId windows.default-wallpaper)[0].MatchesDefault|Should -BeTrue
      Mock Get-RideDefaultImageState {[pscustomobject]@{Available=$true;PolicyPath='C:\owned.png';Owned=$true;SourceSha256=('A'*64);Context=$null}}
      @(Get-RideStatus -OperationId windows.default-wallpaper)[0].MatchesDefault|Should -BeFalse
      $profile=@{SchemaVersion=1;Name='Image';Operations=@(@{Id='windows.default-wallpaper';State='Configured';ImagePath='C:\source.png';ImageSha256=('A'*64)})}
      @(Get-RideStatus -Profile $profile)[0].InDesiredState|Should -BeTrue
      $profile.Operations[0].ImageSha256='B'*64
      @(Get-RideStatus -Profile $profile)[0].InDesiredState|Should -BeFalse
    }
    It 'restores shared-policy image operations in reverse capture order' {
      $script:imageTestRoot=Join-Path $TestDrive 'machine'
      $run='b'*32;$dir=Join-Path $script:imageTestRoot $run
      $null=New-Item -ItemType Directory -Path $dir -Force
      Mock Get-RideStateRoot {if($Scope -eq 'Machine'){$script:imageTestRoot}else{Join-Path $TestDrive 'unused-user'}}
      $index=0
      foreach($type in @('LockScreen','Wallpaper')) {
        $id=if($type -eq 'Wallpaper'){'windows.default-wallpaper'}else{'windows.default-lock-screen'}
        @{SchemaVersion=1;RunId=$run;OperationId=$id;Kind='DefaultImage';Scope='Machine';CreatedUtc=('2026-11-03T10:00:0'+$index+'Z');Snapshot=@{SnapshotVersion=1;OperationId=$id;ImageType=$type;ImageRunId=$run}}|ConvertTo-Json -Depth 5|Set-Content (Join-Path $dir ($id+'.json'))
        $index++
      }
      $script:imageRecoveryOrder=@()
      Mock Restore-RideDefaultImageState {if(-not $ValidateOnly){$script:imageRecoveryOrder+=@($Operation.ImageType)}}
      Restore-RideRun $run -Confirm:$false
      ($script:imageRecoveryOrder -join ',')|Should -Be 'Wallpaper,LockScreen'
      Should -Invoke Restore-RideDefaultImageState -Times 2 -Exactly -ParameterFilter {$ValidateOnly}
    }
    It 'reads a machine-only failed-run manifest to enable no-child-intent recovery' {
      $root=Join-Path $TestDrive 'machine-manifest';$run='d'*32;$dir=Join-Path $root $run
      $null=New-Item -ItemType Directory -Path $dir -Force
      Mock Get-RideStateRoot {if($Scope -eq 'Machine'){$root}else{Join-Path $TestDrive 'no-user-manifest'}}
      $operation=Get-RideOperation windows.default-lock-screen
      @{SchemaVersion=1;RunId=$run;OperationId=$operation.Id;Kind='DefaultImage';Scope='Machine';CreatedUtc='2026-11-04T00:00:00Z';Snapshot=@{SnapshotVersion=1;OperationId=$operation.Id;ImageType='LockScreen';ImageRunId=$run}}|ConvertTo-Json -Depth 5|Set-Content -LiteralPath (Join-Path $dir ($operation.Id+'.json'))
      @{RunId=$run;Scopes=@('Machine');OperationProgress=@(@{OperationId=$operation.Id;Status='Failed'})}|ConvertTo-Json -Depth 5|Set-Content -LiteralPath (Join-Path $dir '_manifest.json')
      $script:failedIntentFallback=$false
      Mock Restore-RideDefaultImageState {$script:failedIntentFallback=$FailedApplyWithoutChildIntent}
      Restore-RideRun $run -Confirm:$false
      $script:failedIntentFallback|Should -BeTrue
      Should -Invoke Restore-RideDefaultImageState -Times 2 -Exactly -ParameterFilter {$FailedApplyWithoutChildIntent}
    }
  }
  It 'completes Configured from catalog metadata' {
    $line='& "'+(Resolve-Path (Join-Path $PSScriptRoot '../ride.ps1')).Path+'" set windows.default-wallpaper -State Con'
    (TabExpansion2 $line $line.Length).CompletionMatches.CompletionText | Should -Contain 'Configured'
  }
  It 'rejects image inputs on read-only search before dispatch' {
    { & (Join-Path $PSScriptRoot '../ride.ps1') search wallpaper -ImagePath 'C:\wall.png' } | Should -Throw '*Image inputs require*'
  }
  It 'completes local image paths without invoking handlers' {
    $file=Join-Path $TestDrive 'selected.png'; Set-Content -LiteralPath $file -Value 'completion only'
    $line='& "'+(Resolve-Path (Join-Path $PSScriptRoot '../ride.ps1')).Path+'" set windows.default-wallpaper -ImagePath "'+$TestDrive+'\sel'
    @((TabExpansion2 $line $line.Length).CompletionMatches | Where-Object {$_.CompletionText -like '*selected.png*'}).Count | Should -Be 1
  }
}
Describe 'Automatic image selection hashes' {
  BeforeAll {
    Import-Module (Join-Path $PSScriptRoot '../modules/RIDE.DefaultImages.psm1')
    Import-Module (Join-Path $PSScriptRoot '../modules/RIDE.CatalogValidation.psm1') -Force
    Add-Type -AssemblyName System.Drawing
  }
  BeforeEach {
    $script:image=Join-Path $TestDrive 'automatic.png'
    $bitmap=[Drawing.Bitmap]::new(2,3)
    try{$bitmap.Save($script:image,[Drawing.Imaging.ImageFormat]::Png)}finally{$bitmap.Dispose()}
    $script:hash=(Get-FileHash -LiteralPath $script:image).Hash
  }
  It 'calculates and carries a hash in direct and profile plans for both image operations' {
    foreach($id in @('windows.default-wallpaper','windows.default-lock-screen')) {
      $plan=@(Get-RideSingleOperationPlan $id Set Configured -ImagePath $script:image)
      $plan[0].Operation.ImageSha256|Should -BeExactly $script:hash
      $profile=@{SchemaVersion=1;Name='Automatic';Operations=@(@{Id=$id;State='Configured';ImagePath=$script:image})}
      @(Get-RidePlan $profile)[0].Operation.ImageSha256|Should -BeExactly $script:hash
      $profile.Operations[0].ContainsKey('ImageSha256')|Should -BeFalse
    }
  }
  It 'retains explicit pins and refuses mismatching bytes at execution before saving state' {
    Mock Get-RidePlatform -ModuleName RIDE.Engine {'Windows 11'}
    Mock Test-RideAdministrator -ModuleName RIDE.Engine {$true}
    Mock Get-RideCurrentState -ModuleName RIDE.Engine {@{Available=$true}}
    Mock Assert-RideDefaultImageTarget -ModuleName RIDE.Engine {}
    Mock Save-RideRunManifest -ModuleName RIDE.Engine {}
    Mock Set-RideDefaultImageState -ModuleName RIDE.Engine {}
    $plan=@(Get-RideSingleOperationPlan windows.default-lock-screen Set Configured -ImagePath $script:image -ImageSha256 ('0'*64))
    $plan[0].Operation.ImageSha256|Should -Be ('0'*64)
    {Invoke-RidePlan $plan -Confirm:$false}|Should -Throw '*hash differs*'
    Should -Invoke Save-RideRunManifest -ModuleName RIDE.Engine -Times 0 -Exactly
    Should -Invoke Set-RideDefaultImageState -ModuleName RIDE.Engine -Times 0 -Exactly
  }
  It 'refuses a changed automatically hashed source before saving state or applying' {
    Mock Get-RidePlatform -ModuleName RIDE.Engine {'Windows 11'}
    Mock Test-RideAdministrator -ModuleName RIDE.Engine {$true}
    Mock Get-RideCurrentState -ModuleName RIDE.Engine {@{Available=$true}}
    Mock Assert-RideDefaultImageTarget -ModuleName RIDE.Engine {}
    Mock Save-RideRunManifest -ModuleName RIDE.Engine {}
    Mock Set-RideDefaultImageState -ModuleName RIDE.Engine {}
    $plan=@(Get-RideSingleOperationPlan windows.default-wallpaper Set Configured -ImagePath $script:image)
    $changed=[IO.File]::ReadAllBytes($script:image);$changed[20]=$changed[20] -bxor 1
    [IO.File]::WriteAllBytes($script:image,$changed)
    {Invoke-RidePlan $plan -Confirm:$false}|Should -Throw '*hash differs*'
    Should -Invoke Save-RideRunManifest -ModuleName RIDE.Engine -Times 0 -Exactly
    Should -Invoke Set-RideDefaultImageState -ModuleName RIDE.Engine -Times 0 -Exactly
  }
  It 'rejects missing or invalid PNG files when calculating a hash' {
    {Get-RideSingleOperationPlan windows.default-wallpaper Set Configured -ImagePath (Join-Path $TestDrive 'missing.png')}|Should -Throw
    [IO.File]::WriteAllText($script:image,('not an image'*10))
    {Get-RideSingleOperationPlan windows.default-lock-screen Set Configured -ImagePath $script:image}|Should -Throw
  }
  It 'validates profiles without a hash and rejects malformed explicit pins without reading source files' {
    $profile=Join-Path $TestDrive 'optional.psd1'
    $body="@{SchemaVersion=1;Name='Optional';Description='Test';Operations=@(@{Id='windows.default-lock-screen';State='Configured';ImagePath='C:\Missing\lock.png' HASHFIELD})}"
    Set-Content -LiteralPath $profile -Value $body.Replace('HASHFIELD','')
    @(Get-RideCatalogValidationErrors -Catalog (Get-RideCatalog) -ProfilePaths @(Get-Item $profile)).Count|Should -Be 0
    Set-Content -LiteralPath $profile -Value $body.Replace('HASHFIELD',";ImageSha256='bad'")
    @(Get-RideCatalogValidationErrors -Catalog (Get-RideCatalog) -ProfilePaths @(Get-Item $profile)) -join ';'|Should -Match 'optional ImageSha256'
  }
}
Describe 'Default image adapter boundaries' {
  InModuleScope RIDE.DefaultImages {
    BeforeEach {
      $script:op=@{Id='windows.default-wallpaper';ImageType='Wallpaper';ImagePath='C:\input.png';ImageSha256=('A'*64)}
      $script:c=[pscustomobject]@{Build='26300';Revision=9711;EditionId='EnterpriseEval';ComputerName='Synthetic';InstallationType='Client';NativeProcess=$true;Architecture='AMD64';Administrator=$true;Guest=$false}
    }
    It 'requires candidate opt-in outside the accepted build and preserves edition checks' {
      Assert-RideDefaultImageTarget $script:op @{Context=$script:c}
      $script:c.Revision=9712
      {Assert-RideDefaultImageTarget $script:op @{Context=$script:c}}|Should -Throw '*AllowCandidate*'
      Assert-RideDefaultImageTarget $script:op @{Context=$script:c} -Preview
      Assert-RideDefaultImageTarget $script:op @{Context=$script:c} -AllowCandidate
      $script:c.EditionId='Professional'
      {Assert-RideDefaultImageTarget $script:op @{Context=$script:c} -AllowCandidate}|Should -Throw '*Enterprise/Education*'
    }
    It 'binds the child lifecycle to the outer identity and managed storage' {
      Mock Get-RideDefaultImageState {@{Context=$script:c}}
      Mock Get-RidePngSource {}
      Mock Initialize-RideDefaultImageDirectory {}
      Mock Set-RideDefaultWallpaperImage {@{Status='Applied'}}
      Set-RideDefaultImageState $script:op 'C:\SyntheticState' ('a'*32) -Confirm:$false
      Should -Invoke Set-RideDefaultWallpaperImage -Times 1 -Exactly -ParameterFilter {$RunId -ceq ('a'*32) -and $ExpectedComputerName -ceq 'Synthetic' -and $AssetDirectory -eq 'C:\SyntheticState\Images\Wallpaper' -and $StateDirectory -eq 'C:\SyntheticState\ImageState\Wallpaper'}
    }
    It 'previews without creating managed directories or invoking the child writer' {
      Mock Get-RideDefaultImageState {@{Context=$script:c}}
      Mock Get-RidePngSource {}
      Mock Initialize-RideDefaultImageDirectory {}
      Mock Set-RideDefaultWallpaperImage {}
      Set-RideDefaultImageState $script:op 'C:\SyntheticState' ('a'*32) -WhatIf
      Should -Invoke Initialize-RideDefaultImageDirectory -Times 0 -Exactly
      Should -Invoke Set-RideDefaultWallpaperImage -Times 0 -Exactly
    }
    It 'refuses mismatched recovery identity before reading receipts' {
      {Restore-RideDefaultImageState $script:op @{SnapshotVersion=1;OperationId=$script:op.Id;ImageType='Wallpaper';ImageRunId=('b'*32)} ('a'*32) 'C:\SyntheticState' -ValidateOnly}|Should -Throw '*identity*'
    }
    It 'treats a failed lock-screen apply without child intent as unchanged and recoverable' {
      Mock Get-RideDefaultLockContext { [pscustomobject]@{EditionId='Professional'} } -ModuleName RIDE.DefaultLockScreen
      $operation=Get-RideOperation windows.default-lock-screen
      $run='c'*32
      $snapshot=@{SnapshotVersion=1;OperationId=$operation.Id;ImageType='LockScreen';ImageRunId=$run}
      {Restore-RideDefaultImageState $operation $snapshot $run (Join-Path $TestDrive 'failed-machine') -FailedApplyWithoutChildIntent -ValidateOnly}|Should -Not -Throw
    }
  }
}
