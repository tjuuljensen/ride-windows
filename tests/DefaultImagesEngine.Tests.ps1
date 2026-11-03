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
    It 'previews both images without snapshots, directories or handler dispatch' {
      $plan=@(Get-RidePlan (Get-RideProfile -Path (Join-Path $script:RideRoot 'profiles/default-images.psd1')))
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
  }
}
