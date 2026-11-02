<#
.SYNOPSIS
  Verify owned wallpaper user fixtures without creating Windows accounts/profiles.
.DESCRIPTION
  Native identity, accounts, groups, sessions, profile queries and deletion are
  mocked. Intent/receipt files use real private current-user TestDrive storage.
.EXAMPLE
  Invoke-Pester ./tests/WallpaperTestUser.Tests.ps1
.NOTES
  Native Windows PowerShell 5.1/7 and Pester 5. Version: 0.1.0.
#>
BeforeDiscovery {Import-Module (Join-Path $PSScriptRoot 'integration/RIDE.WallpaperTestUser.psm1') -Force}
Describe 'Owned wallpaper user fixtures' {
  InModuleScope RIDE.WallpaperTestUser {
    BeforeEach {
      $script:id=[guid]::NewGuid().ToString('N');$script:sid='S-1-5-21-101-202-303-1001'
      $script:root=Join-Path $TestDrive ([guid]::NewGuid().ToString('N').Substring(0,8));$null=New-Item -ItemType Directory -Path $script:root
      $script:context=[pscustomobject]@{ComputerName='RIDE-Synthetic-VM';Build='26300';EditionId='EnterpriseEval';Revision=9711;InstallationType='Client';NativeProcess=$true;Architecture='AMD64';Guest=$true;Administrator=$true;RunMarker=$script:id}
      $script:password=ConvertTo-SecureString 'Synthetic-Only-Fixture-42!' -AsPlainText -Force
      $script:parameters=@{RunId=$script:id;Purpose='FirstLogon';StateDirectory=$script:root;Password=$script:password;ExpectedComputerName='RIDE-Synthetic-VM';ExpectedBuild='26300';ExpectedEditionId='EnterpriseEval';DisposableVm=$true;Confirm=$false}
      $script:remove=@{RunId=$script:id;Purpose='FirstLogon';StateDirectory=$script:root;DisposableVm=$true;Confirm=$false}
      $script:observe=@{RunId=$script:id;Purpose='FirstLogon';StateDirectory=$script:root;DisposableVm=$true}
      $script:account=$null;$script:profile=$null;$script:groups=@();$script:sessions=0;$script:profileDirectory=$false
      $script:sentinel=[pscustomobject]@{Name='UnrelatedUser';Sid='S-1-5-21-101-202-303-1000';Description='Preserve';Enabled=$true;Source='Local'}
      $script:sentinelBefore=$script:sentinel|ConvertTo-Json -Compress
      $script:events=[Collections.Generic.List[string]]::new()
      Mock Get-RideWallpaperUserContext {$script:context}
      Mock Assert-RideDefaultWallpaperAcceptanceRoot -ModuleName RIDE.DefaultWallpaperAcceptance {param($Path);[IO.Path]::GetFullPath($Path)}
      Mock Get-RideWallpaperUserProfileRoot {'C:\Users'}
      Mock Get-RideWallpaperUserAccounts {$script:sentinel;if($script:account){$script:account}}
      Mock Get-RideWallpaperUserProfiles {if($script:profile){$script:profile}}
      Mock Get-RideWallpaperUserGroups {$script:groups}
      Mock Get-RideWallpaperUserSessionCount {$script:sessions}
      Mock Test-RideWallpaperUserPath {$script:profileDirectory}
      Mock Write-RideWallpaperUserRecord {
        param($Path,$Record)
        $bytes=[Text.UTF8Encoding]::new($false).GetBytes(($Record|ConvertTo-Json -Depth 15 -Compress))
        $stream=& (Get-Module RIDE.PrivateFiles) {param($p) New-RidePrivateFileStream -Path $p -Scope User} $Path
        try{$stream.Write($bytes,0,$bytes.Length);$stream.Flush($true)}finally{$stream.Dispose()}
      }
      Mock Read-RideWallpaperUserRecord {
        param($Path)
        $bytes=& (Get-Module RIDE.PrivateFiles) {param($p) Read-RidePrivateFileBytes -Path $p -Scope User -MaximumBytes 1048576} $Path
        [Text.UTF8Encoding]::new($false,$true).GetString($bytes)|ConvertFrom-Json
      }
      $script:selection=Get-RideWallpaperUserSelection $script:id FirstLogon $script:root
      Mock New-RideWallpaperUserNative {
        param($Name,$Description,$Password)
        if(-not (Test-Path -LiteralPath ($script:selection.Prefix+'.intent.json'))){throw 'Missing intent before creation.'}
        if($Password -isnot [securestring]){throw 'No SecureString password.'}
        $script:events.Add('Create')
        $script:account=[pscustomobject]@{Name=$Name;Sid=$script:sid;Description=$Description;Enabled=$true;Source='Local'}
        $script:sid
      }
      Mock Add-RideWallpaperUserGroup {
        param($Sid)
        if($Sid -cne $script:sid -or -not (Test-Path -LiteralPath ($script:selection.Prefix+'.created.json'))){throw 'No correlated saved SID before group change.'}
        $script:events.Add('AddUsers');$script:groups=@('S-1-5-32-545')
      }
      Mock Disable-RideWallpaperUserNative {param($Sid);if($Sid -cne $script:sid){throw 'Foreign SID.'};$script:events.Add('Disable');$script:account.Enabled=$false}
      Mock Remove-RideWallpaperUserProfileNative {
        param($Sid,$Path)
        if($Sid -cne $script:sid -or $Path -cne ('C:\Users\'+$script:selection.Name) -or $script:account.Enabled){throw 'Foreign profile or enabled account.'}
        $script:events.Add('DeleteProfile');$script:profile=$null;$script:profileDirectory=$false
      }
      Mock Remove-RideWallpaperUserNative {param($Sid);if($Sid -cne $script:sid -or $script:profile -or $script:profileDirectory){throw 'Foreign account or remaining profile.'};$script:events.Add('DeleteUser');$script:account=$null;$script:groups=@()}
    }
    AfterEach {$script:password.Dispose()}
    It 'captures intent before creation and SID before adding only standard Users membership' {
      $result=New-RideWallpaperTestUser @script:parameters
      $result.Status|Should -Be Created;$result.Sid|Should -BeExactly $script:sid
      ($result.State.Groups -join ';')|Should -BeExactly 'S-1-5-32-545'
      $result.State.Profile|Should -BeNullOrEmpty;$result.NativeFirstLogonAcceptancePassed|Should -BeFalse
      ($script:events -join ';')|Should -BeExactly 'Create;AddUsers'
      $saved=Get-Content -LiteralPath ($script:selection.Prefix+'.created.json') -Raw
      $saved|Should -Not -Match 'Password|Synthetic-Only-Fixture'
      (Get-Acl -LiteralPath ($script:selection.Prefix+'.created.json')).AreAccessRulesProtected|Should -BeTrue
      ($script:sentinel|ConvertTo-Json -Compress)|Should -BeExactly $script:sentinelBefore
    }
    It 'repeats creation without resetting a password or creating a second user' {
      $null=New-RideWallpaperTestUser @script:parameters
      (New-RideWallpaperTestUser @script:parameters).Status|Should -Be AlreadyCreated
      Should -Invoke New-RideWallpaperUserNative -Times 1 -Exactly
      Should -Invoke Add-RideWallpaperUserGroup -Times 1 -Exactly
      @(Get-ChildItem -LiteralPath $script:root -File).Count|Should -Be 2
    }
    It 'previews creation without a password, elevation, records or native mutations' {
      $script:parameters.Remove('Password');$script:context.Administrator=$false
      (New-RideWallpaperTestUser @script:parameters -WhatIf).Status|Should -Be Preview
      @(Get-ChildItem -LiteralPath $script:root).Count|Should -Be 0
      Should -Invoke New-RideWallpaperUserNative -Times 0 -Exactly
    }
    It 'refuses an unmarked guest, wrong target or missing elevation before records' {
      $script:context.Guest=$false
      {New-RideWallpaperTestUser @script:parameters}|Should -Throw '*Hyper-V guest*'
      $script:context.Guest=$true;$script:context.ComputerName='Other'
      {New-RideWallpaperTestUser @script:parameters}|Should -Throw '*guest differs*'
      $script:context.ComputerName='RIDE-Synthetic-VM';$script:context.Administrator=$false
      {New-RideWallpaperTestUser @script:parameters}|Should -Throw '*Existing elevation*'
      @(Get-ChildItem -LiteralPath $script:root).Count|Should -Be 0
    }
    It 'refuses a pre-existing account or profile instead of adopting it: <Collision>' -TestCases @(@{Collision='Account'},@{Collision='Profile'}) {
      param($Collision)
      if($Collision -eq 'Account'){$script:account=[pscustomobject]@{Name=$script:selection.Name;Sid=$script:sid}}else{$script:profileDirectory=$true}
      {New-RideWallpaperTestUser @script:parameters}|Should -Throw '*already exists*'
      Should -Invoke New-RideWallpaperUserNative -Times 0 -Exactly
      @(Get-ChildItem -LiteralPath $script:root).Count|Should -Be 0
    }
    It 'requires a synthetic SecureString for actual creation without recording plaintext' {
      $script:parameters.Remove('Password')
      {New-RideWallpaperTestUser @script:parameters}|Should -Throw '*synthetic SecureString*'
      @(Get-ChildItem -LiteralPath $script:root).Count|Should -Be 0
    }
    It 'retains incomplete creation intent and refuses blind retry without a saved SID' {
      Mock New-RideWallpaperUserNative {throw 'Synthetic provider failure.'}
      {New-RideWallpaperTestUser @script:parameters}|Should -Throw '*creation incomplete*'
      Test-Path -LiteralPath ($script:selection.Prefix+'.intent.json')|Should -BeTrue
      {New-RideWallpaperTestUser @script:parameters}|Should -Throw '*Incomplete fixture creation*'
      Should -Invoke Remove-RideWallpaperUserNative -Times 0 -Exactly
    }
    It 'preserves a saved SID after group failure so the owned account can be removed' {
      Mock Add-RideWallpaperUserGroup {throw 'Synthetic group failure.'}
      {New-RideWallpaperTestUser @script:parameters}|Should -Throw '*creation incomplete*'
      (Remove-RideWallpaperTestUser @script:remove).Status|Should -Be Removed
      Should -Invoke Remove-RideWallpaperUserProfileNative -Times 0 -Exactly
      Should -Invoke Remove-RideWallpaperUserNative -Times 1 -Exactly
    }
    It 'observes a real-profile-shaped snapshot without writing or claiming sign-in acceptance' {
      $null=New-RideWallpaperTestUser @script:parameters
      $script:profile=[pscustomobject]@{Sid=$script:sid;Path=('C:\Users\'+$script:selection.Name);Loaded=$true;Special=$false;Roaming=$false;Status=0;RefCount=1};$script:profileDirectory=$true;$script:sessions=1
      $count=@(Get-ChildItem -LiteralPath $script:root).Count
      $result=Get-RideWallpaperTestUser @script:observe
      $result.Status|Should -Be Observed;$result.State.Profile.Loaded|Should -BeTrue
      $result.NativeAcceptancePassed|Should -BeFalse
      @(Get-ChildItem -LiteralPath $script:root).Count|Should -Be $count
      Should -Invoke Disable-RideWallpaperUserNative -Times 0 -Exactly
    }
    It 'cleans up the unloaded exact profile before deleting the account and supports repeated cleanup' {
      $null=New-RideWallpaperTestUser @script:parameters
      $script:profile=[pscustomobject]@{Sid=$script:sid;Path=('C:\Users\'+$script:selection.Name);Loaded=$false;Special=$false;Roaming=$false;Status=0;RefCount=0};$script:profileDirectory=$true
      $result=Remove-RideWallpaperTestUser @script:remove
      $result.Status|Should -Be Removed;$result.NativeAcceptancePassed|Should -BeFalse
      (Remove-RideWallpaperTestUser @script:remove).Status|Should -Be AlreadyRemoved
      ($script:events -join ';')|Should -BeExactly 'Create;AddUsers;Disable;DeleteProfile;DeleteUser'
      ($script:sentinel|ConvertTo-Json -Compress)|Should -BeExactly $script:sentinelBefore
    }
    It 'previews cleanup without disabling the account or creating an intent' {
      $null=New-RideWallpaperTestUser @script:parameters
      (Remove-RideWallpaperTestUser @script:remove -WhatIf).Status|Should -Be Preview
      $script:account.Enabled|Should -BeTrue
      Test-Path -LiteralPath ($script:selection.Prefix+'.cleanup-intent.json')|Should -BeFalse
      Should -Invoke Disable-RideWallpaperUserNative -Times 0 -Exactly
    }
    It 'refuses an active or unsafe profile before disabling anything: <Condition>' -TestCases @(@{Condition='Session'},@{Condition='Loaded'},@{Condition='RefCount'},@{Condition='Special'},@{Condition='Roaming'},@{Condition='Temporary'},@{Condition='Moved'}) {
      param($Condition)
      $null=New-RideWallpaperTestUser @script:parameters
      $script:profile=[pscustomobject]@{Sid=$script:sid;Path=('C:\Users\'+$script:selection.Name);Loaded=$false;Special=$false;Roaming=$false;Status=0;RefCount=0};$script:profileDirectory=$true
      switch($Condition){Session {$script:sessions=1};Loaded {$script:profile.Loaded=$true};RefCount {$script:profile.RefCount=1};Special {$script:profile.Special=$true};Roaming {$script:profile.Roaming=$true};Temporary {$script:profile.Status=1};Moved {$script:profile.Path='C:\Users\UnrelatedUser'}}
      {Remove-RideWallpaperTestUser @script:remove}|Should -Throw
      Should -Invoke Disable-RideWallpaperUserNative -Times 0 -Exactly
      Should -Invoke Remove-RideWallpaperUserProfileNative -Times 0 -Exactly
      $script:account.Enabled|Should -BeTrue
    }
    It 'refuses replaced, renamed or promoted account ownership: <Condition>' -TestCases @(@{Condition='Replaced'},@{Condition='Renamed'},@{Condition='Description'},@{Condition='Administrator'}) {
      param($Condition)
      $null=New-RideWallpaperTestUser @script:parameters
      switch($Condition){Replaced {$script:account.Sid='S-1-5-21-101-202-303-1009'};Renamed {$script:account.Name='AnotherUser'};Description {$script:account.Description='Reused'};Administrator {$script:groups+=@('S-1-5-32-544')}}
      {Remove-RideWallpaperTestUser @script:remove}|Should -Throw
      Should -Invoke Disable-RideWallpaperUserNative -Times 0 -Exactly
      Should -Invoke Remove-RideWallpaperUserNative -Times 0 -Exactly
    }
    It 'refuses an orphan directory instead of falling back to recursive deletion' {
      $null=New-RideWallpaperTestUser @script:parameters;$script:profileDirectory=$true
      {Remove-RideWallpaperTestUser @script:remove}|Should -Throw '*registered profile disagree*'
      Should -Invoke Remove-RideWallpaperUserProfileNative -Times 0 -Exactly
    }
    It 'retains a disabled account after profile-deletion failure and permits a later retry' {
      $null=New-RideWallpaperTestUser @script:parameters
      $script:profile=[pscustomobject]@{Sid=$script:sid;Path=('C:\Users\'+$script:selection.Name);Loaded=$false;Special=$false;Roaming=$false;Status=0;RefCount=0};$script:profileDirectory=$true
      Mock Remove-RideWallpaperUserProfileNative {throw 'Synthetic deletion failure.'}
      {Remove-RideWallpaperTestUser @script:remove}|Should -Throw '*RemoveProfile*'
      $script:account.Enabled|Should -BeFalse
      @(Get-ChildItem -LiteralPath $script:root -Filter '*.failure.*.json').Count|Should -Be 1
      Should -Invoke Remove-RideWallpaperUserNative -Times 0 -Exactly
      Mock Remove-RideWallpaperUserProfileNative {$script:profile=$null;$script:profileDirectory=$false}
      (Remove-RideWallpaperTestUser @script:remove).Status|Should -Be Removed
    }
    It 'finishes cleanup when the account was removed but its receipt write was interrupted' {
      $null=New-RideWallpaperTestUser @script:parameters
      Mock Write-RideWallpaperUserRecord {throw 'Synthetic receipt failure.'} -ParameterFilter {$Path -like '*.removed.json'}
      {Remove-RideWallpaperTestUser @script:remove}|Should -Throw '*Verify*'
      $script:account|Should -BeNullOrEmpty
      Mock Write-RideWallpaperUserRecord {
        param($Path,$Record)
        $bytes=[Text.UTF8Encoding]::new($false).GetBytes(($Record|ConvertTo-Json -Depth 15 -Compress))
        $stream=& (Get-Module RIDE.PrivateFiles) {param($p) New-RidePrivateFileStream -Path $p -Scope User} $Path
        try{$stream.Write($bytes,0,$bytes.Length);$stream.Flush($true)}finally{$stream.Dispose()}
      } -ParameterFilter {$Path -like '*.removed.json'}
      (Remove-RideWallpaperTestUser @script:remove).Status|Should -Be Removed
      Should -Invoke Remove-RideWallpaperUserNative -Times 1 -Exactly
    }
    It 'detects a new session after disabling and preserves the profile' {
      $null=New-RideWallpaperTestUser @script:parameters
      Mock Disable-RideWallpaperUserNative {$script:account.Enabled=$false;$script:sessions=1}
      {Remove-RideWallpaperTestUser @script:remove}|Should -Throw '*RemoveProfile*'
      Should -Invoke Remove-RideWallpaperUserProfileNative -Times 0 -Exactly
      Should -Invoke Remove-RideWallpaperUserNative -Times 0 -Exactly
    }
    It 'refuses a changed saved profile path or target before cleanup' {
      $null=New-RideWallpaperTestUser @script:parameters
      $script:context.Revision=9999
      {Remove-RideWallpaperTestUser @script:remove}|Should -Throw '*target changed*'
      $script:context.Revision=9711
      $path=$script:selection.Prefix+'.created.json';$r=Read-RideWallpaperUserRecord $path;$r.ProfilePath='C:\Users\UnrelatedUser'
      [IO.File]::WriteAllText($path,($r|ConvertTo-Json -Depth 15))
      {Remove-RideWallpaperTestUser @script:remove}|Should -Throw '*ownership record differs*'
      Should -Invoke Disable-RideWallpaperUserNative -Times 0 -Exactly
    }
    It 'does not recreate a removed fixture or accept unexplained external removal' {
      $null=New-RideWallpaperTestUser @script:parameters
      $script:account=$null
      {Remove-RideWallpaperTestUser @script:remove}|Should -Throw '*without a cleanup intent*'
      {New-RideWallpaperTestUser @script:parameters}|Should -Throw '*do not recreate*'
      Should -Invoke New-RideWallpaperUserNative -Times 1 -Exactly
    }
    It 'refuses a corrupt cleanup receipt instead of reporting repeated success' {
      $null=New-RideWallpaperTestUser @script:parameters
      $null=Remove-RideWallpaperTestUser @script:remove
      $path=$script:selection.Prefix+'.removed.json';$r=Read-RideWallpaperUserRecord $path;$r.ProfilePath='C:\Users\UnrelatedUser'
      [IO.File]::WriteAllText($path,($r|ConvertTo-Json -Depth 15))
      {Remove-RideWallpaperTestUser @script:remove}|Should -Throw '*receipt identity differs*'
      Should -Invoke Remove-RideWallpaperUserNative -Times 1 -Exactly
    }
    It 'completes the current request for initial creation without requiring saved state' {
      $prior=$env:RIDE_TEST_RUN_ID
      try{
        $env:RIDE_TEST_RUN_ID=$script:id
        $r=@(& $script:WallpaperUserCompleter 'New-RideWallpaperTestUser' 'RunId' $script:id.Substring(0,2) $null @{})
        $r.Count|Should -Be 1;$r[0].CompletionText|Should -BeExactly $script:id
        Should -Invoke Get-RideWallpaperUserContext -Times 0 -Exactly
      }finally{$env:RIDE_TEST_RUN_ID=$prior}
    }
    It 'completes saved request IDs once without inspecting Windows or reading private content' {
      foreach($purpose in @('control','firstlogon','recovery')){[IO.File]::WriteAllText((Join-Path $script:root ($script:id+'.wallpaper-user.'+$purpose+'.created.json')),'not a report')}
      $r=@(& $script:WallpaperUserCompleter 'Remove-RideWallpaperTestUser' 'RunId' $script:id.Substring(0,2) $null @{StateDirectory=$script:root})
      $r.Count|Should -Be 1;$r[0].CompletionText|Should -BeExactly $script:id
      Should -Invoke Get-RideWallpaperUserContext -Times 0 -Exactly
      Should -Invoke Read-RideWallpaperUserRecord -Times 0 -Exactly
    }
  }
}
