<#
.SYNOPSIS
  Verify per-user lock-screen image lifecycle and exact recovery guards.
.DESCRIPTION
  Uses a synthetic user identity and a mocked Windows personalization API.
.NOTES
  Requires Pester 5, Windows PowerShell 5.1 or PowerShell 7 on Windows.
#>
BeforeAll { Import-Module (Join-Path $PSScriptRoot '../modules/RIDE.UserLockScreen.psm1') -Force }
Describe 'Per-user lock-screen image lifecycle' {
  InModuleScope RIDE.UserLockScreen {
    BeforeEach {
      $script:root=Join-Path $TestDrive ([guid]::NewGuid().ToString('N'));$script:assets=Join-Path $script:root 'Images';$script:state=Join-Path $script:root 'State'
      $null=New-Item -ItemType Directory -Path $script:assets,$script:state
      $script:source=Join-Path $script:root 'input.png';$bitmap=[Drawing.Bitmap]::new(2,2)
      try{$bitmap.Save($script:source,[Drawing.Imaging.ImageFormat]::Png)}finally{$bitmap.Dispose()}
      $script:oldImage=Join-Path $script:root 'old.jpg';[IO.File]::WriteAllText($script:oldImage,'synthetic prior image')
      $script:oldHash=(Get-FileHash -LiteralPath $script:oldImage -Algorithm SHA256).Hash
      $script:currentUri=([uri]$script:oldImage).AbsoluteUri
      $script:context=[pscustomobject]@{ComputerName='RIDE-Synthetic-VM';UserSid='S-1-5-21-1000';UserProfile=$script:root;Build='26100';Architecture='AMD64';Interactive=$true}
      $script:selection=@{Path=$script:source;ExpectedSha256=(Get-FileHash -LiteralPath $script:source -Algorithm SHA256).Hash;AssetDirectory=$script:assets;StateDirectory=$script:state;ExpectedComputerName=$script:context.ComputerName;ExpectedUserSid=$script:context.UserSid;ExpectedBuild=$script:context.Build;Confirm=$false}
      Mock Get-RideUserLockScreenContext {$script:context}
      Mock Get-RideUserLockScreenImageUri {$script:currentUri}
      Mock Invoke-RideUserLockScreenSet {$script:currentUri=([uri]$Path).AbsoluteUri}
    }
    It 'applies to the current user and restores the exact prior image URI and bytes' {
      $applied=Set-RideUserLockScreenImage @script:selection
      $applied.Status|Should -Be 'Applied'
      $applied.Scope|Should -Be 'User'
      $script:currentUri|Should -BeExactly ([uri]$applied.AssetPath).AbsoluteUri
      $state=Get-RideUserLockScreenState -AssetDirectory $script:assets -StateDirectory $script:state
      $state.Owned|Should -BeTrue
      $state.SourceSha256|Should -BeExactly $script:selection.ExpectedSha256
      $restored=Restore-RideUserLockScreenImage -RunId $applied.RunId -AssetDirectory $script:assets -StateDirectory $script:state -Confirm:$false
      $restored.Status|Should -Be 'Restored'
      $script:currentUri|Should -BeExactly ([uri]$script:oldImage).AbsoluteUri
      (Get-FileHash -LiteralPath $script:oldImage -Algorithm SHA256).Hash|Should -BeExactly $script:oldHash
      Test-Path -LiteralPath $applied.AssetPath|Should -BeFalse
    }
    It 'refuses dynamic or opaque prior modes before persistence and image writes' {
      $script:currentUri='ms-appx:///Windows/lockscreen.jpg'
      {Set-RideUserLockScreenImage @script:selection}|Should -Throw '*dynamic or opaque*'
      @(Get-ChildItem -LiteralPath $script:state -File).Count|Should -Be 0
      @(Get-ChildItem -LiteralPath $script:assets -File).Count|Should -Be 0
      Should -Invoke Invoke-RideUserLockScreenSet -Times 0 -Exactly
    }
    It 'previews without creating recovery files or changing the current URI' {
      (Set-RideUserLockScreenImage @script:selection -WhatIf).Status|Should -Be 'Preview'
      @(Get-ChildItem -LiteralPath $script:state -File).Count|Should -Be 0
      @(Get-ChildItem -LiteralPath $script:assets -File).Count|Should -Be 0
      $script:currentUri|Should -BeExactly ([uri]$script:oldImage).AbsoluteUri
      Should -Invoke Invoke-RideUserLockScreenSet -Times 0 -Exactly
    }
    It 'rolls back an incomplete apply only when the captured transaction state still matches' {
      $script:setCalls=0
      Mock Invoke-RideUserLockScreenSet {
        $script:currentUri=([uri]$Path).AbsoluteUri
        $script:setCalls++
        if($script:setCalls -eq 1){throw 'synthetic failure after the Windows API changed the URI'}
      }
      {Set-RideUserLockScreenImage @script:selection}|Should -Throw '*Automatic rollback was attempted*'
      $script:currentUri|Should -BeExactly ([uri]$script:oldImage).AbsoluteUri
      @(Get-ChildItem -LiteralPath $script:assets -File).Count|Should -Be 0
      @(Get-ChildItem -LiteralPath $script:state -Filter '*.user-lock.intent.json').Count|Should -Be 1
    }
    It 'refuses a changed original source and preserves the active image during restore' {
      $applied=Set-RideUserLockScreenImage @script:selection
      [IO.File]::WriteAllText($script:oldImage,'changed prior image')
      {Restore-RideUserLockScreenImage -RunId $applied.RunId -AssetDirectory $script:assets -StateDirectory $script:state -Confirm:$false}|Should -Throw '*source changed*'
      $script:currentUri|Should -BeExactly ([uri]$applied.AssetPath).AbsoluteUri
      Test-Path -LiteralPath $applied.AssetPath|Should -BeTrue
    }
  }
}
