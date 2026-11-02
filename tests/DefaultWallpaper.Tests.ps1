<#
.SYNOPSIS
  Verify owned first-logon wallpaper lifecycle without changing Windows policy.
.DESCRIPTION
  Uses real temporary PNG/state files. Target, policy, asset directory permission
  and machine ACL writers are mocked. Private test files use current-user ACLs.
.EXAMPLE
  Invoke-Pester ./tests/DefaultWallpaper.Tests.ps1
.NOTES
  Pester 5, native Windows PowerShell 5.1/7. Version: 0.1.0.
#>
BeforeDiscovery {Import-Module (Join-Path $PSScriptRoot '../modules/RIDE.DefaultWallpaper.psm1') -Force}
Describe 'Machine first-logon wallpaper candidate lifecycle' {
  InModuleScope RIDE.DefaultWallpaper {
    BeforeAll {Add-Type -AssemblyName System.Drawing}
    BeforeEach {
      $script:root=Join-Path $TestDrive ([guid]::NewGuid().ToString('N'))
      $script:assets=Join-Path $script:root 'Images';$script:state=Join-Path $script:root 'State'
      $null=New-Item -ItemType Directory -Path $script:assets,$script:state
      $script:source=Join-Path $script:root 'input.png';$bitmap=[Drawing.Bitmap]::new(2,3)
      try{$bitmap.Save($script:source,[Drawing.Imaging.ImageFormat]::Png)}finally{$bitmap.Dispose()}
      $script:hash=(Get-FileHash -LiteralPath $script:source).Hash
      $script:context=[pscustomobject]@{ComputerName='RIDE-Synthetic-VM';Build='26300';EditionId='EnterpriseEval';Revision=9711;InstallationType='Client';NativeProcess=$true;Architecture='AMD64';Guest=$true;Administrator=$true}
      $script:registry=[pscustomobject]@{Exists=$true;Security='unchanged-key-security';Rows=@([pscustomobject]@{Name='Unrelated';Kind='DWord';Value=42});SubKeys=@('KeepChild')}
      $script:before=$script:registry|ConvertTo-Json -Depth 10|ConvertFrom-Json
      $script:selection=@{Path=$script:source;ExpectedSha256=$script:hash;AssetDirectory=$script:assets;StateDirectory=$script:state;ExpectedComputerName='RIDE-Synthetic-VM';ExpectedBuild='26300';ExpectedEditionId='EnterpriseEval';AllowCandidate=$true;Confirm=$false}
      Mock Get-RideDefaultWallpaperContext {$script:context}
      Mock Get-RideDefaultWallpaperProfiles {@([pscustomobject]@{Sid='S-1-5-21-123-1000';Path='C:\Users\SyntheticExisting'})}
      Mock Assert-RideDefaultWallpaperAssetDirectory {'unchanged-directory-security'}
      Mock Assert-RideDefaultWallpaperAssetSecurity {}
      Mock Get-RideDefaultWallpaperRegistry {$script:registry|ConvertTo-Json -Depth 10|ConvertFrom-Json}
      Mock Set-RideDefaultWallpaperRegistry {
        param($Row,$RemoveCreatedKey)
        if($RemoveCreatedKey){$script:registry=[pscustomobject]@{Exists=$false;Security=$null;Rows=@();SubKeys=@()};return}
        $rows=@($script:registry.Rows|Where-Object Name -INE 'ThemeFile')
        if($null -ne $Row){$rows+=@([pscustomobject]@{Name='ThemeFile';Kind=$Row.Kind;Value=$Row.Value})}
        $script:registry=[pscustomobject]@{Exists=$true;Security='unchanged-key-security';Rows=@($rows|Sort-Object Name);SubKeys=@($script:registry.SubKeys)}
      }
      Mock New-RideDefaultWallpaperAssetStream {param($Path);[IO.File]::Open($Path,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None)}
      Mock New-RidePrivateFileStream {
        param($Path,$Scope)
        if($Scope -cne 'Machine'){throw 'Expected machine state.'}
        & (Get-Module RIDE.PrivateFiles) {param($p) New-RidePrivateFileStream -Path $p -Scope User} $Path
      }
      Mock Read-RidePrivateFileBytes {
        param($Path,$MaximumBytes,$Scope)
        if($Scope -cne 'Machine'){throw 'Expected machine state read.'}
        & (Get-Module RIDE.PrivateFiles) {param($p,$bound) Read-RidePrivateFileBytes -Path $p -MaximumBytes $bound -Scope User} $Path $MaximumBytes
      }
    }
    It 'applies, repeats and restores prior absence while preserving unrelated policy and source bytes' {
      $applied=Set-RideDefaultWallpaperImage @script:selection
      $applied.Status|Should -Be Applied;$applied.NativeVisualAcceptance|Should -BeFalse
      (Get-FileHash -LiteralPath $applied.AssetPath).Hash|Should -BeExactly $script:hash
      (Get-FileHash -LiteralPath $script:source).Hash|Should -BeExactly $script:hash
      (Set-RideDefaultWallpaperImage @script:selection).Status|Should -Be AlreadyDesired
      @(Get-ChildItem -LiteralPath $script:state -File).Count|Should -Be 2
      (Restore-RideDefaultWallpaperRun -RunId $applied.RunId -StateDirectory $script:state -AllowCandidate -Confirm:$false).Status|Should -Be Restored
      Test-RideDefaultWallpaperEqual $script:registry $script:before|Should -BeTrue
      Test-Path -LiteralPath $applied.AssetPath|Should -BeFalse
      (Restore-RideDefaultWallpaperRun -RunId $applied.RunId -StateDirectory $script:state -AllowCandidate -Confirm:$false).Status|Should -Be AlreadyRestored
      Should -Invoke Set-RideDefaultWallpaperRegistry -Times 2 -Exactly
    }
    It 'recovers a pre-existing expandable string without touching its referenced image' {
      $oldImage=Join-Path $script:root 'old.png';[IO.File]::WriteAllText($oldImage,'unrelated original bytes')
      $script:registry.Rows=@([pscustomobject]@{Name='ThemeFile';Kind='ExpandString';Value='%ProgramData%\Previous\image.png'})+$script:registry.Rows
      $before=Get-RideDefaultWallpaperRegistry
      $applied=Set-RideDefaultWallpaperImage @script:selection
      $null=Restore-RideDefaultWallpaperRun -RunId $applied.RunId -StateDirectory $script:state -AllowCandidate -Confirm:$false
      Test-RideDefaultWallpaperEqual $before $script:registry|Should -BeTrue
      [IO.File]::ReadAllText($oldImage)|Should -BeExactly 'unrelated original bytes'
    }
    It 'recovers an absent personalization key without claiming visible image recovery' {
      $script:registry=[pscustomobject]@{Exists=$false;Security=$null;Rows=@();SubKeys=@()}
      $applied=Set-RideDefaultWallpaperImage @script:selection
      $result=Restore-RideDefaultWallpaperRun -RunId $applied.RunId -StateDirectory $script:state -AllowCandidate -Confirm:$false
      $result.NativeVisualAcceptance|Should -BeFalse;$script:registry.Exists|Should -BeFalse
      Should -Invoke Set-RideDefaultWallpaperRegistry -Times 1 -Exactly -ParameterFilter {$RemoveCreatedKey -eq $true}
    }
    It 'previews apply and restore without changing files, policy or state' {
      (Set-RideDefaultWallpaperImage @script:selection -WhatIf).Status|Should -Be Preview
      @(Get-ChildItem -LiteralPath $script:state -File).Count|Should -Be 0
      @(Get-ChildItem -LiteralPath $script:assets -File).Count|Should -Be 0
      Should -Invoke Set-RideDefaultWallpaperRegistry -Times 0 -Exactly
      $applied=Set-RideDefaultWallpaperImage @script:selection
      (Restore-RideDefaultWallpaperRun -RunId $applied.RunId -StateDirectory $script:state -WhatIf).Status|Should -Be Preview
      Test-Path -LiteralPath $applied.AssetPath|Should -BeTrue
      Should -Invoke Set-RideDefaultWallpaperRegistry -Times 1 -Exactly
    }
    It 'refuses source mismatches before persistence or any writer' {
      $script:selection.ExpectedSha256='0'*64
      {Set-RideDefaultWallpaperImage @script:selection}|Should -Throw '*hash differs*'
      Should -Invoke New-RidePrivateFileStream -Times 0 -Exactly
      Should -Invoke Set-RideDefaultWallpaperRegistry -Times 0 -Exactly
    }
    It 'refuses an unsupported target and missing existing elevation or candidate selection' {
      $script:context.EditionId='Professional'
      {Set-RideDefaultWallpaperImage @script:selection}|Should -Throw '*Enterprise/Education*'
      $script:context.EditionId='EnterpriseEval';$script:context.Guest=$false
      {Set-RideDefaultWallpaperImage @script:selection}|Should -Throw '*Hyper-V guest*'
      $script:context.Guest=$true;$script:context.Administrator=$false
      {Set-RideDefaultWallpaperImage @script:selection}|Should -Throw '*Existing elevation*'
      $script:context.Administrator=$true;$script:selection.AllowCandidate=$false
      {Set-RideDefaultWallpaperImage @script:selection}|Should -Throw '*AllowCandidate*'
      Should -Invoke New-RidePrivateFileStream -Times 0 -Exactly
    }
    It 'refuses a different explicitly selected computer before reading source or state' {
      $script:selection.ExpectedComputerName='Different-VM'
      {Set-RideDefaultWallpaperImage @script:selection}|Should -Throw '*target differs*'
      Should -Invoke New-RidePrivateFileStream -Times 0 -Exactly
    }
    It 'refuses a malformed prior policy type without changing it' {
      $script:registry.Rows+=@([pscustomobject]@{Name='ThemeFile';Kind='DWord';Value=1})
      {Set-RideDefaultWallpaperImage @script:selection}|Should -Throw '*string policy*'
      Should -Invoke Set-RideDefaultWallpaperRegistry -Times 0 -Exactly
    }
    It 'never starts image or policy writes when recovery capture fails' {
      Mock New-RidePrivateFileStream {throw 'Synthetic private storage failure.'}
      {Set-RideDefaultWallpaperImage @script:selection}|Should -Throw '*storage failure*'
      Should -Invoke New-RideDefaultWallpaperAssetStream -Times 0 -Exactly
      Should -Invoke Set-RideDefaultWallpaperRegistry -Times 0 -Exactly
    }
    It 'retains intent and owned image after a policy failure and refuses incomplete automatic recovery' {
      Mock Set-RideDefaultWallpaperRegistry {throw 'Synthetic registry failure.'}
      {Set-RideDefaultWallpaperImage @script:selection}|Should -Throw '*apply incomplete*Run ID*'
      $records=@(Get-ChildItem -LiteralPath $script:state -File);$records.Count|Should -Be 1
      $runId=$records[0].Name.Substring(0,32)
      @(Get-ChildItem -LiteralPath $script:assets -File).Count|Should -Be 2
      {Restore-RideDefaultWallpaperRun -RunId $runId -StateDirectory $script:state -AllowCandidate -Confirm:$false}|Should -Throw
      $intent=Read-RideDefaultWallpaperRun $script:state $runId intent
      Test-RideDefaultWallpaperEqual $intent.Before $script:before|Should -BeTrue
    }
    It 'retains intent and never writes policy when image creation fails' {
      Mock New-RideDefaultWallpaperAssetStream {throw 'Synthetic image creation failure.'}
      {Set-RideDefaultWallpaperImage @script:selection}|Should -Throw '*apply incomplete*'
      @(Get-ChildItem -LiteralPath $script:state -File).Count|Should -Be 1
      Should -Invoke Set-RideDefaultWallpaperRegistry -Times 0 -Exactly
    }
    It 'detects policy drift after intent capture before creating the image' {
      $script:contextCalls=0
      Mock Get-RideDefaultWallpaperContext {
        $script:contextCalls++
        if($script:contextCalls -eq 2){$script:registry.Rows+=@([pscustomobject]@{Name='Concurrent';Kind='String';Value='preserve'})}
        $script:context
      }
      {Set-RideDefaultWallpaperImage @script:selection}|Should -Throw '*changed during preflight*'
      Should -Invoke New-RideDefaultWallpaperAssetStream -Times 0 -Exactly
      Should -Invoke Set-RideDefaultWallpaperRegistry -Times 0 -Exactly
    }
    It 'refuses policy drift during repeat or recovery instead of removing owned content' {
      $applied=Set-RideDefaultWallpaperImage @script:selection
      $script:registry.Rows+=@([pscustomobject]@{Name='AnotherWriter';Kind='DWord';Value=1})
      {Set-RideDefaultWallpaperImage @script:selection}|Should -Throw '*changed*'
      {Restore-RideDefaultWallpaperRun -RunId $applied.RunId -StateDirectory $script:state -AllowCandidate -Confirm:$false}|Should -Throw '*conflicts*'
      Test-Path -LiteralPath $applied.AssetPath|Should -BeTrue
      Should -Invoke Set-RideDefaultWallpaperRegistry -Times 1 -Exactly
    }
    It 'refuses replaced image bytes and preserves them' {
      $applied=Set-RideDefaultWallpaperImage @script:selection
      $bytes=[IO.File]::ReadAllBytes($applied.AssetPath);$bytes[30]=$bytes[30] -bxor 1
      [IO.File]::WriteAllBytes($applied.AssetPath,$bytes)
      {Restore-RideDefaultWallpaperRun -RunId $applied.RunId -StateDirectory $script:state -AllowCandidate -Confirm:$false}|Should -Throw '*conflicts*'
      Test-Path -LiteralPath $applied.AssetPath|Should -BeTrue
    }
    It 'refuses timestamp drift even when image bytes match' {
      $applied=Set-RideDefaultWallpaperImage @script:selection
      [IO.File]::SetLastWriteTimeUtc($applied.AssetPath,[datetime]::UtcNow.AddDays(-2))
      {Restore-RideDefaultWallpaperRun -RunId $applied.RunId -StateDirectory $script:state -AllowCandidate -Confirm:$false}|Should -Throw '*conflicts*'
      (Get-FileHash -LiteralPath $applied.AssetPath).Hash|Should -BeExactly $script:hash
    }
    It 'requires candidate permission again for actual recovery' {
      $applied=Set-RideDefaultWallpaperImage @script:selection
      {Restore-RideDefaultWallpaperRun -RunId $applied.RunId -StateDirectory $script:state -Confirm:$false}|Should -Throw '*AllowCandidate*'
      Test-Path -LiteralPath $applied.AssetPath|Should -BeTrue
      Should -Invoke Set-RideDefaultWallpaperRegistry -Times 1 -Exactly
    }
    It 'does not mistake a broken reparse entry for a restored absent image' {
      $applied=Set-RideDefaultWallpaperImage @script:selection
      [IO.File]::Delete($applied.AssetPath);$script:registry=$script:before
      Mock Get-Item {[pscustomobject]@{Attributes=[IO.FileAttributes]::ReparsePoint;PSIsContainer=$false}}
      {Restore-RideDefaultWallpaperRun -RunId $applied.RunId -StateDirectory $script:state -AllowCandidate -Confirm:$false}|Should -Throw '*reparse point*'
    }
    It 'refuses drive-root state paths instead of converting them to drive-relative paths' {
      {Resolve-RideDefaultWallpaperDirectory ([IO.Path]::GetPathRoot($TestDrive))}|Should -Throw '*below the drive root*'
    }
    It 'refuses directory security or target drift during recovery' {
      $applied=Set-RideDefaultWallpaperImage @script:selection
      Mock Assert-RideDefaultWallpaperAssetDirectory {'changed-security'}
      {Restore-RideDefaultWallpaperRun -RunId $applied.RunId -StateDirectory $script:state -AllowCandidate -Confirm:$false}|Should -Throw '*directory changed*'
      $script:context.Revision=9999
      {Restore-RideDefaultWallpaperRun -RunId $applied.RunId -StateDirectory $script:state -AllowCandidate -Confirm:$false}|Should -Throw '*target changed*'
    }
    It 'can finish owned file removal after policy restoration was interrupted' {
      $applied=Set-RideDefaultWallpaperImage @script:selection
      $script:registry=$script:before
      (Restore-RideDefaultWallpaperRun -RunId $applied.RunId -StateDirectory $script:state -AllowCandidate -Confirm:$false).Status|Should -Be Restored
      Should -Invoke Set-RideDefaultWallpaperRegistry -Times 1 -Exactly
      Test-Path -LiteralPath $applied.AssetPath|Should -BeFalse
    }
    It 'refuses a forged owned image path inside otherwise private recovery state' {
      $applied=Set-RideDefaultWallpaperImage @script:selection
      $path=Get-RideDefaultWallpaperRunPath $script:state $applied.RunId intent
      $intent=Read-RideDefaultWallpaperRun $script:state $applied.RunId intent
      $intent.AssetPath=$script:source
      [IO.File]::WriteAllText($path,($intent|ConvertTo-Json -Depth 15))
      {Restore-RideDefaultWallpaperRun -RunId $applied.RunId -StateDirectory $script:state -AllowCandidate -Confirm:$false}|Should -Throw '*ownership*'
      (Get-FileHash -LiteralPath $script:source).Hash|Should -BeExactly $script:hash
    }
    It 'constructs a protected public-read image ACL distinct from private recovery ACLs' {
      $acl=New-RideDefaultWallpaperAssetSecurity
      $acl.AreAccessRulesProtected|Should -BeTrue
      $acl.GetOwner([Security.Principal.SecurityIdentifier]).Value|Should -BeExactly 'S-1-5-32-544'
      $rules=@($acl.GetAccessRules($true,$true,[Security.Principal.SecurityIdentifier]));$rules.Count|Should -Be 3
      $users=@($rules|Where-Object {$_.IdentityReference.Value -ceq 'S-1-5-32-545'})
      $users.Count|Should -Be 1
      ($users[0].FileSystemRights -band [Security.AccessControl.FileSystemRights]::Write)|Should -Be 0
      ($users[0].FileSystemRights -band [Security.AccessControl.FileSystemRights]::ReadAndExecute)|Should -Be ([Security.AccessControl.FileSystemRights]::ReadAndExecute)
    }
    It 'binds the first-logon theme policy to its generated theme and selected image' {
      $applied=Set-RideDefaultWallpaperImage @script:selection
      (Get-RideDefaultWallpaperRow (Get-RideDefaultWallpaperRegistry)).Value|Should -BeExactly $applied.ThemePath
      $bytes=[IO.File]::ReadAllBytes($applied.ThemePath)
      $bytes[0]|Should -Be 255;$bytes[1]|Should -Be 254
      $content=[Text.Encoding]::Unicode.GetString($bytes,2,$bytes.Length-2)
      $content|Should -Match ([regex]::Escape('Wallpaper='+$applied.AssetPath))
      $content|Should -Match '\[VisualStyles\]';$content|Should -Match '\[MasterThemeSelector\]'
      $content|Should -Not -Match '\[Slideshow\]|SCRNSAVE|\[Control Panel\\Cursors\]'
      $null=Restore-RideDefaultWallpaperRun -RunId $applied.RunId -StateDirectory $script:state -AllowCandidate -Confirm:$false
      Test-Path -LiteralPath $applied.ThemePath|Should -BeFalse
    }
    It 'preserves changed theme bytes during repeat and recovery' {
      $applied=Set-RideDefaultWallpaperImage @script:selection
      [IO.File]::AppendAllText($applied.ThemePath,'external change')
      {Set-RideDefaultWallpaperImage @script:selection}|Should -Throw '*changed*'
      {Restore-RideDefaultWallpaperRun -RunId $applied.RunId -StateDirectory $script:state -AllowCandidate -Confirm:$false}|Should -Throw '*conflicts*'
      Test-Path -LiteralPath $applied.ThemePath|Should -BeTrue
    }
    It 'retains assets when new users may have consumed the first-logon theme' {
      $applied=Set-RideDefaultWallpaperImage @script:selection
      Mock Get-RideDefaultWallpaperProfiles {@([pscustomobject]@{Sid='S-1-5-21-123-1000';Path='C:\Users\SyntheticExisting'},[pscustomobject]@{Sid='S-1-5-21-123-1001';Path='C:\Users\SyntheticNew'})}
      {Restore-RideDefaultWallpaperRun -RunId $applied.RunId -StateDirectory $script:state -AllowCandidate -Confirm:$false}|Should -Throw '*profiles changed since apply*'
      Test-Path -LiteralPath $applied.ThemePath|Should -BeTrue
      Test-Path -LiteralPath $applied.AssetPath|Should -BeTrue
      Should -Invoke Set-RideDefaultWallpaperRegistry -Times 1 -Exactly
    }
    It 'can finish image removal after the captured policy and owned theme were already recovered' {
      $applied=Set-RideDefaultWallpaperImage @script:selection
      $script:registry=$script:before;[IO.File]::Delete($applied.ThemePath)
      (Restore-RideDefaultWallpaperRun -RunId $applied.RunId -StateDirectory $script:state -AllowCandidate -Confirm:$false).Status|Should -Be Restored
      Test-Path -LiteralPath $applied.AssetPath|Should -BeFalse
      Should -Invoke Set-RideDefaultWallpaperRegistry -Times 1 -Exactly
    }
    It 'refuses a missing theme while the changed policy still references it' {
      $applied=Set-RideDefaultWallpaperImage @script:selection
      [IO.File]::Delete($applied.ThemePath)
      {Restore-RideDefaultWallpaperRun -RunId $applied.RunId -StateDirectory $script:state -AllowCandidate -Confirm:$false}|Should -Throw '*conflicts*'
      Test-Path -LiteralPath $applied.AssetPath|Should -BeTrue
    }
    It 'does not publish policy when owned theme creation fails' {
      Mock New-RideDefaultWallpaperAssetStream {throw 'Synthetic theme creation failure.'} -ParameterFilter {$Path.EndsWith('.theme')}
      {Set-RideDefaultWallpaperImage @script:selection}|Should -Throw '*apply incomplete*'
      Should -Invoke Set-RideDefaultWallpaperRegistry -Times 0 -Exactly
      @(Get-ChildItem -LiteralPath $script:assets -File).Count|Should -Be 1
    }
    It 'refuses user-profile drift between private capture and file mutation' {
      $script:profileReads=0
      Mock Get-RideDefaultWallpaperProfiles {
        $script:profileReads++
        if($script:profileReads -eq 1){return @([pscustomobject]@{Sid='S-1-5-21-123-1000';Path='C:\Users\SyntheticExisting'})}
        @([pscustomobject]@{Sid='S-1-5-21-123-1001';Path='C:\Users\SyntheticNew'})
      }
      {Set-RideDefaultWallpaperImage @script:selection}|Should -Throw '*profiles changed during preflight*'
      Should -Invoke New-RideDefaultWallpaperAssetStream -Times 0 -Exactly
      Should -Invoke Set-RideDefaultWallpaperRegistry -Times 0 -Exactly
    }
    It 'rejects INI injection, environment expansion, streams and nonlocal theme paths' {
      foreach($bad in @("C:\Images\x.png`n[Slideshow]",'C:\%USERNAME%\x.png','C:\Images\x.png:extra.png','\\server\images\x.png','C:\Images\..\x.png','C:\Images\x.jpg')){
        {New-RideDefaultWallpaperTheme $bad}|Should -Throw '*canonical local PNG*'
      }
      $unicodeName='billede-'+[char]0x00E6+'.png'
      $theme=New-RideDefaultWallpaperTheme ('C:\Images\'+$unicodeName)
      [Text.Encoding]::Unicode.GetString($theme.Content)|Should -Match ([regex]::Escape($unicodeName))
      $theme.Sha256|Should -Match '^[A-F0-9]{64}$'
    }
    It 'completes saved run IDs without reading state or calling the target provider' {
      $id='a'*32;[IO.File]::WriteAllText((Get-RideDefaultWallpaperRunPath $script:state $id applied),'inert completion fixture')
      $results=@(& $script:DefaultWallpaperRunCompleter 'Restore-RideDefaultWallpaperRun' 'RunId' 'A' $null @{StateDirectory=$script:state})
      $results.Count|Should -Be 1;$results[0].CompletionText|Should -BeExactly $id
      Should -Invoke Get-RideDefaultWallpaperContext -Times 0 -Exactly
      Should -Invoke Read-RidePrivateFileBytes -Times 0 -Exactly
    }
  }
}
Describe 'First-logon wallpaper asset directory permissions' {
  InModuleScope RIDE.DefaultWallpaper {
    BeforeEach {
      $script:directory=Join-Path $TestDrive 'Parent/Images'
      $null=New-Item -ItemType Directory -Path $script:directory -Force
      $script:directoryAcl=[Security.AccessControl.DirectorySecurity]::new()
      $script:directoryAcl.SetAccessRuleProtection($true,$false)
      $script:directoryAcl.SetOwner([Security.Principal.SecurityIdentifier]::new('S-1-5-32-544'))
      foreach($sid in @('S-1-5-32-544','S-1-5-18','S-1-5-32-545')){
        $rights=if($sid -ceq 'S-1-5-32-545'){[Security.AccessControl.FileSystemRights]::ReadAndExecute}else{[Security.AccessControl.FileSystemRights]::FullControl}
        $script:directoryAcl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new([Security.Principal.SecurityIdentifier]::new($sid),$rights,[Security.AccessControl.AccessControlType]::Allow))
      }
      Mock Get-Acl {$script:directoryAcl}
    }
    It 'accepts an administrator-owned directory and parent with public read access' {
      (Assert-RideDefaultWallpaperAssetDirectory $script:directory)|Should -Not -BeNullOrEmpty
      Should -Invoke Get-Acl -Times 3 -Exactly
      $sid=[Security.Principal.SecurityIdentifier]::new('S-1-5-32-545')
      $script:directoryAcl.PurgeAccessRules($sid)
      $script:directoryAcl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new($sid,[Security.AccessControl.FileSystemRights]::ReadAndExecute,[Security.AccessControl.InheritanceFlags]'ContainerInherit,ObjectInherit',[Security.AccessControl.PropagationFlags]::InheritOnly,[Security.AccessControl.AccessControlType]::Allow))
      {Assert-RideDefaultWallpaperAssetDirectory $script:directory}|Should -Throw '*requires Builtin Users read/execute*'
    }
    It 'refuses a different directory owner without repairing permissions' {
      $script:directoryAcl.SetOwner([Security.Principal.SecurityIdentifier]::new('S-1-5-32-545'))
      {Assert-RideDefaultWallpaperAssetDirectory $script:directory}|Should -Throw '*owned*'
    }
    It 'refuses write access for ordinary users' {
      $script:directoryAcl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new([Security.Principal.SecurityIdentifier]::new('S-1-5-32-545'),[Security.AccessControl.FileSystemRights]::Write,[Security.AccessControl.AccessControlType]::Allow))
      {Assert-RideDefaultWallpaperAssetDirectory $script:directory}|Should -Throw '*modification*'
    }
    It 'refuses a deny rule that conflicts with image readability' {
      $script:directoryAcl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new([Security.Principal.SecurityIdentifier]::new('S-1-5-32-545'),[Security.AccessControl.FileSystemRights]::Read,[Security.AccessControl.AccessControlType]::Deny))
      {Assert-RideDefaultWallpaperAssetDirectory $script:directory}|Should -Throw '*conflicting*'
    }
  }
}
