<#
.SYNOPSIS
  Verify pure Terminal JSONC field ownership and recovery with synthetic byte arrays.
.DESCRIPTION
  Exercises strict bounded syntax, comments, exact Unicode/BOM/newline retention,
  declared profile identity and conflict recovery. No Terminal settings file,
  application, process environment or Windows state is read or changed.
.EXAMPLE
  Invoke-Pester .\tests\TerminalJsonc.Tests.ps1
.INPUTS
  None.
.OUTPUTS
  Pester results.
.NOTES
  Compatibility: Native Windows PowerShell 5.1 and PowerShell 7; Pester 5.x.
  Version: Repository test fixture; file integration and native acceptance are separate.
#>
BeforeAll {
  Import-Module (Join-Path (Split-Path -Parent $PSScriptRoot) 'modules/RIDE.TerminalJsonc.psm1') -Force
  $script:First='{11111111-1111-1111-1111-111111111111}'
  $script:Second='{22222222-2222-2222-2222-222222222222}'
  $script:Third='{33333333-3333-3333-3333-333333333333}'
  $script:ProfileJson='"profiles":{"defaults":{},"list":[{"guid":"'+$First+'","name":"Original"},{"guid":"'+$Second+'","name":"Next"}]}'
  function Get-TerminalFixtureBytes {
    param([string]$Text,[switch]$Bom)
    $codec=[Text.UTF8Encoding]::new([bool]$Bom,$true)
    ,([byte[]](@($codec.GetPreamble())+@($codec.GetBytes($Text))))
  }
  function Get-TerminalFixtureText {
    param([byte[]]$Bytes)
    [Text.Encoding]::UTF8.GetString($Bytes).TrimStart([char]0xfeff)
  }
}
Describe 'Terminal JSONC inspection' {
  It 'inspects root identity independently of nested fields and quoted comments' {
    $text='/* banner */ {"defaultProfile":"'+$First+'","unknown":{"defaultProfile":"nested","url":"https://host/path/*literal*/","escape":"quote: \""},'+$ProfileJson+',} // footer'
    $result=Get-RideTerminalDefaultProfileDocument (Get-TerminalFixtureBytes $text)
    $result.DefaultProfile | Should -BeExactly $First
    $result.Profiles.Count | Should -Be 2
    $result.MutationAuthorized | Should -BeFalse
    $result.AvailabilityVerified | Should -BeFalse
    $result.InstanceVerified | Should -BeFalse
  }
  It 'decodes escaped root keys and valid Unicode surrogate pairs without rewriting them' {
    $text='{"\u0064efaultProfile":"'+$First+'","label":"\uD83D\uDE80",'+$ProfileJson+'}'
    $patch=New-RideTerminalDefaultProfilePatch (Get-TerminalFixtureBytes $text) $Second
    (Get-TerminalFixtureText $patch.Bytes) | Should -BeExactly $text.Replace('"\u0064efaultProfile":"'+$First+'"','"\u0064efaultProfile":"'+$Second+'"')
  }
  It 'supports old profile arrays without converting their schema' {
    $text='{"profiles":[{"guid":"'+$First+'","name":"Original"}],"defaultProfile":"Original"}'
    $result=Get-RideTerminalDefaultProfileDocument (Get-TerminalFixtureBytes $text)
    $result.Profiles[0].Id | Should -BeExactly $First
    $result.DefaultProfile | Should -BeExactly 'Original'
  }
  It 'retains source declarations without claiming dynamic profile availability' {
    $text='{"profiles":{"list":[{"guid":"'+$First+'","source":"Windows.Terminal.Wsl"}]}}'
    $result=Get-RideTerminalDefaultProfileDocument (Get-TerminalFixtureBytes $text)
    $result.Profiles[0].Source | Should -BeExactly 'Windows.Terminal.Wsl'
    $result.Profiles[0].AvailabilityVerified | Should -BeFalse
  }
  It 'rejects malformed or unsupported syntax: <Case>' -ForEach @(
    @{Case='unterminated comment';Text='{/* never closes'},
    @{Case='unterminated string';Text='{"x":"'},
    @{Case='single quotes';Text="{'x':1}"},
    @{Case='unquoted key';Text='{x:1}'},
    @{Case='missing comma';Text='{"x":1 "y":2}'},
    @{Case='multiple commas';Text='{"x":1,,}'},
    @{Case='leading zero';Text='{"x":01}'},
    @{Case='NaN';Text='{"x":NaN}'},
    @{Case='invalid escape';Text='{"x":"\q"}'},
    @{Case='unpaired surrogate';Text='{"x":"\uD800"}'},
    @{Case='trailing content';Text='{} true'},
    @{Case='nonobject root';Text='[]'},
    @{Case='duplicate key';Text='{"x":1,"x":2}'},
    @{Case='escaped duplicate';Text='{"defaultProfile":"a","\u0064efaultProfile":"b"}'},
    @{Case='nested duplicate';Text='{"unknown":{"x":1,"x":2}}'},
    @{Case='invalid default type';Text='{"defaultProfile":false}'},
    @{Case='invalid profiles type';Text='{"profiles":"wrong"}'},
    @{Case='invalid list type';Text='{"profiles":{"list":{}}}'},
    @{Case='invalid hidden type';Text='{"profiles":{"list":[{"hidden":"false"}]}}'}
  ) {
    {Get-RideTerminalDefaultProfileDocument (Get-TerminalFixtureBytes $Text)} | Should -Throw
  }
  It 'accepts JSON number forms, literals and trailing array commas in unknown fields' {
    $text='{"unknown":[0,-0,1.25,1e+20,-4E-2,true,false,null,],'+$ProfileJson+'}'
    (Get-RideTerminalDefaultProfileDocument (Get-TerminalFixtureBytes $text)).Profiles.Count | Should -Be 2
  }
  It 'refuses invalid UTF-8, UTF-16 and the size/depth/node limits' {
    {Get-RideTerminalDefaultProfileDocument ([byte[]]@(255,255,255))} | Should -Throw '*UTF-8*'
    {Get-RideTerminalDefaultProfileDocument ([Text.Encoding]::Unicode.GetBytes('{}'))} | Should -Throw
    {Get-RideTerminalDefaultProfileDocument ([byte[]]::new(1048577))} | Should -Throw '*1 MiB*'
    $deep='{"x":'+('['*66)+'0'+(']'*66)+'}'
    {Get-RideTerminalDefaultProfileDocument (Get-TerminalFixtureBytes $deep)} | Should -Throw '*limit*'
    $wide='{"x":['+('0,'*32769)+'0]}'
    {Get-RideTerminalDefaultProfileDocument (Get-TerminalFixtureBytes $wide)} | Should -Throw '*limit*'
  }
}
Describe 'Terminal narrow patch and recovery' {
  It 'preserves exact bytes through replacement and recovery for BOM <Bom> and <NewlineName>' -ForEach @(
    @{Bom=$false;NewlineName='LF';Newline="`n"},@{Bom=$true;NewlineName='LF';Newline="`n"},
    @{Bom=$false;NewlineName='CRLF';Newline="`r`n"},@{Bom=$true;NewlineName='CRLF';Newline="`r`n"}
  ) {
    $text='// caf'+[char]233+$Newline+'{'+$Newline+'  "defaultProfile" /* keep */ : "Original",'+$Newline+'  '+$ProfileJson+','+$Newline+'  "number":1e+05,'+$Newline+'}'+$Newline
    $bytes=Get-TerminalFixtureBytes $text -Bom:$Bom
    $originalBase64=[Convert]::ToBase64String($bytes)
    $patch=New-RideTerminalDefaultProfilePatch $bytes $Second
    $patch.Changed | Should -BeTrue
    $patch.MutationAuthorized | Should -BeFalse
    (Get-TerminalFixtureText $patch.Bytes) | Should -BeExactly $text.Replace(': "Original",',': "'+$Second+'",')
    [Convert]::ToBase64String($bytes) | Should -BeExactly $originalBase64
    $snapshot=$patch.Snapshot | ConvertTo-Json -Depth 8 | ConvertFrom-Json
    $restored=Restore-RideTerminalDefaultProfilePatch $patch.Bytes $snapshot
    [Convert]::ToBase64String($restored.Bytes) | Should -BeExactly $originalBase64
  }
  It 'does not rewrite an already selected GUID spelling or escaped literal' {
    $text='{"defaultProfile":"\u007b11111111-1111-1111-1111-111111111111}",'+$ProfileJson+'}'
    $bytes=Get-TerminalFixtureBytes $text
    $patch=New-RideTerminalDefaultProfilePatch $bytes $First
    $patch.Changed | Should -BeFalse
    [Convert]::ToBase64String($patch.Bytes) | Should -BeExactly ([Convert]::ToBase64String($bytes))
    (Restore-RideTerminalDefaultProfilePatch $bytes $patch.Snapshot).Changed | Should -BeFalse
  }
  It 'inserts and removes only its new property while preserving unrelated comments and edits' {
    $text='/* lead */ {'+"`r`n"+' // retain this comment'+"`r`n"+$ProfileJson+',"unknown":1,} // tail'
    $bytes=Get-TerminalFixtureBytes $text -Bom
    $patch=New-RideTerminalDefaultProfilePatch $bytes $Second
    $patch.Snapshot.Mode | Should -Be Insert
    (Get-RideTerminalDefaultProfileDocument $patch.Bytes).DefaultProfile | Should -BeExactly $Second
    $edited=Get-TerminalFixtureBytes ((Get-TerminalFixtureText $patch.Bytes).Replace('"unknown":1','"unknown":2')) -Bom
    $restored=Restore-RideTerminalDefaultProfilePatch $edited $patch.Snapshot
    (Get-TerminalFixtureText $restored.Bytes) | Should -BeExactly $text.Replace('"unknown":1','"unknown":2')
    (Restore-RideTerminalDefaultProfilePatch $restored.Bytes $patch.Snapshot).Changed | Should -BeFalse
  }
  It 'preserves unrelated field edits while restoring a previous root string' {
    $text='{"defaultProfile":"'+$First+'","unknown":{"defaultProfile":"nested"},'+$ProfileJson+'}'
    $patch=New-RideTerminalDefaultProfilePatch (Get-TerminalFixtureBytes $text) $Second
    $edited=Get-TerminalFixtureBytes ((Get-TerminalFixtureText $patch.Bytes).Replace('"nested"','"changed"'))
    $restored=Restore-RideTerminalDefaultProfilePatch $edited $patch.Snapshot
    (Get-TerminalFixtureText $restored.Bytes) | Should -BeExactly $text.Replace('"nested"','"changed"')
  }
  It 'refuses modified or removed owned values and tampered snapshots' {
    $text='{"defaultProfile":"'+$First+'",'+$ProfileJson+'}'
    $patch=New-RideTerminalDefaultProfilePatch (Get-TerminalFixtureBytes $text) $Second
    $edited=Get-TerminalFixtureBytes ((Get-TerminalFixtureText $patch.Bytes).Replace('"defaultProfile":"'+$Second+'"','"defaultProfile":"operator"'))
    {Restore-RideTerminalDefaultProfilePatch $edited $patch.Snapshot} | Should -Throw '*conflict*'
    $removed=Get-TerminalFixtureBytes ('{'+$ProfileJson+'}')
    {Restore-RideTerminalDefaultProfilePatch $removed $patch.Snapshot} | Should -Throw '*conflict*'
    $snapshot=$patch.Snapshot | ConvertTo-Json -Depth 8 | ConvertFrom-Json
    $snapshot.OriginalLiteral='"other"'
    {Restore-RideTerminalDefaultProfilePatch $patch.Bytes $snapshot} | Should -Throw '*snapshot content*'
  }
  It 'refuses insertion recovery after owned formatting or BOM changes' {
    $bytes=Get-TerminalFixtureBytes ('{'+$ProfileJson+'}')
    $patch=New-RideTerminalDefaultProfilePatch $bytes $Second
    $changed=Get-TerminalFixtureBytes ((Get-TerminalFixtureText $patch.Bytes).Replace('"defaultProfile": ','"defaultProfile" : '))
    {Restore-RideTerminalDefaultProfilePatch $changed $patch.Snapshot} | Should -Throw '*conflict*'
    {Restore-RideTerminalDefaultProfilePatch (Get-TerminalFixtureBytes (Get-TerminalFixtureText $patch.Bytes) -Bom) $patch.Snapshot} | Should -Throw '*BOM changed*'
  }
  It 'refuses absent or hidden chosen profiles and duplicate GUIDs' {
    $bytes=Get-TerminalFixtureBytes ('{'+$ProfileJson+'}')
    {New-RideTerminalDefaultProfilePatch $bytes $Third} | Should -Throw '*visible declaration*'
    {New-RideTerminalDefaultProfilePatch $bytes 'Next'} | Should -Throw '*GUID in braces*'
    $hidden=Get-TerminalFixtureBytes ('{'+$ProfileJson.Replace('"name":"Next"','"name":"Next","hidden":true')+'}')
    {New-RideTerminalDefaultProfilePatch $hidden $Second} | Should -Throw '*visible declaration*'
    $duplicate=Get-TerminalFixtureBytes ('{'+$ProfileJson.Replace($Second,$First)+'}')
    {Get-RideTerminalDefaultProfileDocument $duplicate} | Should -Throw '*Duplicate declared*'
  }
  It 'honors default hidden configuration with an explicit per-profile override' {
    $text='{'+$ProfileJson.Replace('"defaults":{}','"defaults":{"hidden":true}').Replace('"name":"Next"','"name":"Next","hidden":false')+'}'
    $bytes=Get-TerminalFixtureBytes $text
    {New-RideTerminalDefaultProfilePatch $bytes $First} | Should -Throw '*visible declaration*'
    (New-RideTerminalDefaultProfilePatch $bytes $Second).Changed | Should -BeTrue
  }
  It 'refuses recovery when the previous profile disappeared or its name became ambiguous' {
    $text='{"defaultProfile":"Original",'+$ProfileJson+'}'
    $patch=New-RideTerminalDefaultProfilePatch (Get-TerminalFixtureBytes $text) $Second
    $missing=Get-TerminalFixtureBytes ((Get-TerminalFixtureText $patch.Bytes).Replace('"name":"Original"','"name":"Renamed"'))
    {Restore-RideTerminalDefaultProfilePatch $missing $patch.Snapshot} | Should -Throw '*Prior default profile*'
    $ambiguous=Get-TerminalFixtureBytes ((Get-TerminalFixtureText $patch.Bytes).Replace('"name":"Next"','"name":"Original"'))
    {Restore-RideTerminalDefaultProfilePatch $ambiguous $patch.Snapshot} | Should -Throw '*Prior default profile*'
  }
  It 'requires a resolvable prior default before creating a recoverable patch' {
    $bytes=Get-TerminalFixtureBytes ('{"defaultProfile":"unknown",'+$ProfileJson+'}')
    {New-RideTerminalDefaultProfilePatch $bytes $Second} | Should -Throw '*Prior default profile*'
  }
  It 'restores inserted-property absence after unrelated properties were prepended' {
    $bytes=Get-TerminalFixtureBytes ('{'+$ProfileJson+'}')
    $patch=New-RideTerminalDefaultProfilePatch $bytes $Second
    $text=Get-TerminalFixtureText $patch.Bytes
    $edited=Get-TerminalFixtureBytes ('{"newSetting":true,'+$text.Substring(1))
    $restored=Restore-RideTerminalDefaultProfilePatch $edited $patch.Snapshot
    (Get-TerminalFixtureText $restored.Bytes) | Should -BeExactly ('{"newSetting":true,'+$ProfileJson+'}')
  }
  It 'preserves unusual comments, Unicode and layout over multiple synthetic round trips' {
    foreach($separator in @('',"`n","`r`n",'/* : , } [ "/ */',"// nested-looking {`n")){
      $unknown='"opaque":{"quoted":"defaultProfile // not a key","unicode":"'+[char]0x00e6+'","number":-1.2300e+04,}'
      $text='{'+$separator+'"defaultProfile"'+$separator+':'+$separator+'"Original",'+$separator+$ProfileJson+','+$separator+$unknown+'}'+$separator
      $bytes=Get-TerminalFixtureBytes $text
      $patch=New-RideTerminalDefaultProfilePatch $bytes $Second
      $restored=Restore-RideTerminalDefaultProfilePatch $patch.Bytes $patch.Snapshot
      [Convert]::ToBase64String($restored.Bytes) | Should -BeExactly ([Convert]::ToBase64String($bytes))
    }
  }
  It 'completes only supplied visible GUID declarations and filters case-insensitively' {
    $global:RideTerminalTestBytes=Get-TerminalFixtureBytes ('{'+$ProfileJson+'}')
    try {
      $line='New-RideTerminalDefaultProfilePatch -Bytes $global:RideTerminalTestBytes -ProfileId '
      $matches=(TabExpansion2 -InputScript $line -CursorColumn $line.Length).CompletionMatches.CompletionText
      $matches | Should -Contain ("'"+$First+"'")
      $matches | Should -Contain ("'"+$Second+"'")
      $line+='''{222'
      $matches=(TabExpansion2 -InputScript $line -CursorColumn $line.Length).CompletionMatches.CompletionText
      $matches | Should -Contain ("'"+$Second+"'")
      $matches | Should -Not -Contain ("'"+$First+"'")
    } finally {Remove-Variable -Name RideTerminalTestBytes -Scope Global}
  }
}
