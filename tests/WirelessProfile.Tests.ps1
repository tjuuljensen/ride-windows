<#
.SYNOPSIS
  Verify generated WLAN XML using synthetic settings and private TestDrive files.
.DESCRIPTION
  No WLAN API, service, adapter, import, connection or real credential is used.
  The output ACL checks create ordinary test files with restricted permissions.
.EXAMPLE
  Invoke-Pester ./tests/WirelessProfile.Tests.ps1
.NOTES
  Pester 5; native Windows PowerShell 5.1 and PowerShell 7. Version: 0.1.0.
#>
BeforeAll {
  Import-Module (Join-Path $PSScriptRoot '../modules/RIDE.WirelessProfile.psm1') -Force
  $script:fixture=Import-PowerShellDataFile (Join-Path $PSScriptRoot 'fixtures/wireless-profile.synthetic.psd1')
  function New-FixtureParameters {
    @{ProfileName=$script:fixture.ProfileName;Ssid=$script:fixture.Ssid;Security=$script:fixture.Security;
      Key=(ConvertTo-SecureString $script:fixture.SyntheticKey -AsPlainText -Force);
      ConnectionMode=$script:fixture.ConnectionMode;HiddenNetwork=$script:fixture.HiddenNetwork;
      OutputPath=(Join-Path $TestDrive ([guid]::NewGuid().ToString('N')+'.xml'))}
  }
}
Describe 'Generated wireless profile files' {
  It 'generates the synthetic WPA2 AES profile with correct XML ordering and no automatic connection' {
    $p=New-FixtureParameters;$result=New-RideWirelessProfileFile @p
    [xml]$xml=Get-Content -LiteralPath $p.OutputPath -Raw
    $xml.DocumentElement.NamespaceURI | Should -Be 'http://www.microsoft.com/networking/WLAN/profile/v1'
    @($xml.WLANProfile.ChildNodes.LocalName) | Should -Be @('name','SSIDConfig','connectionType','connectionMode','autoSwitch','MSM')
    $xml.WLANProfile.SSIDConfig.SSID.hex | Should -Be ([BitConverter]::ToString([Text.Encoding]::UTF8.GetBytes($p.Ssid)).Replace('-',''))
    $xml.WLANProfile.MSM.security.authEncryption.authentication | Should -Be 'WPA2PSK'
    $xml.WLANProfile.MSM.security.authEncryption.encryption | Should -Be 'AES'
    $xml.WLANProfile.MSM.security.sharedKey.keyMaterial | Should -Be $script:fixture.SyntheticKey
    $xml.WLANProfile.connectionMode | Should -Be 'manual'
    $xml.WLANProfile.autoSwitch | Should -Be 'false'
    $result.Imported | Should -BeFalse
    ($result|ConvertTo-Json) | Should -Not -Match ([regex]::Escape($script:fixture.SyntheticKey))
    $result.PSObject.Properties.Name | Should -Not -Contain 'Xml'
  }
  It 'escapes XML metacharacters in the profile identity and passphrase' {
    $p=New-FixtureParameters;$p.ProfileName='RIDE <test> & "quoted"';$secret='Synthetic<&>"key!'
    $p.Key=ConvertTo-SecureString $secret -AsPlainText -Force
    New-RideWirelessProfileFile @p | Out-Null
    [xml]$xml=Get-Content -LiteralPath $p.OutputPath -Raw
    $xml.WLANProfile.name | Should -Be $p.ProfileName
    $xml.WLANProfile.MSM.security.sharedKey.keyMaterial | Should -Be $secret
    @($xml.GetElementsByTagName('test')).Count | Should -Be 0
  }
  It 'encodes Unicode SSIDs as UTF-8 bytes without character normalization' {
    $p=New-FixtureParameters;$p.Ssid='RIDE-'+[char]0x00e6+[char]0x00f8+[char]0x00e5
    New-RideWirelessProfileFile @p | Out-Null
    [xml]$xml=Get-Content -LiteralPath $p.OutputPath -Raw
    $xml.WLANProfile.SSIDConfig.SSID.hex | Should -Be '524944452DC3A6C3B8C3A5'
  }
  It 'preserves exact binary SSIDs including zero and non-UTF8 bytes' {
    $p=New-FixtureParameters;$p.Remove('Ssid');$p.SsidBytes=[byte[]]@(0,255,1,128)
    New-RideWirelessProfileFile @p | Out-Null
    [xml]$xml=Get-Content -LiteralPath $p.OutputPath -Raw
    $xml.WLANProfile.SSIDConfig.SSID.hex | Should -Be '00FF0180'
  }
  It 'enforces the 32-byte SSID limit rather than a 32-character limit' {
    $p=New-FixtureParameters;$p.Ssid=([string][char]0x00e6)*17
    {New-RideWirelessProfileFile @p} | Should -Throw '*1-32 bytes*'
    Test-Path -LiteralPath $p.OutputPath | Should -BeFalse
    $p.Ssid='x'*32;New-RideWirelessProfileFile @p | Out-Null
    Test-Path -LiteralPath $p.OutputPath | Should -BeTrue
  }
  It 'supports an explicit 64-digit hexadecimal network key' {
    $p=New-FixtureParameters;$p.Key=ConvertTo-SecureString ('AB01'*16) -AsPlainText -Force
    New-RideWirelessProfileFile @p | Out-Null
    [xml]$xml=Get-Content -LiteralPath $p.OutputPath -Raw
    $xml.WLANProfile.MSM.security.sharedKey.keyType | Should -Be 'networkKey'
  }
  It 'rejects invalid keys without echoing them or creating a file' {
    foreach($secret in @('short',('Z'*64),('X'*65),('validkey'+[char]0x00e6),"valid`nkey")) {
      $p=New-FixtureParameters;$p.Key=ConvertTo-SecureString $secret -AsPlainText -Force
      $failure=$null;try{New-RideWirelessProfileFile @p}catch{$failure=$_}
      $failure | Should -Not -BeNullOrEmpty
      $failure.Exception.Message | Should -Not -Match ([regex]::Escape($secret))
      Test-Path -LiteralPath $p.OutputPath | Should -BeFalse
    }
  }
  It 'requires a key for WPA2 and refuses irrelevant keys for open profiles' {
    $p=New-FixtureParameters;$p.Remove('Key')
    {New-RideWirelessProfileFile @p} | Should -Throw '*requires*'
    $p=New-FixtureParameters;$p.Security='Open'
    {New-RideWirelessProfileFile @p} | Should -Throw '*does not accept a key*'
    $p.Remove('Key');New-RideWirelessProfileFile @p | Out-Null
    [xml]$xml=Get-Content -LiteralPath $p.OutputPath -Raw
    $xml.WLANProfile.MSM.security.authEncryption.encryption | Should -Be 'none'
    @($xml.GetElementsByTagName('sharedKey')).Count | Should -Be 0
  }
  It 'respects explicit automatic and hidden-network settings without importing' {
    $p=New-FixtureParameters;$p.ConnectionMode='auto';$p.HiddenNetwork=$true
    (New-RideWirelessProfileFile @p).Imported | Should -BeFalse
    [xml]$xml=Get-Content -LiteralPath $p.OutputPath -Raw
    $xml.WLANProfile.SSIDConfig.nonBroadcast | Should -Be 'true'
    $xml.WLANProfile.connectionMode | Should -Be 'auto'
  }
  It 'does not write on WhatIf or invoke the private-file factory' {
    Mock -ModuleName RIDE.WirelessProfile New-RideWirelessPrivateStream {throw 'Unexpected writer'}
    $p=New-FixtureParameters;New-RideWirelessProfileFile @p -WhatIf | Out-Null
    Test-Path -LiteralPath $p.OutputPath | Should -BeFalse
    Should -Invoke -ModuleName RIDE.WirelessProfile New-RideWirelessPrivateStream -Exactly 0
  }
  It 'preserves an existing output file' {
    $p=New-FixtureParameters;[IO.File]::WriteAllText($p.OutputPath,'unrelated fixture')
    {New-RideWirelessProfileFile @p} | Should -Throw '*already exists*'
    [IO.File]::ReadAllText($p.OutputPath) | Should -Be 'unrelated fixture'
  }
  It 'refuses existing files at the atomic private-file creation boundary' {
    InModuleScope RIDE.WirelessProfile -Parameters @{Root=$TestDrive} {
      $path=Join-Path $Root 'race.xml';[IO.File]::WriteAllText($path,'preserve')
      {New-RideWirelessPrivateStream -Path $path} | Should -Throw
      [IO.File]::ReadAllText($path) | Should -Be 'preserve'
    }
  }
  It 'creates output with protected current-user and SYSTEM access only' {
    $p=New-FixtureParameters;New-RideWirelessProfileFile @p | Out-Null
    $acl=Get-Acl -LiteralPath $p.OutputPath
    $acl.AreAccessRulesProtected | Should -BeTrue
    $ids=@($acl.GetAccessRules($true,$true,[Security.Principal.SecurityIdentifier]).IdentityReference.Value | Sort-Object -Unique)
    $me=[Security.Principal.WindowsIdentity]::GetCurrent();try{$expected=@($me.User.Value,'S-1-5-18')|Sort-Object -Unique}finally{$me.Dispose()}
    $ids | Should -Be $expected
  }
  It 'refuses invalid profile names and missing output parents' {
    $p=New-FixtureParameters;$p.ProfileName="invalid`nname"
    {New-RideWirelessProfileFile @p} | Should -Throw '*ProfileName*'
    $p=New-FixtureParameters;$p.OutputPath=Join-Path $TestDrive 'missing/profile.xml'
    {New-RideWirelessProfileFile @p} | Should -Throw '*parent directory*'
  }
  It 'completes security and connection choices without creating files' {
    foreach($case in @(@{Line='New-RideWirelessProfileFile -Security W';Expected='WPA2Personal'},@{Line='New-RideWirelessProfileFile -ConnectionMode m';Expected='manual'})) {
      @([Management.Automation.CommandCompletion]::CompleteInput($case.Line,$case.Line.Length,$null).CompletionMatches.CompletionText) | Should -Be @($case.Expected)
    }
  }
}
