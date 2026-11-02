<#
.SYNOPSIS
  Exercise WLAN lifecycle recovery using synthetic profiles and mocked native calls.
.DESCRIPTION
  Creates private TestDrive files and uses real current-user DPAPI protection.
  Every WLAN boundary and target context is mocked; no adapter or service is used.
.EXAMPLE
  Invoke-Pester ./tests/WirelessLifecycle.Tests.ps1
.NOTES
  Pester 5; native Windows PowerShell 5.1 and PowerShell 7. Version: 0.1.0.
#>
BeforeDiscovery {
  Import-Module (Join-Path $PSScriptRoot '../modules/RIDE.WirelessProfile.psm1') -Force
  Import-Module (Join-Path $PSScriptRoot '../modules/RIDE.WirelessLifecycle.psm1') -Force
}
Describe 'Private synthetic WLAN lifecycle' {
  InModuleScope RIDE.WirelessLifecycle {
    BeforeEach {
      $script:fixtureName='RIDE synthetic lifecycle fixture'
      $script:key='RIDE-Synthetic-Only-2026!'
      $script:folder=Join-Path $TestDrive ([guid]::NewGuid().ToString('N'))
      $null=New-Item -ItemType Directory -Path $script:folder
      $script:profilePath=Join-Path $script:folder 'synthetic.xml'
      New-RideWirelessProfileFile -ProfileName $script:fixtureName -Ssid 'RIDE-SYNTHETIC-NO-CONNECT' -Security WPA2Personal -Key (ConvertTo-SecureString $script:key -AsPlainText -Force) -OutputPath $script:profilePath | Out-Null
      $script:desired=[IO.File]::ReadAllText($script:profilePath)
      $script:profiles=@{}
      $script:order=[Collections.Generic.List[string]]::new()
      $script:order.Add('unrelated-first');$script:order.Add('unrelated-last')
      $script:writes=[Collections.Generic.List[object]]::new()
      $script:addDefaults=$false
      $script:fakeContext=[pscustomobject]@{ComputerName='RIDE-Synthetic-VM';Build='26300';EditionId='EnterpriseEval';Revision=9711;ProductType='WinNT';InstallationType='Client';UserSid='S-1-5-21-123-456-789-1001';NativeProcess=$true;Architecture='AMD64';Administrator=$true}
      $script:install=@{ProfilePath=$script:profilePath;InterfaceId=[guid]'de81fe79-7a46-4d65-a865-e38bfa8aaeb8';StateDirectory=$script:folder;ExpectedComputerName='RIDE-Synthetic-VM';ExpectedBuild='26300';ExpectedEditionId='EnterpriseEval';AllowCandidate=$true;Confirm=$false}
      Mock Get-RideWirelessLifecycleContext {$script:fakeContext}
      Mock Get-RideWirelessLifecycleRows {
        for($i=0;$i -lt $script:order.Count;$i++){
          $name=$script:order[$i];$flags=if($script:profiles.ContainsKey($name)){$script:profiles[$name].Flags}else{0}
          [pscustomobject]@{Name=$name;Flags=[uint32]$flags;Position=$i}
        }
      }
      Mock Get-RideWirelessLifecycleContent {
        param($InterfaceId,$Name)
        $value=$script:profiles[$Name]
        [pscustomobject]@{Present=($null -ne $value);Xml=$value.Xml;Flags=$value.Flags;GrantedAccess=0x70023}
      }
      Mock Set-RideWirelessLifecycleContent {
        param($InterfaceId,$Xml,$SecurityDescriptor,$Overwrite)
        $script:writes.Add([pscustomobject]@{Action='Set';Sddl=$SecurityDescriptor;Overwrite=$Overwrite})
        [xml]$document=$Xml;$name=[string]$document.WLANProfile.name
        if(-not $script:profiles.ContainsKey($name)){$script:order.Insert(0,$name)}
        if($script:addDefaults){
          $ssid=$document.WLANProfile.SSIDConfig.SSID
          if(-not $ssid.name){$element=$document.CreateElement('name',$document.DocumentElement.NamespaceURI);$element.InnerText='RIDE-SYNTHETIC-NO-CONNECT';$null=$ssid.AppendChild($element)}
          $Xml=$document.OuterXml
        }
        $script:profiles[$name]=[pscustomobject]@{Xml=$Xml;Flags=0}
      }
      Mock Remove-RideWirelessLifecycleContent {
        param($InterfaceId,$Name)
        $script:writes.Add([pscustomobject]@{Action='Delete'})
        $script:profiles.Remove($Name);$null=$script:order.Remove($Name)
      }
      Mock Set-RideWirelessLifecyclePosition {
        param($InterfaceId,$Name,$Position)
        $script:writes.Add([pscustomobject]@{Action='Position'})
        $null=$script:order.Remove($Name);$script:order.Insert([int]$Position,$Name)
      }
    }
    It 'imports, repeats, removes, restores removal and restores original absence and order' {
      $original=Get-RideWirelessLifecycleSnapshot $script:install.InterfaceId $script:fixtureName
      $installed=Install-RideWirelessProfile @script:install
      $installed.Status|Should -Be Applied
      $installed.ConnectionAttempted|Should -BeFalse
      (Install-RideWirelessProfile @script:install).Status|Should -Be AlreadyDesired
      $script:writes.Count|Should -Be 1
      $removed=Remove-RideWirelessProfile -OwnerRunId $installed.RunId -StateDirectory $script:folder -AllowCandidate -Confirm:$false
      $removed.Status|Should -Be Applied
      (Remove-RideWirelessProfile -OwnerRunId $installed.RunId -StateDirectory $script:folder -AllowCandidate -Confirm:$false).Status|Should -Be AlreadyAbsent
      (Restore-RideWirelessProfileRun -RunId $removed.RunId -StateDirectory $script:folder -AllowCandidate -Confirm:$false).Status|Should -Be Restored
      (Restore-RideWirelessProfileRun -RunId $installed.RunId -StateDirectory $script:folder -AllowCandidate -Confirm:$false).Status|Should -Be Restored
      (Restore-RideWirelessProfileRun -RunId $installed.RunId -StateDirectory $script:folder -AllowCandidate -Confirm:$false).Status|Should -Be AlreadyRestored
      Test-RideWirelessSnapshotEqual $original (Get-RideWirelessLifecycleSnapshot $script:install.InterfaceId $script:fixtureName)|Should -BeTrue
      @($script:writes|Where-Object Action -eq Set).Sddl|Should -Be @($script:WirelessProfileSddl,$script:WirelessProfileSddl)
    }
    It 'accepts native readback defaults without repeatedly overwriting a matching profile' {
      $script:addDefaults=$true
      $run=Install-RideWirelessProfile @script:install
      $run.Status|Should -Be Applied
      (Install-RideWirelessProfile @script:install).Status|Should -Be AlreadyDesired
      $script:writes.Count|Should -Be 1
      (Restore-RideWirelessProfileRun -RunId $run.RunId -StateDirectory $script:folder -AllowCandidate -Confirm:$false).Status|Should -Be Restored
      $automatic=$script:desired.Replace('<connectionMode>manual</connectionMode>','<connectionMode>auto</connectionMode>')
      Test-RideWirelessDesiredEqual ($automatic.Replace('<autoSwitch>false</autoSwitch>','')) $automatic|Should -BeTrue
      Test-RideWirelessDesiredEqual ($automatic.Replace('<autoSwitch>false</autoSwitch>','<autoSwitch>true</autoSwitch>')) $automatic|Should -BeFalse
    }
    It 'captures and restores existing XML and position while leaving its permissions unchanged' {
      $previous=$script:desired.Replace($script:key,'Previous-Synthetic-Key!')
      $script:profiles[$script:fixtureName]=[pscustomobject]@{Xml=$previous;Flags=0}
      $script:order.Insert(1,$script:fixtureName)
      {Install-RideWirelessProfile @script:install}|Should -Throw '*ReplaceExisting*'
      $run=Install-RideWirelessProfile @script:install -ReplaceExisting
      $script:writes[0].Sddl|Should -BeNullOrEmpty
      $script:writes[0].Overwrite|Should -BeTrue
      {Remove-RideWirelessProfile -OwnerRunId $run.RunId -StateDirectory $script:folder -AllowCandidate -Confirm:$false}|Should -Throw '*RIDE-created*'
      (Restore-RideWirelessProfileRun -RunId $run.RunId -StateDirectory $script:folder -AllowCandidate -Confirm:$false).Status|Should -Be Restored
      $script:profiles[$script:fixtureName].Xml|Should -BeExactly $previous
      $script:order.IndexOf($script:fixtureName)|Should -Be 1
      @($script:writes|Where-Object Action -eq Set)[1].Sddl|Should -BeNullOrEmpty
    }
    It 'refuses policy, per-user and unknown scope flags' {
      $script:order.Add($script:fixtureName)
      foreach($flag in @(1,2,4)){
        $script:profiles[$script:fixtureName]=[pscustomobject]@{Xml=$script:desired;Flags=$flag}
        {Install-RideWirelessProfile @script:install -ReplaceExisting}|Should -Throw '*all-user*'
      }
      $script:writes.Count|Should -Be 0
    }
    It 'previews without writing profiles or recovery records and without requiring elevation' {
      $script:fakeContext.Administrator=$false
      Install-RideWirelessProfile @script:install -WhatIf
      $script:writes.Count|Should -Be 0
      @(Get-ChildItem -LiteralPath $script:folder -Filter '*.dat').Count|Should -Be 0
    }
    It 'refuses missing candidate opt-in, elevation and mismatched target before any writer' {
      $script:install.AllowCandidate=$false
      {Install-RideWirelessProfile @script:install}|Should -Throw '*AllowCandidate*'
      $script:install.AllowCandidate=$true;$script:fakeContext.Administrator=$false
      {Install-RideWirelessProfile @script:install}|Should -Throw '*existing elevation*'
      $script:fakeContext.Administrator=$true;$script:install.ExpectedBuild='26100'
      {Install-RideWirelessProfile @script:install}|Should -Throw '*target differs*'
      $script:writes.Count|Should -Be 0
    }
    It 'refuses auto mode without its explicit opt-in' {
      [IO.File]::WriteAllText($script:profilePath,$script:desired.Replace('<connectionMode>manual</connectionMode>','<connectionMode>auto</connectionMode>'))
      {Install-RideWirelessProfile @script:install}|Should -Throw '*AllowAutoConnect*'
      $script:writes.Count|Should -Be 0
    }
    It 'refuses recovery and removal after a key change without exposing that key' {
      $run=Install-RideWirelessProfile @script:install
      $script:profiles[$script:fixtureName].Xml=$script:desired.Replace($script:key,'Changed-Synthetic-Key!')
      {Restore-RideWirelessProfileRun -RunId $run.RunId -StateDirectory $script:folder -AllowCandidate -Confirm:$false}|Should -Throw '*recovery conflict*'
      {Remove-RideWirelessProfile -OwnerRunId $run.RunId -StateDirectory $script:folder -AllowCandidate -Confirm:$false}|Should -Throw '*changed since installation*'
      $script:writes.Count|Should -Be 1
    }
    It 'refuses recovery after profile-order or target drift' {
      $run=Install-RideWirelessProfile @script:install
      $script:order.Reverse()
      {Restore-RideWirelessProfileRun -RunId $run.RunId -StateDirectory $script:folder -AllowCandidate -Confirm:$false}|Should -Throw '*recovery conflict*'
      $script:order.Reverse();$script:fakeContext.Revision++
      {Restore-RideWirelessProfileRun -RunId $run.RunId -StateDirectory $script:folder -AllowCandidate -Confirm:$false}|Should -Throw '*identity drift*'
      $script:writes.Count|Should -Be 1
    }
    It 'stores private encrypted recovery records and emits no XML or key in public results' {
      $run=Install-RideWirelessProfile @script:install
      ($run|ConvertTo-Json)|Should -Not -Match ([regex]::Escape($script:key))
      foreach($file in Get-ChildItem -LiteralPath $script:folder -Filter '*.dat'){
        (Get-Acl -LiteralPath $file.FullName).AreAccessRulesProtected|Should -BeTrue
        [Text.Encoding]::UTF8.GetString([IO.File]::ReadAllBytes($file.FullName))|Should -Not -Match ([regex]::Escape($script:key))
      }
      (Read-RideWirelessRunPart $script:folder $run.RunId intent).DesiredXml|Should -BeExactly $script:desired
    }
    It 'retains durable intent without claiming apply success when the native writer throws' {
      Mock Set-RideWirelessLifecycleContent {throw 'Native synthetic failure with sensitive diagnostic'}
      {Install-RideWirelessProfile @script:install}|Should -Throw '*Run ID:*Private intent retained*'
      @(Get-ChildItem -LiteralPath $script:folder -Filter '*.intent.dat').Count|Should -Be 1
      @(Get-ChildItem -LiteralPath $script:folder -Filter '*.applied.dat').Count|Should -Be 0
      $id=(Get-ChildItem -LiteralPath $script:folder -Filter '*.intent.dat').Name.Split('.')[0]
      {Restore-RideWirelessProfileRun -RunId $id -StateDirectory $script:folder -AllowCandidate -Confirm:$false}|Should -Throw '*missing, damaged*'
    }
    It 'retains intent after a successful write when verification detects an unexpected native key' {
      Mock Set-RideWirelessLifecycleContent {
        $script:order.Insert(0,$script:fixtureName)
        $script:profiles[$script:fixtureName]=[pscustomobject]@{Xml=$script:desired.Replace($script:key,'Unexpected-Synthetic-Key!');Flags=0}
      }
      {Install-RideWirelessProfile @script:install}|Should -Throw '*did not complete*'
      $script:profiles.ContainsKey($script:fixtureName)|Should -BeTrue
      @(Get-ChildItem -LiteralPath $script:folder -Filter '*.intent.dat').Count|Should -Be 1
      @(Get-ChildItem -LiteralPath $script:folder -Filter '*.applied.dat').Count|Should -Be 0
    }
    It 'never calls a native writer if private intent persistence fails' {
      Mock Save-RideWirelessRunPart {throw 'Synthetic persistence failure'}
      {Install-RideWirelessProfile @script:install}|Should -Throw '*persistence failure*'
      $script:writes.Count|Should -Be 0
    }
    It 'rejects damaged DPAPI records and invalid run IDs without a native writer' {
      $run=Install-RideWirelessProfile @script:install
      $path=Get-RideWirelessRunPath $script:folder $run.RunId intent
      [IO.File]::WriteAllBytes($path,[byte[]]@(1,2,3,4))
      {Restore-RideWirelessProfileRun -RunId $run.RunId -StateDirectory $script:folder -AllowCandidate -Confirm:$false}|Should -Throw '*missing, damaged*'
      {Restore-RideWirelessProfileRun -RunId '../escape' -StateDirectory $script:folder -AllowCandidate -Confirm:$false}|Should -Throw '*missing, damaged*'
      $script:writes.Count|Should -Be 1
    }
    It 'rejects broadly readable XML without changing its permissions' {
      $ordinary=Join-Path $script:folder 'ordinary.xml'
      [IO.File]::WriteAllText($ordinary,$script:desired)
      $before=(Get-Acl -LiteralPath $ordinary).Sddl
      $script:install.ProfilePath=$ordinary
      {Install-RideWirelessProfile @script:install}|Should -Throw '*permissions differ*'
      (Get-Acl -LiteralPath $ordinary).Sddl|Should -BeExactly $before
      $script:writes.Count|Should -Be 0
    }
    It 'rejects extra generated-input settings, duplicate fields and DTDs before mutation' {
      foreach($xml in @($script:desired.Replace('</WLANProfile>','<extra>true</extra></WLANProfile>'),$script:desired.Replace('<connectionType>ESS</connectionType>','<connectionType>ESS</connectionType><connectionType>ESS</connectionType>'),$script:desired.Replace('<nonBroadcast>false</nonBroadcast>','<nonBroadcast>invalid</nonBroadcast>'),$script:desired.Replace('<autoSwitch>false</autoSwitch>','<autoSwitch>true</autoSwitch>'),('<!DOCTYPE WLANProfile [<!ENTITY probe "synthetic">]>'+($script:desired -replace '<\?xml[^?]*\?>','')))){
        [IO.File]::WriteAllText($script:profilePath,$xml)
        {Install-RideWirelessProfile @script:install}|Should -Throw '*outside the supported*'
      }
      $script:writes.Count|Should -Be 0
    }
    It 'preserves significant whitespace in an eight-space passphrase' {
      $xml=$script:desired.Replace($script:key,'        ')
      $parsed=Read-RideWirelessLifecycleXml $xml -GeneratedInput
      $parsed.Document.SelectSingleNode('//w:keyMaterial',$parsed.Namespaces).InnerText|Should -BeExactly '        '
      Test-RideWirelessDesiredEqual $xml $script:desired|Should -BeFalse
    }
    It 'completes saved run IDs without reading credentials or invoking native calls' {
      $run=Install-RideWirelessProfile @script:install
      $script:writes.Clear()
      Mock Read-RideWirelessRunPart {throw 'Completion must not decrypt records'}
      Mock Get-RideWirelessLifecycleRows {throw 'Completion must not query WLAN'}
      $results=@(& $script:WirelessRunCompleter 'Restore-RideWirelessProfileRun' 'RunId' $run.RunId.Substring(0,6) $null @{StateDirectory=$script:folder})
      $results.Count|Should -Be 1
      $results[0].CompletionText|Should -BeExactly $run.RunId
      $script:writes.Count|Should -Be 0
    }
  }
}
