<#
.SYNOPSIS
  Verify synthetic WLAN acceptance orchestration with mocked guest/native boundaries.
.DESCRIPTION
  No VM, WLAN or lifecycle system mutation occurs. Temporary generation and report
  files are created in Pester TestDrive; native acceptance is never inferred.
.EXAMPLE
  Invoke-Pester ./tests/WirelessAcceptance.Tests.ps1
.NOTES
  Pester 5 on native Windows PowerShell 5.1 and PowerShell 7. Version: 0.1.0.
#>
BeforeDiscovery {
  Import-Module (Join-Path $PSScriptRoot 'integration/RIDE.WirelessAcceptance.psm1') -Force
}
Describe 'Synthetic native WLAN acceptance orchestration' {
  InModuleScope RIDE.WirelessAcceptance {
    BeforeEach {
      $script:request=[guid]::NewGuid().ToString('N')
      $script:parameters=@{RunId=$script:request;InterfaceId=[guid]'de81fe79-7a46-4d65-a865-e38bfa8aaeb8';ExpectedComputerName='RIDE-Synthetic-VM';ExpectedBuild='26300';ExpectedEditionId='EnterpriseEval';EvidenceRoot=$TestDrive;DisposableVm=$true;Confirm=$false}
      $script:context=[pscustomobject]@{ComputerName='RIDE-Synthetic-VM';Manufacturer='Microsoft Corporation';Model='Virtual Machine';Build='26300';EditionId='EnterpriseEval';InstallationType='Client';NativeProcess=$true;Architecture='AMD64';Administrator=$true;WlanService='Running';GuestMarker='1';IntegrationMarker='1';RunMarker=$script:request}
      $script:present=$false;$script:ssid=$null;$script:malformedResult=$false
      $script:name='RIDE synthetic lifecycle fixture '+$script:request.Substring(0,8)
      $script:installId='11111111111111111111111111111111'
      $script:replaceId='22222222222222222222222222222222'
      $script:removeId='33333333333333333333333333333333'
      $script:events=[Collections.Generic.List[string]]::new()
      Mock Get-RideWirelessAcceptanceEnvironment {$script:context}
      Mock Get-RideWirelessAcceptanceRows {
        [pscustomobject]@{Name='Unrelated';Flags=[uint32]0;Position=0}
        if($script:present){[pscustomobject]@{Name=$script:name;Flags=[uint32]0;Position=1}}
      }
      Mock Test-RideWirelessAcceptanceProfile {
        param($InterfaceId,$Name,$Ssid,$SyntheticKey)
        $script:present -and $script:ssid -ceq $Ssid -and $Name -ceq $script:name
      }
      Mock Install-RideWirelessProfile {
        param($ProfilePath,$StateDirectory,$ReplaceExisting,$WhatIf)
        if($WhatIf){$script:events.Add('Preview');return}
        if($ReplaceExisting){$script:ssid='RIDE-SYNTHETIC-REPLACEMENT';$id=$script:replaceId;$script:events.Add('Replace')}
        elseif($script:present){$script:events.Add('Repeat');return [pscustomobject]@{SchemaVersion=1;Status='AlreadyDesired';RunId=$null}}
        else{$script:present=$true;$script:ssid='RIDE-SYNTHETIC-NO-CONNECT';$id=$script:installId;$script:events.Add('Import')}
        [IO.File]::WriteAllText((Join-Path $StateDirectory ($id+'.intent.dat')),'synthetic inert test record')
        [IO.File]::WriteAllText((Join-Path $StateDirectory ($id+'.applied.dat')),'synthetic inert test record')
        [pscustomobject]@{SchemaVersion=1;Status=if($script:malformedResult){'Failed'}else{'Applied'};RunId=$id}
      }
      Mock Remove-RideWirelessProfile {
        param($OwnerRunId,$StateDirectory)
        if($OwnerRunId -cne $script:installId){throw 'Wrong owner ID'}
        $script:events.Add('Remove');$script:present=$false
        [pscustomobject]@{SchemaVersion=1;Status='Applied';RunId=$script:removeId}
      }
      Mock Restore-RideWirelessProfileRun {
        param($RunId,$StateDirectory)
        $status='Restored'
        if($RunId -ceq $script:replaceId){$script:ssid='RIDE-SYNTHETIC-NO-CONNECT';$script:events.Add('RestoreReplacement')}
        elseif($RunId -ceq $script:removeId){$script:present=$true;$script:ssid='RIDE-SYNTHETIC-NO-CONNECT';$script:events.Add('RestoreRemoval')}
        elseif($RunId -ceq $script:installId){if(-not $script:present){$status='AlreadyRestored'};$script:present=$false;$script:events.Add('RestoreInitial')}
        else{throw 'Wrong restore ID'}
        [pscustomobject]@{SchemaVersion=1;Status=$status;RunId=$RunId}
      }
    }
    It 'runs the full sequence and requires independent readback before reporting success' {
      $result=Invoke-RideWirelessAcceptance @script:parameters
      $result.Status|Should -Be Passed
      $result.Checks.Count|Should -Be 9
      $result.RecoveryRequired|Should -BeFalse
      $result.ConnectionAttempted|Should -BeFalse
      @($script:events)|Should -Be @('Preview','Import','Repeat','Replace','RestoreReplacement','Remove','RestoreRemoval','RestoreInitial','RestoreInitial')
      @($result.LifecycleRuns|Where-Object {-not $_.Restored}).Count|Should -Be 0
      $script:present|Should -BeFalse
      $reportPath=Join-Path $result.EvidenceDirectory 'result.json'
      (Get-Acl -LiteralPath $reportPath).AreAccessRulesProtected|Should -BeTrue
      (Get-Content -LiteralPath $reportPath -Raw)|Should -Not -Match 'RIDE-Synthetic-Only-2026!'
      Should -Invoke Test-RideWirelessAcceptanceProfile -Times 4 -Exactly
    }
    It 'previews without creating evidence or invoking a lifecycle command' {
      $script:context.Administrator=$false
      $result=Invoke-RideWirelessAcceptance @script:parameters -WhatIf
      $result.Status|Should -Be Preview
      $result.NativeAcceptancePassed|Should -BeFalse
      Test-Path -LiteralPath (Join-Path $TestDrive $script:request)|Should -BeFalse
      $script:events.Count|Should -Be 0
    }
    It 'refuses non-VM and uncorrelated contexts before lifecycle calls' {
      $script:context.Model='Developer workstation'
      {Invoke-RideWirelessAcceptance @script:parameters}|Should -Throw '*disposable Hyper-V*'
      $script:context.Model='Virtual Machine';$script:context.RunMarker='unrelated'
      {Invoke-RideWirelessAcceptance @script:parameters}|Should -Throw '*correlated*'
      $script:events.Count|Should -Be 0
    }
    It 'refuses wrong target build and empty interface identity' {
      $script:parameters.ExpectedBuild='26100'
      {Invoke-RideWirelessAcceptance @script:parameters}|Should -Throw '*target differs*'
      $script:parameters.ExpectedBuild='26300';$script:parameters.InterfaceId=[guid]::Empty
      {Invoke-RideWirelessAcceptance @script:parameters}|Should -Throw '*nonempty*'
      $script:parameters.RunId='AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA'
      {Invoke-RideWirelessAcceptance @script:parameters}|Should -Throw
      $script:events.Count|Should -Be 0
    }
    It 'reports unavailable elevation and service as NotRun without starting either' {
      $script:context.Administrator=$false
      (Invoke-RideWirelessAcceptance @script:parameters).Reason|Should -Be ExistingElevationRequired
      $script:context.Administrator=$true;$script:context.WlanService='Stopped'
      $result=Invoke-RideWirelessAcceptance @script:parameters
      $result.Status|Should -Be NotRun
      $result.Reason|Should -Be WlanServiceUnavailable
      $result.NativeAcceptancePassed|Should -BeFalse
      $script:events.Count|Should -Be 0
    }
    It 'reports unavailable interface without exposing the native exception' {
      Mock Get-RideWirelessAcceptanceRows {throw 'Provider-sensitive-diagnostic'}
      $result=Invoke-RideWirelessAcceptance @script:parameters
      $result.Status|Should -Be NotRun
      $result.Reason|Should -Be WlanInterfaceUnavailable
      ($result|ConvertTo-Json)|Should -Not -Match 'Provider-sensitive-diagnostic'
      $script:events.Count|Should -Be 0
    }
    It 'preserves a colliding profile and an existing evidence directory' {
      $script:present=$true
      (Invoke-RideWirelessAcceptance @script:parameters).Reason|Should -Be SyntheticProfileCollision
      $script:present=$false
      $null=New-Item -ItemType Directory -Path (Join-Path $TestDrive $script:request)
      {Invoke-RideWirelessAcceptance @script:parameters}|Should -Throw '*already exists*'
      $script:events.Count|Should -Be 0
    }
    It 'does not accept a failed lifecycle result or continue later steps' {
      $script:malformedResult=$true
      $result=Invoke-RideWirelessAcceptance @script:parameters
      $result.Status|Should -Be Failed
      $result.Stage|Should -Be Import
      $result.RecoveryRequired|Should -BeTrue
      $result.NativeAcceptancePassed|Should -BeFalse
      @($script:events)|Should -Be @('Preview','Import')
      @(Get-ChildItem -LiteralPath (Join-Path $result.EvidenceDirectory 'state') -File).Count|Should -Be 2
      $result.StateRunIds|Should -Contain $script:installId
    }
    It 'keeps recovery evidence and refuses a pass when independent profile verification fails' {
      Mock Test-RideWirelessAcceptanceProfile {$false}
      $result=Invoke-RideWirelessAcceptance @script:parameters
      $result.Status|Should -Be Failed
      $result.Stage|Should -Be Import
      $result.LifecycleRuns[0].RunId|Should -Be $script:installId
      $result.LifecycleRuns[0].Restored|Should -BeFalse
      $script:present|Should -BeTrue
      Should -Invoke Remove-RideWirelessProfile -Times 0 -Exactly
      Should -Invoke Restore-RideWirelessProfileRun -Times 0 -Exactly
    }
    It 'never labels an unsuccessful restore or partial native write as recovered' {
      Mock Restore-RideWirelessProfileRun {throw 'RIDE-Synthetic-Only-2026!'}
      $result=Invoke-RideWirelessAcceptance @script:parameters
      $result.Status|Should -Be Failed
      $result.Stage|Should -Be RestoreReplacement
      $result.RecoveryRequired|Should -BeTrue
      $result.NativeAcceptancePassed|Should -BeFalse
      ($result|ConvertTo-Json -Depth 6)|Should -Not -Match 'RIDE-Synthetic-Only-2026!'
      $result.LifecycleRuns.Count|Should -Be 2
      Should -Invoke Remove-RideWirelessProfile -Times 0 -Exactly
    }
  }
}

Describe 'Independent WLAN acceptance XML readback' {
  InModuleScope RIDE.WirelessAcceptance {
    BeforeEach {
      $script:readbackPath=Join-Path $TestDrive ([guid]::NewGuid().ToString('N')+'.xml')
      $key=ConvertTo-SecureString 'RIDE-Synthetic-Only-2026!' -AsPlainText -Force
      try{New-RideWirelessProfileFile -ProfileName 'Synthetic readback' -Ssid 'RIDE-SYNTHETIC-NO-CONNECT' -Security WPA2Personal -Key $key -OutputPath $script:readbackPath|Out-Null}finally{$key.Dispose()}
      $script:content=[pscustomobject]@{Present=$true;Flags=0;Xml=[IO.File]::ReadAllText($script:readbackPath)}
      Mock Get-RideWirelessAcceptanceContent {$script:content}
      $script:readback=@{InterfaceId=[guid]'de81fe79-7a46-4d65-a865-e38bfa8aaeb8';Name='Synthetic readback';Ssid='RIDE-SYNTHETIC-NO-CONNECT';SyntheticKey='RIDE-Synthetic-Only-2026!'}
    }
    It 'verifies exact synthetic identity, SSID, key and scope without emitting XML' {
      Test-RideWirelessAcceptanceProfile @script:readback|Should -BeTrue
      [xml]$lowercase=$script:content.Xml
      $lowercase.WLANProfile.SSIDConfig.SSID.hex=$lowercase.WLANProfile.SSIDConfig.SSID.hex.ToLowerInvariant()
      $script:content.Xml=$lowercase.OuterXml
      Test-RideWirelessAcceptanceProfile @script:readback|Should -BeTrue
      $script:content.Flags=2
      Test-RideWirelessAcceptanceProfile @script:readback|Should -BeFalse
      $script:content.Flags=0;$script:content.Xml=$script:content.Xml.Replace('RIDE-Synthetic-Only-2026!','Wrong-Synthetic-Key!')
      Test-RideWirelessAcceptanceProfile @script:readback|Should -BeFalse
    }
    It 'rejects automatic connection, duplicate identity and DTD content' {
      $original=$script:content.Xml
      $script:content.Xml=$original.Replace('<connectionMode>manual</connectionMode>','<connectionMode>auto</connectionMode>')
      Test-RideWirelessAcceptanceProfile @script:readback|Should -BeFalse
      $script:content.Xml=$original.Replace('<name>Synthetic readback</name>','<name>Synthetic readback</name><name>Synthetic readback</name>')
      Test-RideWirelessAcceptanceProfile @script:readback|Should -BeFalse
      $script:content.Xml='<!DOCTYPE WLANProfile [<!ENTITY probe "synthetic">]>'+($original -replace '<\?xml[^?]*\?>','')
      {Test-RideWirelessAcceptanceProfile @script:readback}|Should -Throw
    }
  }
}
