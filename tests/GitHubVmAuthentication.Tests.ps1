<#
.SYNOPSIS
  Verify VM authentication boundaries and evidence publication without a real VM.
.DESCRIPTION
  Mocks remoting, controller credentials and time; uses synthetic canaries and TestDrive.
.EXAMPLE
  Invoke-Pester .\tests\GitHubVmAuthentication.Tests.ps1
.INPUTS
  None.
.OUTPUTS
  Pester results.
.NOTES
  Windows PowerShell 5.1/7 and Pester 5.7.1. Owner: RIDE-Windows maintainers.
  Version 0.1.0; no real credentials, publishers, VMs or installers.
#>

BeforeDiscovery {
  Import-Module (Join-Path $PSScriptRoot 'integration/RIDE.GitHubVmAuthentication.psm1') -Force
  Import-Module (Join-Path $PSScriptRoot 'integration/RIDE.TestAutomation.psm1') -Force
}

Describe 'Protected host credential code' {
  It 'rejects PAT delivery from a mutable checkout before credential or VM access' {
    $runner = Join-Path $PSScriptRoot 'integration/Invoke-RideVmTest.ps1'
    { & $runner -Transport AutomatedLab -LabName RIDETest -IntegrationSuite GitHubAuthentication -GuestGitHubAuthentication PAT -ResultDirectory $TestDrive -AuthenticationConfigurationPath (Join-Path $TestDrive 'configuration.json') -Confirm:$false } | Should -Throw '*registered protected controller installation*'
  }
}

Describe 'PAT evidence export gate' {
  BeforeEach {
    $script:Root = Join-Path $TestDrive ([guid]::NewGuid().ToString('N'))
    $null = New-Item -ItemType Directory -Path (Join-Path $script:Root 'guest') -Force
    $script:Canary = 'syntheticPAT_exportCanary_123456789'
    $script:Token = ConvertTo-SecureString $script:Canary -AsPlainText -Force
    $script:Run = 'a' * 32
    @{ RunId = $script:Run; Status = 'Passed' } | ConvertTo-Json | Set-Content -LiteralPath (Join-Path $script:Root 'result.json')
    'safe guest output' | Set-Content -LiteralPath (Join-Path $script:Root 'guest/transcript.log')
  }
  AfterEach { $script:Token.Dispose() }

  It 'approves only scanned evidence and detects subsequent mutation' {
    Publish-RideVmGitHubEvidence $script:Root $script:Run $script:Token
    Test-RideVmGitHubExport $script:Root $script:Run | Should -BeTrue
    'modified' | Add-Content -LiteralPath (Join-Path $script:Root 'export/guest/transcript.log')
    Test-RideVmGitHubExport $script:Root $script:Run | Should -BeFalse
  }

  It 'rejects plaintext, Base64 and UTF16 canaries without printing them' -TestCases @(@{Kind='Plain'},@{Kind='Base64'},@{Kind='Unicode'}) {
    param($Kind)
    $path = Join-Path $script:Root 'guest/transcript.log'
    $value = if ($Kind -eq 'Base64') { [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($script:Canary)) } else { $script:Canary }
    $encoding = if ($Kind -eq 'Unicode') { [Text.Encoding]::Unicode } else { [Text.Encoding]::UTF8 }
    [IO.File]::WriteAllText($path, $value, $encoding)
    try { Publish-RideVmGitHubEvidence $script:Root $script:Run $script:Token; throw 'Expected refusal' }
    catch { $_.Exception.Message | Should -Match 'safety scan'; ($_ | Out-String) | Should -Not -Match $script:Canary }
    Test-RideVmGitHubExport $script:Root $script:Run | Should -BeFalse
    Test-Path -LiteralPath (Join-Path $script:Root 'export-safety.json') | Should -BeFalse
  }

  It 'refuses an encrypted credential record in evidence' {
    '{"Ciphertext":"DPAPI-binary-placeholder"}' | Set-Content -LiteralPath (Join-Path $script:Root 'guest/state.json')
    { Publish-RideVmGitHubEvidence $script:Root $script:Run $script:Token } | Should -Throw '*safety scan*'
  }

  It 'refuses incomplete reads and leaves no publication approval' {
    $stream = [IO.File]::Open((Join-Path $script:Root 'guest/transcript.log'), 'Open', 'ReadWrite', 'None')
    try { { Publish-RideVmGitHubEvidence $script:Root $script:Run $script:Token } | Should -Throw '*safety scan*' }
    finally { $stream.Dispose() }
    Test-RideVmGitHubExport $script:Root $script:Run | Should -BeFalse
  }

  It 'rejects unlisted files and wrong request correlation' {
    Publish-RideVmGitHubEvidence $script:Root $script:Run $script:Token
    Test-RideVmGitHubExport $script:Root ('b' * 32) | Should -BeFalse
    'extra' | Set-Content -LiteralPath (Join-Path $script:Root 'export/extra.log')
    Test-RideVmGitHubExport $script:Root $script:Run | Should -BeFalse
  }

  It 'does not publish snapshots or raw source files' {
    $null = New-Item -ItemType Directory -Path (Join-Path $script:Root 'snapshot')
    'reviewed source without credential material' | Set-Content -LiteralPath (Join-Path $script:Root 'snapshot/synthetic.txt')
    Publish-RideVmGitHubEvidence $script:Root $script:Run $script:Token
    Test-Path -LiteralPath (Join-Path $script:Root 'export/snapshot') | Should -BeFalse
    Test-RideVmGitHubExport $script:Root $script:Run | Should -BeTrue
  }

  It 'blocks export when a retained snapshot or sidecar contains the credential' -TestCases @(@{Name='snapshot/synthetic.txt'},@{Name='retained-sidecar.txt'}) {
    param($Name)
    $null = New-Item -ItemType Directory -Path (Join-Path $script:Root 'snapshot') -Force
    $script:Canary | Set-Content -LiteralPath (Join-Path $script:Root $Name)
    { Publish-RideVmGitHubEvidence $script:Root $script:Run $script:Token } | Should -Throw '*safety scan*'
    Test-RideVmGitHubExport $script:Root $script:Run | Should -BeFalse
  }

  It 'stages final summary before terminal controller result publication' {
    $summary = @{ RunId = $script:Run; Status = 'TimedOut'; GuestGitHubAuthentication = 'PAT' }
    Publish-RideVmGitHubEvidence $script:Root $script:Run $script:Token -Summary $summary
    (Get-Content -LiteralPath (Join-Path $script:Root 'export/result.json') -Raw | ConvertFrom-Json).Status | Should -Be TimedOut
    Test-RideVmGitHubExport $script:Root $script:Run | Should -BeTrue
  }
}

Describe 'Dedicated controller credentials and encrypted sessions' {
  InModuleScope RIDE.GitHubVmAuthentication {
    BeforeEach {
      $script:Config = [pscustomobject]@{ SchemaVersion = 2; Capabilities = @('GitHubPatGuestV1'); GuestGitHubCredentialReference = 'vm-only'; HostAccountSid = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value }
      Mock Get-RideGitHubCredentialContext { [pscustomobject]@{ Purpose = 'VmTest'; Token = ConvertTo-SecureString 'synthetic' -AsPlainText -Force } }
    }
    It 'refuses old capability and identity mismatch before secret lookup' {
      $script:Config.SchemaVersion = 1
      { Get-RideVmGitHubContext $script:Config } | Should -Throw '*capability*'
      $script:Config.SchemaVersion = 2; $script:Config.HostAccountSid = 'S-1-5-18'
      { Get-RideVmGitHubContext $script:Config } | Should -Throw '*identity*'
      Should -Invoke Get-RideGitHubCredentialContext -Exactly 0
    }
    It 'refuses a personal interactive credential for VM delivery' {
      Mock Get-RideGitHubCredentialContext { [pscustomobject]@{ Purpose = 'Interactive'; Token = ConvertTo-SecureString 'synthetic' -AsPlainText -Force } }
      { Get-RideVmGitHubContext $script:Config } | Should -Throw '*dedicated VmTest*'
    }
    It 'allows the selected dedicated credential' {
      $context = Get-RideVmGitHubContext $script:Config
      try { $context.Purpose | Should -Be VmTest } finally { $context.Token.Dispose() }
    }
    It 'rejects closed or untrusted sessions without delivery' {
      Mock Invoke-Command { throw 'Must not deliver' }
      { New-RideVmGitHubLease ([pscustomobject]@{ State = 'Closed' }) C:\RIDE\ride-windows ('a'*32) $null ([datetime]::UtcNow.AddMinutes(1)) } | Should -Throw '*open session*'
      $session = [pscustomobject]@{ State = 'Opened'; Runspace = @{ ConnectionInfo = [pscustomobject]@{ NoEncryption = $true } } }
      { New-RideVmGitHubLease $session C:\RIDE\ride-windows ('a'*32) $null ([datetime]::UtcNow.AddMinutes(1)) } | Should -Throw '*encrypted*'
      Should -Invoke Invoke-Command -Exactly 0
    }
    It 'sanitizes delivery and cleanup transport errors' {
      Mock Assert-RideVmGitHubSession { }
      Mock Invoke-Command { throw 'synthetic-secret-from-remoting' }
      try { New-RideVmGitHubLease fake C:\RIDE\ride-windows ('a'*32) $null ([datetime]::UtcNow.AddMinutes(1)) }
      catch { ($_ | Out-String) | Should -Not -Match 'synthetic-secret-from-remoting'; $_.Exception.Message | Should -Match 'delivery failed' }
      { Remove-RideVmGitHubLease fake C:\RIDE\ride-windows ('a'*32) } | Should -Throw '*cleanup could not be verified*'
    }
  }
}

Describe 'Authentication queue contract' {
  BeforeEach {
    $script:Request = [pscustomobject]@{ SchemaVersion = 2; RunId = 'a'*32; Source = 'Local'; UnitOnly = $false; IntegrationSuite = 'GitHubAuthentication'; TimeoutMinutes = 30; SubmittedAtUtc = [datetime]::UtcNow.ToString('o'); GuestGitHubAuthentication = 'PAT'; GitHubTestScenario = 'Acquire' }
  }
  It 'accepts explicit versioned PAT mode and all focused recovery scenarios' {
    foreach ($scenario in @('Acquire','FailAfterDelivery','WaitForTimeout')) { $script:Request.GitHubTestScenario = $scenario; { Assert-RideAutomationRequest $script:Request } | Should -Not -Throw }
  }
  It 'rejects broad-suite and unit-only PAT requests' {
    $script:Request.UnitOnly = $true
    { Assert-RideAutomationRequest $script:Request } | Should -Throw
    $script:Request.UnitOnly = $false; $script:Request.IntegrationSuite = 'Full'
    { Assert-RideAutomationRequest $script:Request } | Should -Throw
  }
  It 'rejects tokens and arbitrary credential references in the queue' {
    $script:Request | Add-Member NoteProperty Token 'synthetic-secret'
    { Assert-RideAutomationRequest $script:Request } | Should -Throw '*unsupported field*'
  }
  It 'rejects downgrade to old request schema' {
    $script:Request.SchemaVersion = 1
    { Assert-RideAutomationRequest $script:Request } | Should -Throw '*version-2*'
  }
  It 'keeps old anonymous requests valid' {
    $request = [pscustomobject]@{ RunId = 'b'*32; Source = 'Local'; UnitOnly = $true; TimeoutMinutes = 30; SubmittedAtUtc = [datetime]::UtcNow.ToString('o') }
    { Assert-RideAutomationRequest $request } | Should -Not -Throw
  }

  It 'preserves all registered pins while adding authentication capability' {
    $existing = @{ Name='RIDE-Test'; LabName='Lab'; VMName='VM'; VMId='vm-id'; CheckpointName='clean'; CheckpointId='checkpoint-id'; HostAccountSid='S-1'; GuestRepositoryPath='C:\RIDE\ride-windows'; LocalRepositoryPath='C:\local'; CIRepositoryPath='C:\ci'; IsoPath='C:\media.iso'; IsoSHA256=('a'*64); SchemaVersion=1 }
    $candidate = $existing.Clone(); $candidate.SchemaVersion=2; $candidate.Capabilities=@('GitHubPatGuestV1')
    { Assert-RideAutomationRegistrationPins $existing $candidate } | Should -Not -Throw
    foreach ($field in @('VMId','CheckpointId','HostAccountSid','LocalRepositoryPath','CIRepositoryPath','IsoSHA256')) {
      $changed = $candidate.Clone(); $changed[$field] = 'changed'
      { Assert-RideAutomationRegistrationPins $existing $changed } | Should -Throw '*preserve*pin*'
    }
  }
}
