<#
.SYNOPSIS
  Test provisioning data and controller handoff without changing host resources.
.DESCRIPTION
  Uses data-only helpers and TestDrive; no Hyper-V or AutomatedLab import.
.NOTES
  Compatibility: Windows PowerShell 5.1 and PowerShell 7; Pester 5.7.1.
  Owner: RIDE-Windows maintainers. Repository test fixture; no standalone CLI.
#>

BeforeAll {
  Import-Module (Join-Path $PSScriptRoot 'integration/RIDE.LabProvisioning.psm1') -Force
  Import-Module (Join-Path $PSScriptRoot 'integration/RIDE.TestAutomation.psm1') -Force
  Import-Module (Join-Path (Split-Path -Parent $PSScriptRoot) 'modules/RIDE.CatalogData.psm1') -Force
}

Describe 'Provisioning configuration and per-VM handoff' {
  It 'lets explicit values override a local file while retaining other declared values' {
    $inputPath = Join-Path $TestDrive 'provision.psd1'
    "@{ SchemaVersion = 1; LabName = 'RIDEServerTest'; VMName = 'RIDE-S25-Test'; MemoryGB = 4; GuestRepositoryPath = 'D:\Tests\ride-windows' }" | Set-Content -LiteralPath $inputPath
    $effective = Resolve-RideLabProvisioningConfiguration $inputPath @{ MemoryGB = 12 }
    $effective.MemoryGB | Should -Be 12
    $effective.VMName | Should -Be 'RIDE-S25-Test'
    $effective.GuestRepositoryPath | Should -Be 'D:\Tests\ride-windows'
    $effective.WindowsUpdateMode | Should -Be 'Wait'
  }

  It 'rejects credentials and invalid guest leaf names in local data' {
    $inputPath = Join-Path $TestDrive 'private.psd1'
    "@{ SchemaVersion = 1; Password = 'must-not-store' }" | Set-Content -LiteralPath $inputPath
    { Resolve-RideLabProvisioningConfiguration $inputPath } | Should -Throw '*Unsupported provisioning field*'
    { Resolve-RideLabProvisioningConfiguration -ExplicitParameters @{ GuestRepositoryPath = 'C:\Windows' } } | Should -Throw '*end with ride-windows*'
  }

  It 'generates a registration-compatible seed with discovered VM identity and custom path' {
    $effective = Resolve-RideLabProvisioningConfiguration -ExplicitParameters @{ LabName = 'RIDEServerTest'; VMName = 'RIDE-S25-Test'; GuestRepositoryPath = 'D:\Tests\ride-windows'; CIRepositoryPath = 'C:\ci\ride-windows' }
    $vmId = [guid]::NewGuid()
    $seed = New-RideLabAutomationSeed $effective $vmId 'C:\source\ride-windows' 'D:\ISOs\server.iso'
    $seed.Name | Should -Be 'RIDEServerTest'
    $seed.VMId | Should -Be $vmId.ToString()
    $seed.GuestRepositoryPath | Should -Be 'D:\Tests\ride-windows'
    $seedPath = Join-Path $TestDrive 'controller.json'
    $seed | ConvertTo-Json | Set-Content -LiteralPath $seedPath
    (Read-RideAutomationConfiguration $seedPath).VMName | Should -Be 'RIDE-S25-Test'
    $seed.ContainsKey('CheckpointId') | Should -BeFalse
  }

  It 'rejects invalid configuration values before provisioning' {
    { Resolve-RideLabProvisioningConfiguration -ExplicitParameters @{ MemoryGB = 1 } } | Should -Throw '*MemoryGB*'
    { Resolve-RideLabProvisioningConfiguration -ExplicitParameters @{ DisableTpm = 'false' } } | Should -Throw '*Boolean*'
    { Resolve-RideLabProvisioningConfiguration -ExplicitParameters @{ AutomationSeedPath = 'C:\seed.json' } } | Should -Throw '*CIRepositoryPath*'
  }
}

Describe 'Provisioning preview configuration' {
  BeforeAll {
    # Run the actual initialization and ShouldProcess boundary in a fixture.
    # Omit host preflight and all provisioning, so no Hyper-V/AutomatedLab calls run.
    $scriptPath = Join-Path $PSScriptRoot 'integration/New-RideAutomatedLabVm.ps1'
    $scriptText = Get-Content -LiteralPath $scriptPath -Raw
    $tokens = $null; $errors = $null
    $ast = [Management.Automation.Language.Parser]::ParseFile($scriptPath, [ref]$tokens, [ref]$errors)
    $firstFunction = $ast.EndBlock.Statements | Where-Object { $_ -is [Management.Automation.Language.FunctionDefinitionAst] } | Select-Object -First 1
    $action = $ast.EndBlock.Statements | Where-Object { $_ -is [Management.Automation.Language.AssignmentStatementAst] -and $_.Left.Extent.Text -eq '$action' } | Select-Object -First 1
    $boundary = $ast.EndBlock.Statements | Where-Object { $_ -is [Management.Automation.Language.IfStatementAst] -and $_.Extent.Text -like '*$PSCmdlet.ShouldProcess*' } | Select-Object -First 1
    $probe = @'
[pscustomobject]@{
  OperatingSystemName = $OperatingSystemName; LabName = $LabName; VMName = $VMName
  NetworkMode = $NetworkMode; GuestIpv4Address = $GuestIpv4Address
  MemoryGB = $MemoryGB; DisableTpm = [bool]$DisableTpm
  Ipv4DnsServers = @($Ipv4DnsServers); AutomationSeedPath = $AutomationSeedPath
}
'@
    $previewPath = Join-Path $TestDrive 'Preview.ps1'
    $source = $scriptText.Substring(0, $firstFunction.Extent.StartOffset) + $probe + "`n" + $action.Extent.Text + "`n" + $boundary.Extent.Text + "`nthrow 'Provisioning boundary crossed during WhatIf.'"
    Set-Content -LiteralPath $previewPath -Value $source -Encoding UTF8
    Copy-Item -LiteralPath (Join-Path $PSScriptRoot 'integration/RIDE.LabProvisioning.psm1') -Destination $TestDrive
    $examplePath = Join-Path $PSScriptRoot 'integration/provisioning.server2025.shared-network.example.psd1'
  }

  It 'loads file values under WhatIf and returns before provisioning' {
    $preview = & $previewPath -ConfigurationPath $examplePath -WhatIf
    $preview.OperatingSystemName | Should -Be 'Windows Server 2025 Standard Evaluation (Desktop Experience)'
    $preview.LabName | Should -Be 'RIDESrv2025Test'
    $preview.VMName | Should -Be 'RIDE-S25-Test'
    $preview.NetworkMode | Should -Be 'ExistingNat'
    $preview.GuestIpv4Address | Should -Be '192.168.11.50/24'
    $preview.AutomationSeedPath | Should -Be 'C:\RIDE-Automation\server2025-controller.json'
    $preview.Ipv4DnsServers | Should -Be @('1.1.1.1', '8.8.8.8')
    $preview.MemoryGB | Should -Be 8
    $preview.DisableTpm | Should -BeFalse
  }

  It 'retains explicit CLI overrides under WhatIf and returns before provisioning' {
    $preview = & $previewPath -ConfigurationPath $examplePath -MemoryGB 12 -DisableTpm -WhatIf
    $preview.MemoryGB | Should -Be 12
    $preview.DisableTpm | Should -BeTrue
    $preview.VMName | Should -Be 'RIDE-S25-Test'
    $preview.NetworkMode | Should -Be 'ExistingNat'
  }
}

Describe 'AutomatedLab checkpoint restart and directory preparation' {
  BeforeAll {
    $scriptPath = Join-Path $PSScriptRoot 'integration/New-RideAutomatedLabVm.ps1'
    $source = Get-Content -LiteralPath $scriptPath -Raw
    $tokens = $null; $errors = $null
    $ast = [Management.Automation.Language.Parser]::ParseFile($scriptPath, [ref]$tokens, [ref]$errors)
    $start = $ast.Find({ param($node) $node -is [Management.Automation.Language.CommandAst] -and $node.GetCommandName() -eq 'Stop-LabVM' }, $true).Extent.StartOffset
    $end = ($ast.EndBlock.Statements | Where-Object { $_ -is [Management.Automation.Language.AssignmentStatementAst] -and $_.Left.Extent.Text -eq '$stageRoot' }).Extent.StartOffset
    $preparationCode = [scriptblock]::Create($source.Substring($start, $end - $start))
    function Stop-LabVM { param($ComputerName, [switch] $Wait) }
    function Checkpoint-LabVM { param($ComputerName, $SnapshotName) }
    function Get-LabVMSnapshot { param($ComputerName) }
    function Start-LabVM {
      [CmdletBinding()]
      param($ComputerName, [switch] $Wait, $TimeoutInMinutes)
    }
    function Invoke-LabCommand {
      param($ComputerName, $ActivityName, $Retries, $RetryIntervalInSeconds, [scriptblock] $ScriptBlock, [object[]] $ArgumentList, [switch] $PassThru)
      # Model the worker's output-dependent completion without remoting or sleeps.
      for ($attempt = 0; $attempt -lt $Retries; $attempt++) {
        $script:guestPreparationAttempts++
        $result = @(& $ScriptBlock @ArgumentList)
        if ($result.Count -gt 0) {
          if ($PassThru) { $result }
          return
        }
      }
    }
  }

  BeforeEach {
    $VMName = 'RIDE-S25-Test'; $snapshotName = 'RIDE-clean-test-base'
    $GuestRepositoryPath = Join-Path $TestDrive ([guid]::NewGuid().ToString() + '\ride-windows')
    $script:guestPreparationAttempts = 0
  }

  It 'waits for remoting and completes directory preparation in one attempt' {
    Mock Start-LabVM { }
    . $preparationCode
    $guestDirectoryReady | Should -BeTrue
    $script:guestPreparationAttempts | Should -Be 1
    Test-Path -LiteralPath (Split-Path -Parent $GuestRepositoryPath) -PathType Container | Should -BeTrue
    Should -Invoke Start-LabVM -Times 1 -Exactly -ParameterFilter { $ComputerName -eq 'RIDE-S25-Test' -and $Wait -and $TimeoutInMinutes -eq 10 -and $ErrorAction -eq 'Stop' }
  }

  It 'stops before preparing the directory when the startup wait fails' {
    Mock Start-LabVM { throw 'Guest remoting startup timed out.' }
    { . $preparationCode } | Should -Throw '*startup timed out*'
    $script:guestPreparationAttempts | Should -Be 0
    Test-Path -LiteralPath (Split-Path -Parent $GuestRepositoryPath) | Should -BeFalse
  }

  It 'rejects missing or false readiness before source staging' -TestCases @(
    @{ Result = $null }
    @{ Result = $false }
  ) {
    param($Result)
    Mock Invoke-LabCommand { $Result }
    { . $preparationCode } | Should -Throw '*Source staging has not started*'
  }
}

Describe 'AutomatedLab machine definition boundary' {
  BeforeAll {
    $scriptPath = Join-Path $PSScriptRoot 'integration/New-RideAutomatedLabVm.ps1'
    $source = Get-Content -LiteralPath $scriptPath -Raw
    $tokens = $null; $errors = $null
    $ast = [Management.Automation.Language.Parser]::ParseFile($scriptPath, [ref]$tokens, [ref]$errors)
    $start = $ast.Find({ param($node) $node -is [Management.Automation.Language.CommandAst] -and $node.GetCommandName() -eq 'New-LabDefinition' }, $true).Extent.StartOffset
    $end = $ast.Find({ param($node) $node -is [Management.Automation.Language.CommandAst] -and $node.GetCommandName() -eq 'Install-Lab' }, $true).Extent.StartOffset
    $definitionCode = [scriptblock]::Create($source.Substring($start, $end - $start))
  }

  It 'uses compatible definition parameters and preserves explicit DNS with <Mode>' -TestCases @(
    @{ Mode = 'ExistingNat' }
    @{ Mode = 'NewNat' }
  ) {
    param($Mode)
    $result = & {
      # Models AutomatedLab 5.61.0's mutually exclusive Network/NetworkAdapter
      # public parameter sets without importing AutomatedLab or calling Hyper-V.
      function New-LabDefinition { param($Name, $DefaultVirtualizationEngine, $VmPath) }
      function Add-LabVirtualNetworkDefinition { param($Name, $AddressSpace, [switch] $UseNat) }
      function New-LabNetworkAdapterDefinition {
        param($VirtualSwitch, $Ipv4Address, $Ipv4Gateway, $Ipv4DnsServers)
        $servers = [System.Collections.Generic.List[object]]::new()
        foreach ($server in $Ipv4DnsServers) { $servers.Add($server) }
        [pscustomobject]@{ VirtualSwitch = $VirtualSwitch; Ipv4Address = $Ipv4Address; Ipv4Gateway = $Ipv4Gateway; Ipv4DnsServers = $servers }
      }
      function Add-LabMachineDefinition {
        [CmdletBinding(DefaultParameterSetName = 'Network')]
        param($Name, $OperatingSystem, $Memory, $Processors, $InstallationUserCredential, $HypervProperties,
          [Parameter(ParameterSetName = 'NetworkAdapter')] $NetworkAdapter,
          [Parameter(ParameterSetName = 'Network')] $DnsServer1)
        $script:definitionParameterSet = $PSCmdlet.ParameterSetName
        $script:definedAdapter = $NetworkAdapter
        if ($Mode -eq 'ExistingNat') { $NetworkAdapter.Ipv4DnsServers.Add('0.0.0.0') }
      }
      function Get-ProvisioningNetworkPlan { $networkPlan }
      $NetworkMode = $Mode
      $LabName = 'RIDEServerTest'; $VMName = 'RIDE-S25-Test'; $VMPath = 'D:\VMs\RIDEServerTest'
      $MemoryGB = 8; $ProcessorCount = 4; $selectedOS = 'Server ISO entry'; $installationCredential = $null
      $DisableTpm = $false; $DisableSecureBoot = $false
      $Ipv4DnsServers = @('1.1.1.1', '8.8.8.8')
      $networkPlan = @{
        VirtualNetworkParameters = @{ Name = 'RIDE-Internet'; UseNat = ($Mode -eq 'NewNat') }
        NetworkAdapterParameters = @{ VirtualSwitch = 'RIDE-Internet'; Ipv4Address = '192.168.11.50/24'; Ipv4Gateway = '192.168.11.1'; Ipv4DnsServers = $Ipv4DnsServers }
      }
      . $definitionCode
      [pscustomobject]@{ ParameterSet = $script:definitionParameterSet; Adapter = $script:definedAdapter }
    }
    $result.ParameterSet | Should -Be 'NetworkAdapter'
    $result.Adapter.Ipv4DnsServers.ToArray() | Should -Be @('1.1.1.1', '8.8.8.8')
    $result.Adapter.Ipv4DnsServers | Should -Not -Contain '0.0.0.0'
    $result.Adapter.Ipv4Address | Should -Be '192.168.11.50/24'
    $result.Adapter.Ipv4Gateway | Should -Be '192.168.11.1'
  }
}

Describe 'Existing NAT provisioning safety' {
  BeforeEach {
    $config = Resolve-RideLabProvisioningConfiguration -ExplicitParameters @{
      LabName = 'RIDEServerTest'; VMName = 'RIDE-S25-Test'; NetworkMode = 'ExistingNat'
      NetworkName = 'RIDE-Internet'; NatName = 'RIDE-Internet'
      GuestIpv4Address = '192.168.11.50/24'; Ipv4Gateway = '192.168.11.1'
      Ipv4DnsServers = @('1.1.1.1', '8.8.8.8'); CIRepositoryPath = 'C:\ci\ride-windows'
    }
    $inventory = @{
      Switches = @([pscustomobject]@{ Name = 'RIDE-Internet'; SwitchType = 'Internal' })
      Nats = @([pscustomobject]@{ Name = 'RIDE-Internet'; InternalIPInterfaceAddressPrefix = '192.168.11.0/24' })
      HostAddresses = @([pscustomobject]@{ InterfaceAlias = 'vEthernet (RIDE-Internet)'; IPAddress = '192.168.11.1'; PrefixLength = 24 })
      VMAdapters = @([pscustomobject]@{ VMName = 'RIDE-Win11-Test'; SwitchName = 'RIDE-Internet'; IPAddresses = @() })
      ReservedAddresses = @([pscustomobject]@{ VMName = 'RIDE-Win11-Test'; SwitchName = 'RIDE-Internet'; IPAddress = '192.168.11.10' })
    }
  }

  It 'reuses the shared switch without a second NAT and keeps explicit guest addressing' {
    $plan = Resolve-RideLabNetworkPlan -Configuration $config @inventory
    $plan.VirtualNetworkParameters.Name | Should -Be 'RIDE-Internet'
    $plan.VirtualNetworkParameters.UseNat | Should -BeFalse
    $plan.VirtualNetworkParameters.AddressSpace | Should -Be '192.168.11.0/24'
    $plan.NetworkAdapterParameters.Ipv4Address | Should -Be '192.168.11.50/24'
    $plan.NetworkAdapterParameters.Ipv4Gateway | Should -Be '192.168.11.1'
    $plan.NetworkAdapterParameters.Ipv4DnsServers | Should -Be @('1.1.1.1', '8.8.8.8')
    $seed = New-RideLabAutomationSeed $config ([guid]::NewGuid()) 'C:\source\ride-windows' 'D:\ISOs\server.iso'
    $seed.LabName | Should -Be 'RIDEServerTest'
    $seed.VMName | Should -Be 'RIDE-S25-Test'
    $seed.SchemaVersion | Should -Be 1
  }

  It 'reads the shared-network example and retains explicit override precedence' {
    $example = Join-Path $PSScriptRoot 'integration/provisioning.server2025.shared-network.example.psd1'
    $effective = Resolve-RideLabProvisioningConfiguration $example @{ GuestIpv4Address = '192.168.11.60/24' }
    $effective.NetworkMode | Should -Be 'ExistingNat'
    $effective.GuestIpv4Address | Should -Be '192.168.11.60/24'
  }

  It 'normalizes a single DNS string to a server array for definition parameters' {
    $config.Ipv4DnsServers = '1.1.1.1'
    $effective = Resolve-RideLabProvisioningConfiguration -ExplicitParameters $config
    $effective.Ipv4DnsServers[0] | Should -Be '1.1.1.1'
    $effective.Ipv4DnsServers.Count | Should -Be 1
  }

  It 'rejects invalid shared addressing: <Field> = <Value>' -TestCases @(
    @{ Field = 'GuestIpv4Address'; Value = '192.168.11.0/24' }
    @{ Field = 'GuestIpv4Address'; Value = '192.168.11.255/24' }
    @{ Field = 'GuestIpv4Address'; Value = '192.168.11.1/24' }
    @{ Field = 'GuestIpv4Address'; Value = '192.168.11.50' }
    @{ Field = 'GuestIpv4Address'; Value = '192.168.11.50/31' }
    @{ Field = 'GuestIpv4Address'; Value = '192.168.999.50/24' }
    @{ Field = 'GuestIpv4Address'; Value = '2001:db8::1/24' }
    @{ Field = 'Ipv4Gateway'; Value = '192.168.12.1' }
    @{ Field = 'Ipv4DnsServers'; Value = @() }
    @{ Field = 'Ipv4DnsServers'; Value = @('127.0.0.1') }
    @{ Field = 'NatName'; Value = '' }
    @{ Field = 'NetworkMode'; Value = 'Automatic' }
  ) {
    param($Field, $Value)
    $config[$Field] = $Value
    { Resolve-RideLabProvisioningConfiguration -ExplicitParameters $config } | Should -Throw
  }

  It 'blocks missing and non-internal switches' {
    $inventory.Switches = @()
    { Resolve-RideLabNetworkPlan -Configuration $config @inventory } | Should -Throw '*existing Internal*'
    $inventory.Switches = @([pscustomobject]@{ Name = 'RIDE-Internet'; SwitchType = 'External' })
    { Resolve-RideLabNetworkPlan -Configuration $config @inventory } | Should -Throw '*existing Internal*'
  }

  It 'blocks absent, differently named, and multiple NATs' {
    $inventory.Nats = @()
    { Resolve-RideLabNetworkPlan -Configuration $config @inventory } | Should -Throw '*exactly one host NAT*'
    $inventory.Nats = @([pscustomobject]@{ Name = 'Other'; InternalIPInterfaceAddressPrefix = '192.168.11.0/24' })
    { Resolve-RideLabNetworkPlan -Configuration $config @inventory } | Should -Throw '*exactly one host NAT*'
    $inventory.Nats += [pscustomobject]@{ Name = 'RIDE-Internet'; InternalIPInterfaceAddressPrefix = '192.168.11.0/24' }
    { Resolve-RideLabNetworkPlan -Configuration $config @inventory } | Should -Throw '*exactly one host NAT*'
  }

  It 'blocks a different NAT prefix and an incorrect host gateway' {
    $inventory.Nats[0].InternalIPInterfaceAddressPrefix = '192.168.12.0/24'
    { Resolve-RideLabNetworkPlan -Configuration $config @inventory } | Should -Throw '*match the existing NAT prefix*'
    $inventory.Nats[0].InternalIPInterfaceAddressPrefix = '192.168.11.0/24'
    $inventory.HostAddresses[0].InterfaceAlias = 'vEthernet (Other)'
    { Resolve-RideLabNetworkPlan -Configuration $config @inventory } | Should -Throw '*selected host switch adapter*'
    $inventory.HostAddresses[0].InterfaceAlias = 'vEthernet (RIDE-Internet)'
    $inventory.HostAddresses[0].PrefixLength = 16
    { Resolve-RideLabNetworkPlan -Configuration $config @inventory } | Should -Throw '*selected host switch adapter*'
  }

  It 'blocks guest IPs already assigned to a host or a running VM' {
    $inventory.HostAddresses += [pscustomobject]@{ InterfaceAlias = 'Other'; IPAddress = '192.168.11.50'; PrefixLength = 24 }
    { Resolve-RideLabNetworkPlan -Configuration $config @inventory } | Should -Throw '*assigned to the host*'
    $inventory.HostAddresses = @($inventory.HostAddresses[0])
    $inventory.VMAdapters[0].IPAddresses = @('192.168.11.50')
    { Resolve-RideLabNetworkPlan -Configuration $config @inventory } | Should -Throw '*reported by VM*'
  }

  It 'blocks saved reservations even when Hyper-V reports no addresses' {
    $inventory.ReservedAddresses[0].IPAddress = '192.168.11.50'
    { Resolve-RideLabNetworkPlan -Configuration $config @inventory } | Should -Throw '*reserved by an existing AutomatedLab*'
  }

  It 'fails closed for a shared-switch VM with neither live IPv4 nor saved reservations' {
    $inventory.ReservedAddresses = @()
    $inventory.VMAdapters[0].IPAddresses = @('fe80::1')
    { Resolve-RideLabNetworkPlan -Configuration $config @inventory } | Should -Throw '*Cannot verify addresses*'
  }

  It 'ignores reservations on other switches and allows a live-addressed unmanaged VM' {
    $inventory.ReservedAddresses[0].SwitchName = 'Other'
    $inventory.ReservedAddresses[0].IPAddress = '192.168.11.50'
    $inventory.VMAdapters[0].IPAddresses = @('192.168.11.10')
    (Resolve-RideLabNetworkPlan -Configuration $config @inventory).VirtualNetworkParameters.UseNat | Should -BeFalse
  }

  It 'preserves the new-NAT default while blocking existing host resources' {
    $fresh = Resolve-RideLabProvisioningConfiguration
    $fresh.NetworkMode | Should -Be 'NewNat'
    (Resolve-RideLabNetworkPlan -Configuration $fresh).VirtualNetworkParameters.UseNat | Should -BeTrue
    { Resolve-RideLabNetworkPlan -Configuration $fresh -Nats $inventory.Nats } | Should -Throw '*second NAT*'
    { Resolve-RideLabNetworkPlan -Configuration $fresh -Switches $inventory.Switches } | Should -Throw '*already exists*'
    { Resolve-RideLabProvisioningConfiguration -ExplicitParameters @{ GuestIpv4Address = '192.168.11.50/24' } } | Should -Throw '*only supported*'
  }
}

Describe 'Bounded data-only catalog reader' {
  It 'loads the growing catalog on both supported PowerShell editions' {
    $catalog = Import-RideCatalogData (Join-Path (Split-Path -Parent $PSScriptRoot) 'catalog/operations.psd1')
    $catalog.Operations.Count | Should -BeGreaterThan 91
  }
  It 'rejects an executable expression instead of evaluating it' {
    $path = Join-Path $TestDrive 'invalid-catalog.psd1'
    "@{ SchemaVersion = 1; Operations = @(Get-Process); Groups = @() }" | Set-Content -LiteralPath $path
    { Import-RideCatalogData $path } | Should -Throw '*literal hashtables*'
  }
  It 'rejects executable values inside a literal operation' {
    $path = Join-Path $TestDrive 'executable-entry.psd1'
    '@{ SchemaVersion = 1; Operations = @(@{ Id = (Get-Process) }); Groups = @() }' | Set-Content -LiteralPath $path
    { Import-RideCatalogData $path } | Should -Throw
  }
  It 'rejects executable root statements and unexpected catalog fields' {
    $path = Join-Path $TestDrive 'invalid-root.psd1'
    'Get-Process; @{ SchemaVersion = 1; Operations = @(); Groups = @() }' | Set-Content -LiteralPath $path
    { Import-RideCatalogData $path } | Should -Throw '*declarative catalog syntax*'
    '@{ SchemaVersion = 1; Operations = @(); Groups = @(); Extra = 1 }' | Set-Content -LiteralPath $path
    { Import-RideCatalogData $path } | Should -Throw '*Unexpected or duplicate*'
  }
}
