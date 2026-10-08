# AutomatedLab setup for the RIDE Windows integration VM

This is the optional PowerShell provisioning path for the disposable Windows 11 integration VM. The [Hyper-V Manager runbook](README.md) remains the primary path. AutomatedLab creates the lab and installs Windows; the RIDE repository does not install, configure, or invoke AutomatedLab.

## 1. Complete AutomatedLab installation first

On a clean host, follow the upstream [AutomatedLab installation guide](https://automatedlab.org/en/stable/Wiki/Basic/install/) and its linked setup instructions in full. Do not start with an isolated `Install-Module` command: the installation guide covers prerequisites and dependencies, host setup, and the LabSources directory structure that a clean machine needs. Use an elevated Windows PowerShell session where the guide requires it.

Download the Windows 11 Enterprise Evaluation ISO using the [Windows 11 runbook instructions](README.md#2-register-and-download-the-windows-evaluation-iso). Put the ISO in the `ISOs` directory under the LabSources location configured by AutomatedLab. Allow enough disk space for LabSources, the ISO, and the VM files.

The lab and VM names below are deliberately different. AutomatedLab validates machine names against a 15-character limit; `RIDE-Win11-Test` is exactly 15 characters. The lab name `RIDEWin11Test` is also short and contains only letters and numbers.

## 2. Define a VM with outbound network access

AutomatedLab's Hyper-V network definition defaults to an **Internal** switch. An internal switch alone does not provide the guest with an internet route. Also, `New-LabNetworkAdapterDefinition -VirtualSwitch` expects the name of a network already defined in the current AutomatedLab lab; it does not select a pre-existing host Hyper-V switch. Define the lab network first, then build the adapter from that definition.

For this disposable test VM, the example uses AutomatedLab's `-UseNat` option. AutomatedLab creates an internal Hyper-V switch and host NAT, then configures the guest with an address, gateway, and DNS settings. This gives the guest outbound access without bridging it directly onto your physical LAN. See AutomatedLab's [network definition reference](https://automatedlab.org/en/stable/AutomatedLabDefinition/en-us/Add-LabVirtualNetworkDefinition/), [network documentation](https://automatedlab.org/en/stable/Wiki/Basic/networksandaddresses/), and [network adapter command reference](https://automatedlab.org/en/stable/AutomatedLabDefinition/en-us/New-LabNetworkAdapterDefinition/).

Run the following in an elevated PowerShell session on the Hyper-V host after completing AutomatedLab installation and placing the ISO in LabSources. If the ISO is listed more than once, set `$osName` to the exact Windows 11 Enterprise Evaluation entry you intend to install.

```powershell
$ErrorActionPreference = 'Stop'
Import-Module AutomatedLab

$labName = 'RIDEWin11Test'
$vmName = 'RIDE-Win11-Test'
$vmPath = 'D:\VMs\RIDE-Test' # Change this to a drive with sufficient free space.

$isoDirectory = Join-Path (Get-LabSourcesLocation) 'ISOs'
$availableOs = Get-LabAvailableOperatingSystem -Path $isoDirectory
$availableOs | Format-Table OperatingSystemName, Version, IsoPath -AutoSize

$osName = 'Windows 11 Enterprise Evaluation' # Replace with the exact listed name if it differs.
$installationCredential = Get-Credential -Message 'Choose a local administrator account for the disposable guest'

New-LabDefinition -Name $labName -DefaultVirtualizationEngine HyperV -VmPath $vmPath
$networkName = 'RIDE-Internet'
Add-LabVirtualNetworkDefinition -Name $networkName -UseNat
$networkAdapter = New-LabNetworkAdapterDefinition -VirtualSwitch $networkName

Add-LabMachineDefinition -Name $vmName `
    -OperatingSystem $osName `
    -Memory 8GB `
    -Processors 4 `
    -InstallationUserCredential $installationCredential `
    -HypervProperties @{ EnableTpm = 'true'; EnableSecureBoot = 'on' } `
    -NetworkAdapter $networkAdapter

Install-Lab
Show-LabDeploymentSummary
```

The order matters: create the lab, define its NAT network, and only then create a network adapter that refers to that definition. Do not add `-UseDhcp` to this adapter; AutomatedLab assigns the guest's address and NAT gateway from the lab network definition.

If you specifically need a bridged connection instead, first define an **External** network using `Add-LabVirtualNetworkDefinition -Name $networkName -HyperVProperties @{ SwitchType = 'External'; AdapterName = '<host adapter name>' }`, then create its adapter with `New-LabNetworkAdapterDefinition -VirtualSwitch $networkName -UseDhcp`. Replace the placeholder with the active host adapter's exact `Name` from `Get-NetAdapter`. An external switch places the VM on the physical LAN and may affect host adapter behavior; use it only on a trusted network.

## 3. Verify guest connectivity and finish Windows setup

After `Install-Lab` finishes, open the VM in VMConnect and sign in with the local guest account. In an elevated PowerShell session inside the guest, verify that AutomatedLab configured an IPv4 address, default route, and DNS server, then check HTTPS:

```powershell
Get-NetIPConfiguration
Test-NetConnection www.powershellgallery.com -Port 443
```

Confirm `TcpTestSucceeded` is `True`. If there is no IPv4 address or the connection fails, check that the VM adapter uses the `RIDE-Internet` lab network, that the host itself has internet access, and that the host already has no conflicting WinNAT configuration. Do this before installing packages or running integration tests. The AutomatedLab [`Test-LabMachineInternetConnectivity`](https://automatedlab.org/en/stable/AutomatedLabCore/en-us/Test-LabMachineInternetConnectivity/) cmdlet is another host-side check, but a failed ping can reflect ICMP filtering even when HTTPS works.

Use the guest's Windows Settings and a local PowerShell session for updates and Pester as described in steps 4 and 5. These are manual guest setup steps; AutomatedLab is used to provision the VM and manage its checkpoint.

## 4. Install Windows updates in the guest

Inside the guest, open **Settings > Windows Update**, check for updates, install them, and restart when prompted. Repeat until Windows reports no further updates. Keeping the Windows update path first-party avoids adding another module dependency to the VM setup.

## 5. Install Pester 5.7.1 in the guest

Open **PowerShell as Administrator inside the guest VM**. First install the NuGet provider, then install the same Pester version used by CI and verify it is available:

```powershell
Install-PackageProvider -Name NuGet -MinimumVersion '2.8.5.201' -Scope CurrentUser -Force
Install-Module -Name Pester -RequiredVersion '5.7.1' -Repository PSGallery -Scope CurrentUser -Force -SkipPublisherCheck
Import-Module Pester -RequiredVersion '5.7.1'
Get-Module Pester | Select-Object Name, Version, Path
```

Windows includes Pester 3.4.0 signed by Microsoft; Pester 5.7.1 has a different signing publisher. The [Pester install guide](https://pester.dev/docs/introduction/installation) recommends `-SkipPublisherCheck` for this side-by-side upgrade. Use it only for the pinned Pester package after reviewing the [Pester 5.7.1 Gallery listing](https://www.powershellgallery.com/packages/Pester/5.7.1). The guest needs outbound access to PSGallery. Windows PowerShell is sufficient for this pilot.

## 6. Create and restore the clean checkpoint

Once Windows Update and Pester are complete, create a named checkpoint from the host. The VM should be shut down for a consistent clean baseline:

```powershell
$vmName = 'RIDE-Win11-Test'
$snapshotName = 'RIDE-clean-test-base'

Stop-LabVM -ComputerName $vmName -Wait
Checkpoint-LabVM -ComputerName $vmName -SnapshotName $snapshotName
Get-LabVMSnapshot -ComputerName $vmName
Start-LabVM -ComputerName $vmName
```

After each integration run, restore the baseline from an elevated host PowerShell session:

```powershell
Stop-LabVM -ComputerName 'RIDE-Win11-Test' -Wait
Restore-LabVMSnapshot -ComputerName 'RIDE-Win11-Test' -SnapshotName 'RIDE-clean-test-base'
Start-LabVM -ComputerName 'RIDE-Win11-Test'
```

These are AutomatedLab's [checkpoint](https://automatedlab.org/en/stable/AutomatedLabCore/en-us/Checkpoint-LabVM/) and [restore](https://automatedlab.org/en/stable/AutomatedLabCore/en-us/Restore-LabVMSnapshot/) commands. If starting a new PowerShell session, import AutomatedLab and the lab definition first as described in the upstream [Getting Started guide](https://automatedlab.org/en/stable/Wiki/Basic/gettingstarted/).

## 7. Return to the integration runbook

Continue with [step 6 in the main runbook](README.md#6-copy-this-working-tree-into-the-guest) to copy the current working tree into the guest. Keep the guest on the `RIDE-Internet` NAT network while package checks need outbound access. Restore `RIDE-clean-test-base` before another integration run; because the checkpoint predates the repository copy, copy the current checkout into the guest again after restoring it.
