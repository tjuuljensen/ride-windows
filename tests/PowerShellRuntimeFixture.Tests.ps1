BeforeAll {
  Import-Module (Join-Path $PSScriptRoot 'integration/RIDE.PowerShellRuntimeFixture.psm1') -Force
  $script:previousAttestation=$env:RIDE_INTEGRATION_VM
  $script:archive=Join-Path $TestDrive 'PowerShell-7.6.5-win-x64.zip'
  [IO.File]::WriteAllText($script:archive,'Inert incorrect archive; must not be extracted.')
  $script:target='C:\RIDE\PortableAcceptance\'+[guid]::NewGuid().ToString('N')+'\core-runtime'
}
AfterAll {$env:RIDE_INTEGRATION_VM=$script:previousAttestation}
Describe 'Disposable PowerShell runtime fixture boundary' {
  It 'refuses preparation without guest attestation' {
    $env:RIDE_INTEGRATION_VM='0'
    {Expand-RidePowerShellRuntimeFixture -ArchivePath $script:archive -Destination $script:target}|Should -Throw '*attested*'
    Test-Path -LiteralPath $script:target|Should -BeFalse
  }
  It 'refuses a destination outside the fixed disposable run layout' {
    $env:RIDE_INTEGRATION_VM='1'
    {Expand-RidePowerShellRuntimeFixture -ArchivePath $script:archive -Destination $TestDrive}|Should -Throw '*bounded guest run*'
  }
  It 'refuses a changed archive before creating the destination' {
    $env:RIDE_INTEGRATION_VM='1'
    {Expand-RidePowerShellRuntimeFixture -ArchivePath $script:archive -Destination $script:target}|Should -Throw '*publisher pin*'
    Test-Path -LiteralPath $script:target|Should -BeFalse
  }
}
