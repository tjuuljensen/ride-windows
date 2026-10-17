<#
.SYNOPSIS
  Verify toolkit three-way file decisions with no filesystem mutation.
.DESCRIPTION
  Uses supplied hashes/manifests/observations. Covers preservation, ownership,
  path aliases, unsafe ancestors and explicit modified-file decisions.
.EXAMPLE
  Invoke-Pester .\tests\ToolkitUpdatePreparation.Tests.ps1
.INPUTS
  None.
.OUTPUTS
  Pester results.
.NOTES
  Compatibility: Pester 5, Windows PowerShell 5.1 and PowerShell 7 on Windows.
  Version: Repository fixture; staging/writer/native ownership acceptance pending.
#>
BeforeAll {
  Import-Module (Join-Path (Split-Path -Parent $PSScriptRoot) 'modules/RIDE.ToolkitUpdatePreparation.psm1') -Force
  function New-ToolkitFile {
    param([string]$Path='tools/example/portable/tool.exe',[string]$Hash=('a'*64),[long]$Length=10)
    [pscustomobject]@{RelativePath=$Path;Sha256=$Hash;Length=$Length}
  }
  function New-ToolkitManifest {
    param([object[]]$Files=@())
    [pscustomobject]@{SchemaVersion=1;Kind='ToolkitOwnedFiles';KitId='field-kit';Files=$Files}
  }
  function New-ToolkitObservation {
    param([object[]]$Files=@())
    $entries=@(foreach($file in $Files){[pscustomobject]@{RelativePath=$file.RelativePath;Kind='File';Sha256=$file.Sha256;Length=$file.Length}})
    [pscustomobject]@{SchemaVersion=1;Kind='ToolkitFilesystemObservation';Root='C:\Kits\Field';Complete=$true;CaseSensitive=$false;RootIsReparsePoint=$false;Entries=$entries}
  }
  function New-ToolkitCase {
    param([object[]]$Old=@(),[object[]]$Wanted=@(),[object[]]$Current=@())
    @{KitId='field-kit';Root='C:\Kits\Field';PreviousManifest=(New-ToolkitManifest $Old);DesiredManifest=(New-ToolkitManifest $Wanted);Observation=(New-ToolkitObservation $Current)}
  }
}
Describe 'Owned toolkit update decisions' {
  It 'stages a first publication without creating directories or granting readiness' {
    $args=New-ToolkitCase -Wanted @((New-ToolkitFile));$args.PreviousManifest=$null
    $r=New-RideToolkitUpdatePreparation @args
    $r.Decisions[0].Action|Should -Be StageAdd;$r.StagingRequired|Should -BeTrue
    $r.ReadyForPublication|Should -BeFalse;$r.RecoverySupported|Should -BeFalse
    $r.ConflictCount|Should -Be 0
  }
  It 'stages replacement only when the old owned file is unchanged' {
    $a=New-ToolkitFile;$b=New-ToolkitFile -Hash ('b'*64)
    $args=New-ToolkitCase -Old @($a) -Wanted @($b) -Current @($a)
    $r=New-RideToolkitUpdatePreparation @args
    $r.Decisions[0].Action|Should -Be StageReplace
    $r.Decisions[0].Previous.Sha256|Should -BeExactly ('a'*64)
    $r.Decisions[0].Desired.Sha256|Should -BeExactly ('b'*64)
  }
  It 'keeps owned content already at the desired digest without overwriting it' {
    $a=New-ToolkitFile;$b=New-ToolkitFile -Hash ('b'*64)
    $args=New-ToolkitCase -Old @($a) -Wanted @($b) -Current @($b)
    $r=New-RideToolkitUpdatePreparation @args
    $r.Decisions[0].Action|Should -Be Keep;$r.StagingRequired|Should -BeFalse
  }
  It 'removes only unchanged obsolete managed files while preserving generated and unrelated files' {
    $a=New-ToolkitFile;$log=New-ToolkitFile -Path tools/example/portable/results.log;$other=New-ToolkitFile -Path notes.txt
    $args=New-ToolkitCase -Old @($a) -Current @($a,$log,$other)
    $r=New-RideToolkitUpdatePreparation @args
    @($r.Decisions|Where-Object Action -eq RemoveOwnedUnchanged).Count|Should -Be 1
    @($r.Decisions|Where-Object Action -eq PreserveUnmanaged).Count|Should -Be 2
  }
  It 'retains modified obsolete files for an explicit later decision' {
    $a=New-ToolkitFile;$changed=New-ToolkitFile -Hash ('c'*64)
    $args=New-ToolkitCase -Old @($a) -Current @($changed)
    $r=New-RideToolkitUpdatePreparation @args
    $r.Decisions[0].Action|Should -Be Conflict;$r.Decisions[0].Reason|Should -Be ModifiedOrNonFileObsolete
    $r.Decisions[0].RequiresExplicitDecision|Should -BeTrue
  }
  It 'reports a modified managed replacement conflict alongside independent new work' {
    $a=New-ToolkitFile;$b=New-ToolkitFile -Hash ('b'*64);$changed=New-ToolkitFile -Hash ('c'*64);$new=New-ToolkitFile -Path tools/other/portable/other.exe
    $args=New-ToolkitCase -Old @($a) -Wanted @($b,$new) -Current @($changed)
    $r=New-RideToolkitUpdatePreparation @args
    $r.ConflictCount|Should -Be 1
    @($r.Decisions|Where-Object Action -eq StageAdd).Count|Should -Be 1
    ($r.Decisions|Where-Object Action -eq Conflict).Reason|Should -Be ModifiedManagedFile
    $r.ReadyForPublication|Should -BeFalse
  }
  It 'does not silently recreate a desired managed file the operator may have deleted' {
    $a=New-ToolkitFile;$args=New-ToolkitCase -Old @($a) -Wanted @($a)
    $r=New-RideToolkitUpdatePreparation @args
    $r.Decisions[0].Reason|Should -Be MissingManagedFile;$r.ConflictCount|Should -Be 1
  }
  It 'forgets an obsolete already absent record without deleting anything' {
    $args=New-ToolkitCase -Old @((New-ToolkitFile));$r=New-RideToolkitUpdatePreparation @args
    $r.Decisions[0].Action|Should -Be ForgetAbsent;$r.StagingRequired|Should -BeFalse
  }
  It 'never adopts an unowned same-hash file just because desired content matches' {
    $a=New-ToolkitFile;$args=New-ToolkitCase -Wanted @($a) -Current @($a)
    $r=New-RideToolkitUpdatePreparation @args
    $r.Decisions[0].Action|Should -Be Conflict;$r.Decisions[0].Reason|Should -Be UnownedPath
  }
  It 'compares byte length as well as digest' {
    $a=New-ToolkitFile;$b=New-ToolkitFile -Length 11
    $args=New-ToolkitCase -Old @($a) -Wanted @($a) -Current @($b)
    (New-RideToolkitUpdatePreparation @args).Decisions[0].Reason|Should -Be ModifiedManagedFile
  }
  It 'keeps source objects unchanged and returns copied evidence' {
    $a=New-ToolkitFile;$args=New-ToolkitCase -Old @($a) -Wanted @($a) -Current @($a)
    $before=$args|ConvertTo-Json -Depth 12 -Compress
    $r=New-RideToolkitUpdatePreparation @args;$r.Decisions[0].Observed.Sha256='changed'
    ($args|ConvertTo-Json -Depth 12 -Compress)|Should -BeExactly $before
  }
  It 'uses one case-insensitive identity without promising a case-only rename' {
    $a=New-ToolkitFile -Path Tools/App.exe;$b=New-ToolkitFile -Path tools/app.exe -Hash ('A'*64)
    $args=New-ToolkitCase -Old @($a) -Wanted @($b) -Current @($a)
    $r=New-RideToolkitUpdatePreparation @args
    $r.Decisions.Count|Should -Be 1;$r.Decisions[0].Action|Should -Be Keep
    $r.Decisions[0].Observed.RelativePath|Should -BeExactly Tools/App.exe
  }
}
Describe 'Toolkit namespace and source guards' {
  It 'rejects unsafe member path <Path>' -ForEach @(
    @{Path='../escape'},@{Path='tools/../escape'},@{Path='C:/tool.exe'},@{Path='/root/tool.exe'},
    @{Path='tools\tool.exe'},@{Path='tools//file'},@{Path='tools/file.'},@{Path='tools/file '},
    @{Path='tools/CON.txt'},@{Path='tools/com1'},@{Path='tools/a:b'},@{Path='tools/*.exe'},
    @{Path='tools/./a'},@{Path='tools/'},@{Path=('a'*256)},@{Path="tools/a`nfile"}
  ) {
    $args=New-ToolkitCase -Wanted @((New-ToolkitFile -Path $Path))
    {New-RideToolkitUpdatePreparation @args}|Should -Throw
  }
  It 'rejects duplicate paths and file/descendant manifest collisions' {
    foreach($paths in @(@('tools/a.exe','TOOLS/A.exe'),@('tools','tools/a.exe'))){
      $args=New-ToolkitCase -Wanted @((New-ToolkitFile -Path $paths[0]),(New-ToolkitFile -Path $paths[1]))
      {New-RideToolkitUpdatePreparation @args}|Should -Throw
    }
  }
  It 'requires explicit subdirectory roots rather than drive/share roots or device/relative paths' {
    foreach($root in @('C:\','\\server\share\','relative','C:relative','\\?\C:\kit','C:\kit\..\other')){
      $args=New-ToolkitCase;$args.Root=$root;$args.Observation.Root=$root
      {New-RideToolkitUpdatePreparation @args}|Should -Throw
    }
    $args=New-ToolkitCase;$args.Root='\\server\share\kit';$args.Observation.Root=$args.Root
    (New-RideToolkitUpdatePreparation @args).Root|Should -BeExactly '\\server\share\kit'
  }
  It 'requires complete matching root observations without case-sensitive or root-reparse ambiguity' {
    foreach($case in @('Incomplete','WrongRoot','CaseSensitive','RootReparse')){
      $args=New-ToolkitCase
      switch($case){Incomplete{$args.Observation.Complete=$false}WrongRoot{$args.Observation.Root='C:\Other'}CaseSensitive{$args.Observation.CaseSensitive=$true}RootReparse{$args.Observation.RootIsReparsePoint=$true}}
      {New-RideToolkitUpdatePreparation @args}|Should -Throw
    }
  }
  It 'blocks managed paths beneath a reparse, unavailable or file ancestor' {
    foreach($kind in @('ReparsePoint','Unavailable','File')){
      $a=New-ToolkitFile;$args=New-ToolkitCase -Wanted @($a)
      $entry=[pscustomobject]@{RelativePath='tools';Kind=$kind;Sha256=$null;Length=$null}
      if($kind -eq 'File'){$entry.Sha256='a'*64;$entry.Length=1}
      $args.Observation.Entries=@($entry)
      $r=New-RideToolkitUpdatePreparation @args
      ($r.Decisions|Where-Object RelativePath -eq $a.RelativePath).Reason|Should -Be UnsafeAncestor
    }
  }
  It 'blocks a desired file over a directory, reparse or unavailable item' {
    foreach($kind in @('Directory','ReparsePoint','Unavailable')){
      $a=New-ToolkitFile;$args=New-ToolkitCase -Wanted @($a)
      $args.Observation.Entries=@([pscustomobject]@{RelativePath=$a.RelativePath;Kind=$kind;Sha256=$null;Length=$null})
      (New-RideToolkitUpdatePreparation @args).Decisions[0].Reason|Should -Be NonFileCollision
    }
  }
  It 'detects observed descendants even when a parent directory row was omitted' {
    $args=New-ToolkitCase -Wanted @((New-ToolkitFile -Path tools)) -Current @((New-ToolkitFile -Path tools/unrelated.txt))
    $r=New-RideToolkitUpdatePreparation @args
    ($r.Decisions|Where-Object RelativePath -eq tools).Reason|Should -Be PathHasObservedDescendants
    ($r.Decisions|Where-Object RelativePath -eq tools/unrelated.txt).Action|Should -Be PreserveUnmanaged
  }
  It 'preserves ordinary observed directories while staging an unowned-free child' {
    $a=New-ToolkitFile;$args=New-ToolkitCase -Wanted @($a)
    $args.Observation.Entries=@([pscustomobject]@{RelativePath='tools';Kind='Directory';Sha256=$null;Length=$null})
    $r=New-RideToolkitUpdatePreparation @args
    ($r.Decisions|Where-Object RelativePath -eq tools).Action|Should -Be PreserveUnmanaged
    ($r.Decisions|Where-Object RelativePath -eq $a.RelativePath).Action|Should -Be StageAdd
  }
  It 'rejects wrong kit identity, schema and non-literal digests or lengths' {
    foreach($case in @('Kit','Schema','Hash','Length','Negative','NonFileHash')){
      $a=New-ToolkitFile;$args=New-ToolkitCase -Wanted @($a)
      switch($case){Kit{$args.DesiredManifest.KitId='other'}Schema{$args.DesiredManifest.SchemaVersion='1'}Hash{$a.Sha256='not-a-hash'}Length{$a.Length='10'}Negative{$a.Length=-1}NonFileHash{$args.Observation.Entries=@([pscustomobject]@{RelativePath='tools';Kind='Directory';Sha256=('a'*64);Length=10})}}
      {New-RideToolkitUpdatePreparation @args}|Should -Throw
    }
  }
  It 'accepts JSON data round trips without treating the plan as publication approval' {
    $a=New-ToolkitFile;$args=New-ToolkitCase -Old @($a) -Wanted @($a) -Current @($a)
    foreach($field in @('PreviousManifest','DesiredManifest','Observation')){$args[$field]=ConvertFrom-Json ($args[$field]|ConvertTo-Json -Depth 10)}
    (New-RideToolkitUpdatePreparation @args).ReadyForPublication|Should -BeFalse
  }
}
