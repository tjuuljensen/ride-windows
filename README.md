# ride-windows

&nbsp;

## Description

This RIDE repo (Remove - Install - Disable - Enable) is a PowerShell script for automation of routine tasks done after a fresh installation of Windows 10/11 and Windows Server 2016 / 2019. While the repo originally was centred on minimizing Windows telemetry traffic and on a few must-have installations and configurations, it has evolved over the years and now includes a long list of installations, primarily focused on forensic investigation and analysis. 
The repo does not hold a complete set of all existing Windows tweaks, nor is it a complete way of creating the fully hardened/locked-down machine. 


## Contents
 - [Introduction](#introduction)
 - [Installation](#installation)
 - [History](#history)
 - [FAQ](#faq)
 - [Windows builds overview](#windows-builds-overview)
 - [Advanced usage](#advanced-usage)
 - [Maintaining own forks](#maintaining-own-forks)
 - [Contribution guidelines](#contribution-guidelines)
 - [Credits](#credits)

&nbsp;

## Introduction

I am a Linux user and I use this script to make sure I remember a lot of small steps and configuration tweaks when I make a new Windows virtual or a physical machine. I can create a fully configured machine in a short time with the latest software from the originating source. 

These are my guiding principles:
- I want to have an updated version of Windows 10/11 privacy/hardening tweaks that I frequently use or that I might use in an emergency.
- The script should take away 80-90% percent of "initial configuration" and cumbersome installations having multiple steps.
- The script cuts installation time down from days/hours to minutes
- Anyone with a decent amount of technical understanding, should be able to adopt the installation on their own terms.
- The script must support physical machines as well as virtual machines
- If there is a way in PowerShell, I choose that way. But I'd rather use a few built-in Windows command line tools instead of wasting weeks on "the clean PS path".
- I prefer a script that is maintainable and choose to have a lot of redundant code in my repo.
   
I have a Linux repo and use the same script architecture in my Fedora Linux configuration: https://github.com/tjuuljensen/ride-fedora.

## Installation
Make sure your account is a member of the *Administrators* group as the script attempts to run with elevated privileges. If you just want to run the script with the *default* preset, download and unpack the [latest release](https://github.com/tjuuljensen/ride-windows) and then simply double-click on the *default.cmd* file and confirm *User Account Control* prompt. 
While you can use it as a non-admin user and run it with elevated rights as an admin user, some things will NOT work this way. Read the code or figure it out yourself - but the safe way is to make the primary user admin and run it elevated. For security reasons, the script has features to remove the user from the admin group after installation.

The script supports command line options and parameters which can help you customize the tweak selection or even add your own custom tweaks, however, these features require some basic knowledge of command line usage and PowerShell scripting. Refer to the [Advanced usage](#advanced-usage) section for more details.


&nbsp;

## History

When Windows 10 was released, a lot of discussions emerged about the telemetry and dial-back functions that Microsoft implemented and which had very few configuration options for the normal user. Some people required a machine with a low footprint for privacy reasons, some just needed a machine that was more silent when listening on the network.

For years I maintained a smaller PowerShell lockdown and configuration script to handle my Windows installations, but at some point, I realized that it was a hard game catching up with all the new changes every time a new Windows version was released. A part of the "catch-up game" was to search the internet (GitHub rules!) for clever guys who had been collecting information and putting things into scripts. Most people did not use PowerShell to change the options configuration, so I often had to translate command line/GUI guides into PowerShell.

One day I visited Disassembler0's (now archived) Win10-Initial-Setup-Script on github (https://github.com/Disassembler0/Win10-Initial-Setup-Script). It covered 80% of the stuff I did and had an adjustable command line interface. I immediately discarded a lot of my old code and was using the Disassembler0 repo for years next to a slimmer version of my own.

When Disassembler0 archived his repo in 2021 (Thanks for all the fish!), I adopted all that code in this repo - and I am back to maintaining my bootstrap script myself.

The repo has grown a lot over the last few years. Especially with software installations. I work as a forensic investigator and use a lot of tools, some free and some with license. If you use the script and install software from these sources, I urge you to support the authors of the software. Send them a few bucks if they have a "Buy me a Beer/Coffee" button, or buy a license if they have a licensing option. 
And please be aware, that even though some of the software is free for private use, many of the tools require a license if you use it professionally as I do. 


&nbsp;

## FAQ

**Q:** Can I run the script safely?  
**A:** Definitely not. You have to understand what the functions do and what will be the implications for you if you run them. Some functions lower security, hide controls or uninstall applications. **If you're not sure what the script does, do not attempt to run it!**

**Q:** Can I run the script repeatedly?  
**A:** Yes (at least that I my goal). All of the tweaks and configuration done in registry has been written to support exactly that. A few of the configurations cannot be undone though (replacing the default Windows wallpaper is one example).

**Q:** Which versions and editions of Windows are supported?  
**A:** The script aims to be fully compatible with the most up-to-date 64-bit version of Windows 10/11 receiving updates from the semi-annual channel, however if you create your own preset and exclude the incompatible tweaks, it will also work on LTSB/LTSC. Many of the functions will work on 32-bit Windows, *but some will not*. 
The vast majority of the tweaks will work on all Windows editions. Some of them rely on group policy settings, so there may be a few limitations for Home and Education editions.

**Q:** Can I run the script on Windows Server 2016, 2019 or 2022?  
**A:** Yes. Windows Server is supported. There are even a few tweaks specific to a Server environment. Keep in mind though, that the script is still primarily designed for Windows 10 / 11, so you have to create your own preset.

**Q:** Can I run the script on Windows 7, 8, 8.1 or other versions of Windows?  
**A:** No. Although some tweaks may work also on older versions of Windows, the script is developed only for Windows 10 / 11 and Windows Server 2016 / 2019 / 2022. There are no plans to support older versions.

**Q:** Can I run the script in a multi-user environment?  
**A:** Yes, to a certain extent. Some tweaks (most notably UI tweaks) are set only for the user currently executing the script. As stated above, the script can be run repeatedly; therefore it's possible to run it multiple times, each time as a different user. Due to the nature of authentication and privilege escalation mechanisms in Windows, most of the tweaks can be successfully applied only by users belonging to the *Administrators* group. Standard users will get a UAC prompt asking for admin credentials which then causes the tweaks to be applied to the given admin account instead of the original non-privileged one. There are a few ways this can be circumvented programmatically, but I'm not planning to include any as it would negatively impact code complexity and readability. If you still wish to try to use the script in a multi-user environment, check [this answer in issue #29](https://github.com/Disassembler0/Win10-Initial-Setup-Script/issues/29#issuecomment-333040591) for some pointers.

**Q:** Did you test the script?  
**A:** Yes. I'm testing new additions on up-to-date 64-bit Pro editions of Windows 10 and 11 in VMs. I'm also regularly using it for most of my work and home installations.

**Q:** I've run the script and it did something I don't like, how can I undo it?  
**A:** For every tweak (with a few exceptions), there is also a corresponding function which restores the default settings. The default is considered freshly installed Windows 10 / 11 or Windows Server 2016 with no adjustments made during or after the installation. Use the tweaks to create and run new presets. Alternatively, since some functions are just automation for actions which can be done using GUI, find appropriate control and modify it manually.

**Q:** I've run the script and some controls are now greyed out and display the message "*Some settings are hidden or managed by your organization*", why?  
**A:** To ensure that system-wide tweaks are applied smoothly and reliably, some of them make use of *Group Policy Objects* (*GPO*). The same mechanism is employed also in companies managing their computers in a large scale, so the users without administrative privileges can't change the settings. If you wish to change a setting locked by GPO, apply the appropriate restore tweak and the control will become available again.

**Q:** I've run the script and it broke my computer / killed my neighbour's dog / caused World War 3.  
**A:** I don't care. Also, that's not a question.

**Q:** I'm using a tweak for &lt;feature&gt; on my installation, can you add it?  
**A:** Submit a PR, create a feature request issue or drop me a message. If I find the functionality simple and useful, I might add it. I want to stay clear of any 3rd party modules and executables to do configurations (including also *Chocolatey*, *NuGet*, *Ninite* or other automation solutions), so if you are asking for something in that area, please don't expect me to incorporate it.

**Q:** Didn't you just say, that you wanted to stay clear of 3rd party modules like NuGet? I see that you use it to install the Nuget module PSWindowsUpdate. Why?  
**A:** Oh, you read this far - and you actually verified the code. Kudos to you. Microsoft does not support this functionality (yet) using native Powershell. I still want to stay clear of 3rd party modules, but I needed the PowerShell enabled Windows Update functionality on a machine, so I broke my own rules. It sucks, I know. But life is hard, right? 

**Q:** I'm using a freely available piece of forensic software to examine &lt;some artifact&gt;, can you add it?  
**A:** Submit a PR, create a feature request issue or drop me a message. If I like the software or can see the use of it for some of my fellow forensic colleagues, I might add it. 

**Q:** Can I use the script or modify it for my / my company's needs?  
**A:** Sure, knock yourself out. Just don't forget to include copyright notice as per MIT license requirements. I'd also suggest including a link to this GitHub repo as it's very likely that something will be changed, added or improved to keep track of future versions of Windows 10 / 11.

**Q:** Why are there repeated pieces of code throughout some functions?  
**A:** So you can directly take a function block or a line from within a function and use it elsewhere, without elaborating on any dependencies.

**Q:** For how long are you going to maintain the script?  
**A:** As long as I find it useful. I have maintained it since 2014, so I'll probably continue for some time.

**Q:** A single function or a few functions does not work, why don't you fix it?  
**A:** I run Linux on all of my primary PCs. This is just a hobby project. :-) But by all means - Submit a PR, create a feature request issue or drop me a message. It is likely that I do not know that something broke, and I will fix the features in the script once they are added.

**Q:** Being a Linux user, why haven't you written the code in this repository to support multiple platforms, so it could run under Linux as well?
**A:** Because it is a Windows bootstrap script. Everything is centered around Windows, so why bother writing code that configure a Windows machine but runs under Linux? Only reason that I can think of is, that I sometimes forget which platform I am on, and I write code for this repo on my Linux pc. When I test it in the built-in VS Code terminal, some of the functionality fails (because there is no BITS service on Linux). But hey - even I need to wake up sometimes. BTW: My Linux bootstrapper is written in bash. Go check it out here: https://github.com/tjuuljensen/ride-fedora.

&nbsp;

## Windows builds overview
### Windows 10

| Version |        Code name        |     Marketing name     | Build |
| :-----: | ----------------------- | ---------------------- | :---: |
|  1507   | Threshold 1 (TH1 / RTM) | N/A                    | 10240 |
|  1511   | Threshold 2 (TH2)       | November Update        | 10586 |
|  1607   | Redstone 1 (RS1)        | Anniversary Update     | 14393 |
|  1703   | Redstone 2 (RS2)        | Creators Update        | 15063 |
|  1709   | Redstone 3 (RS3)        | Fall Creators Update   | 16299 |
|  1803   | Redstone 4 (RS4)        | April 2018 Update      | 17134 |
|  1809   | Redstone 5 (RS5)        | October 2018 Update    | 17763 |
|  1903   | 19H1                    | May 2019 Update        | 18362 |
|  1909   | Vanadium                | November 2019 Update   | 18363 |
|  2004   | Vibranium               | May 2020 Update        | 19041 |
|  20H2   | Vibranium               | October 2020 Update    | 19042 |
|  21H1   | Vibranium               | May 2021 Update        | 19043 |
|  21H2   | Vibranium               | November 2021 Update   | 19044 |
|  22H2   | Vibranium               | October 2022 Update    | 19045 |

### Windows 11

| Version |        Code name        |     Marketing name     | Build |
| :-----: | ----------------------- | ---------------------- | :---: |
|  21H2   | Sun Valley              | October 2021 Update    | 22000 |
|  22H2   | Sun Valley 2            | September 2022 Update  | 22621 |
|  23H2   | Sun Valley 3            | October 2023 Update    | 22631 |

&nbsp;

## Advanced usage

    powershell.exe -NoProfile -ExecutionPolicy Bypass -File  ride.ps1 [-include filename] [-preset filename] [-log logname] [-ini inifile]  [[!]tweakname]

    -include filename       load module with user-defined tweaks
    -preset filename        load preset with tweak names to apply
    -log logname            save script output to a file
    -ini inifile            load values from INI file
    tweakname               apply tweak with this particular name
    !tweakname              remove tweak with this particular name from the selection

### Presets

The tweak library consists of separate idempotent functions, containing one tweak each. The functions can be grouped into *presets*. Preset is simply a list of function names which should be called. Any function which is not present or is commented in a preset will not be called, thus the corresponding tweak will not be applied. In order for the script to do something, you need to supply at least one tweak library via `-include` and at least one tweak name, either via `-preset` or directly as a command line argument.

The tweak names can be prefixed with an exclamation mark (`!`) which will instead cause the tweak to be removed from selection. This is useful in cases when you want to apply the whole preset, but omit a few specific tweaks in the current run. Alternatively, you can have a preset that "patches" another preset by adding and removing a small amount of tweaks.

To supply a customized preset, you can either pass the function names directly as arguments.

    powershell.exe -NoProfile -ExecutionPolicy Bypass -File ride.ps1 -include lib-windows.psm1 EnableFirewall EnableDefender

Or you can create a file where you write the function names (one function name per line, no commas or quotes, whitespaces allowed, comments starting with `#`) and then pass the filename using the `-preset` parameter.  
Example of a preset file `mypreset.txt`:

    # Security tweaks
    EnableFirewall
    EnableDefender

    # UI tweaks
    ShowKnownExtensions
    ShowHiddenFiles   # Only hidden, not system

Command using the preset file above:

    powershell.exe -NoProfile -ExecutionPolicy Bypass -File ride.ps1 -include lib-windows.psm1 -preset mypreset.txt

### Includes

The script also supports the inclusion of custom tweaks from user-supplied modules passed via the `-include` parameter. The content of the user-supplied module is completely up to the user, however, it is strongly recommended to have the tweaks separated into respective functions as the main tweak library has. The user-supplied scripts are loaded into the main script via `Import-Module`, so the library should ideally be a `.psm1` PowerShell module.
Example of a user-supplied tweak library `mytweaks.psm1`:

```powershell
Function MyTweak1 {
    Write-Output "Running MyTweak1..."
    # Do something
}

Function MyTweak2 {
    Write-Output "Running MyTweak2..."
    # Do something else
}
```

Command using the script above:

    powershell.exe -NoProfile -ExecutionPolicy Bypass -File ride.ps1 -include mytweaks.psm1 MyTweak1 MyTweak2

### Combination

All features described above can be combined. You can have a preset which includes both tweaks from the original script and your personal ones. Both `-include` and `-preset` options can be used more than once, so you can split your tweaks into groups and then combine them based on your current needs. The `-include` modules are always imported before the first tweak is applied, so the order of the command line parameters doesn't matter and neither does the order of the tweaks (except for `RequireAdmin`, which should always be called first and `Restart`, which should always be called last). It can happen that some tweaks are applied more than once during a single run because you have them in multiple presets. That shouldn't cause any problems as the tweaks are idempotent.  
Example of a preset file `otherpreset.txt`:

    MyTweak1
    MyTweak2
    !ShowHiddenFiles   # Will remove the tweak from the selection
    WaitForKey

Command using all three examples combined:

    powershell.exe -NoProfile -ExecutionPolicy Bypass -File ride.ps1 -include lib-windows.psm1 -include mytweaks.psm1 -preset mypreset.txt -preset otherpreset.txt Restart

&nbsp;

### Logging

If you'd like to store output from the script execution, you can do so using `-log` parameter followed by a filename of the log file you want to create. For example:

    powershell.exe -NoProfile -ExecutionPolicy Bypass -File ride.ps1 -include lib-windows.psm1 -preset mypreset.txt -log myoutput.log

The logging is done using PowerShell `Start-Transcript` cmdlet, which writes extra information about the current environment (date, machine and user name, command used for execution etc.) to the beginning of the file and logs both standard output and standard error streams.

### Using INI files

You can load personal settings to the script using an INI file with certain parameters. The parameters relate to specific functions in the config script. The table shows the functions where the feature is implemented and the default values.

|       Function / Tweak     |    Ini Section      |     Ini Key         | Default value          |
| -------------------------- | ------------------- | ------------------- | ---------------------- |
|  CreateNewLocalAdmin        | LocalAdmin          | AdminUser           | Admin                  |
|  CreateNewLocalAdmin        | LocalAdmin          | AdminPassword       | -                      |
|  EnableBitlockerTPMandPIN   | Bitlocker           | TPMandPINPassword   | -                      |
|  SetRegionalSettings        | Language            | WinUserLanguage     | en-GB                  |
|  SetRegionalSettings        | Language            | Culture             | en-GB                  |
|  SetRegionalSettings        | Language            | Keyboard            | 0406:00000406 (Danish) |
|  SetRegionalSettings        | Language            | Location            | 0x3d (Denmark)         |
|  SetRegionalSettings        | Language            | SystemLocale        | da-DK                  |
|  SetRegionalSettings        | Language            | TimeZone            | Romance Standard Time  |
|  InstallVMwareWorkstation   | VMwareWorkstation   | VMWAREWORKSTATION16 | -                      |
|  (many)                     | Customization       | ToolsFolder         | \Tools                 |

## Maintaining own forks

The easiest way to customize the script settings it is to create your own preset and, if needed, your own tweak scripts as described above. For an easy start, you can base the modifications on the *default.cmd* and *default.preset* and maintain just that. If you choose to fork the script anyway, you don't need to comment or remove the actual functions in *lib-windows.psm1*, because if they are not called, they are not used.

If you wish to make more elaborate modifications to the basic script and incorporate some personal tweaks or adjustments, then I suggest doing it in the following way:

1. Fork the repository on GitHub (obviously).
2. Clone your fork on your computer.

    ```
    git clone https://github.com/<yournamehere>/ride-windows
    cd ride-windows
    ```

3. Add the original repository as a remote (*upstream*).

    ```
    git remote add upstream https://github.com/tjuuljensen/ride-windows
    ```

4. Commit your modifications as you see fit.
5. Once there are new additions in the upstream, create a temporary branch, fetch the changes and reset the branch to be identical to this repository.

    ```
    git branch upstream
    git checkout upstream
    git fetch upstream
    git reset --hard upstream/master
    ```

6. When you have the upstream branch up to date, check back your master and rebase it based on the upstream branch. If there are some conflicts between the changesets, you'll be asked to resolve them manually.

    ```
    git checkout master
    git rebase upstream
    ```

7. Eventually, delete the upstream branch and force-push your changes back onto GitHub.

    ```
    git branch -D upstream
    git push -f master
    ```

**Word of warning:** Rebasing and force-pushing will change the history of your commits. The upside is that your adjustments will always stay on top of the commit history. The downside is that everybody remote-tracking your repository will always have to rebase and force-push too, otherwise, their commit history will not match yours.

&nbsp;

## Contribution guidelines

Following is a list of rules which I'm trying to apply in this project. The rules are not binding and I accept pull requests even if they don't adhere to them, as long as their purpose and content are clear. In cases when there are too many rule violations, I might simply redo the whole functionality and reject the PR while still crediting you. If you'd like to make my work easier, please consider adhering to the following rules too.

### Function naming
Try to give a function a meaningful name up to 27 characters long, which gives away the purpose of the function. Use verbs like `Enable`/`Disable`, `Show`/`Hide`, `Install`/`Uninstall`, and `Add`/`Remove` at the beginning of the function name. In case the function doesn't fit any of these verbs, come up with another name, beginning with the verb `Set`, which indicates what the function does, e.g. `SetCurrentNetworkPrivate` and `SetCurrentNetworkPublic`.

### Revert functions
Always add a function with the opposite name (or equivalent) which reverts the behaviour to default. The default is considered freshly installed Windows 10/11 or Windows Server 2016 / 2019 with no adjustments made during or after the installation. If you don't have access to either of these, create the revert function to the best of your knowledge and I will fill in the rest if necessary.

### Function similarities
Check if there isn't already a function with a similar purpose as the one you're trying to add. As long as the name and objective of the existing function are unchanged, feel free to add your tweak to that function rather than create a new one.

### Function grouping
Try to group functions thematically. There are already several major groups (privacy, security, services etc.), but even within these, some tweaks may be related to each other. In such a case, add a new tweak below the existing one and not to the end of the whole group.

### Default preset
Always add a reference to the tweak and its revert function in the *Default.preset*. Add references to both functions on the same line (mind the spaces) and always comment out the revert function. Whether to comment out the tweak in the default preset is a matter of personal preference. The rule of thumb is that if the tweak makes the system faster, smoother, more secure and less obtrusive, it should be enabled by default. Usability has preference over performance (that's why e.g. indexing is kept enabled).

### Repeatability
Unless applied to an unsupported system, all functions have to be applicable repeatedly without any errors. When you're creating a registry key, always check first if the key doesn't happen to already exist. When you're deleting a registry value, always append `-ErrorAction SilentlyContinue` to prevent errors while deleting already deleted values.

### Input/output hiding
Suppress all output generated by commands and cmdlets using `| Out-Null` or `-ErrorAction SilentlyContinue` where applicable. Whenever an input is needed, use appropriate arguments to suppress the prompt and programmatically provide values for the command to run (e.g. using `-Confirm:$false`). The only acceptable output is from the `Write-Output` cmdlets in the beginning of each function and from non-suppressible cmdlets like `Remove-AppxPackage`.

### Registry
Create the registry keys only if they don't exist on a fresh installation of Windows 10 / 11 or Windows Server 2016 / 2019. When removing from the registry, delete only registry values, not the whole keys. When you're setting registry values, always use `Set-ItemProperty` instead of `New-ItemProperty`. When you're removing registry values, choose either `Set-ItemProperty` or `Remove-ItemProperty` to reinstate the same situation as it was on the clean installation. Again, if you don't know what the original state was, let me know in PR description and I will fill in the gaps. When you need to use `HKEY_USERS` registry hive, always add following snippet before the registry modification to ensure portability.

```powershell
If (!(Test-Path "HKU:")) {
    New-PSDrive -Name HKU -PSProvider Registry -Root HKEY_USERS | Out-Null
}
```

### Force usage
Star Wars jokes aside, don't use `-Force` option unless absolutely necessary. The only permitted case is when you're creating a new registry key (not a value) and you need to ensure that all parent keys will be created as well. In such case always check first if the key doesn't already exist, otherwise, you will delete all its existing values.

### Comments
Always add a simple comment above the function briefly describing what the function does, especially if it has an ambiguous name or if there is some logic hidden under the hood. If you know that the tweak doesn't work on some editions of Windows 10 or on Windows Server, state it in the comment too. Add a `Write-Output` cmdlet with a short description of action to the first line of the function body, so the user can see what is being executed and which function is the problematic one whenever an error occurs. The comment is written in present simple tense, the `Write-Output` in present continuous with ellipsis (resp. three dots) at the end.

### Coding style
Indent using tabs, enclose all string values in double quotes (`"`) and strictly use `PascalCase` wherever possible. Put the opening curly bracket on the same line as the function name or condition, but leave the closing bracket on a separate line for readability.

### Examples

**Naming example**: Consider function `EnableFastMenu`. What does it do? Which menu? How fast is *fast*? A better name might be `EnableFastMenuFlyout`, so it's a bit clearer that we're talking about the menu flyout delays. But the counterpart function would be `DisableFastMenuFlyouts` which is not entirely true. We're not *disabling* anything, we're just making it slow again. So even better might be to name them `SetFastMenuFlyouts` and `SetSlowMenuFlyouts`. Or better yet, just add the functionality to already existing `SetVisualFXPerformance`/`SetVisualFXAppearance`. Even though the names are not 100% match, they aim to tweak similar aspects and operate within the same registry keys.

**Coding example:** The following code applies most of the rules mentioned above (naming, output hiding, repeatability, force usage, comments and coding style).

```powershell
# Enable some feature
Function EnableSomeFeature {
    Write-Output "Enabling some feature..."
    If (!(Test-Path "HKLM:\Some\Registry\Key")) {
        New-Item -Path "HKLM:\Some\Registry\Key" -Force | Out-Null
    }
    Set-ItemProperty -Path "HKLM:\Some\Registry\Key" -Name "SomeValueName" -Type String -Value "SomeValue"
}

# Disable some feature
Function DisableSomeFeature {
    Write-Output "Disabling some feature..."
    Remove-ItemProperty -Path "HKLM:\Some\Registry\Key" -Name "SomeValueName" -ErrorAction SilentlyContinue
}
```


## Credits
Disassembler0's (now archived) Win10-Initial-Setup-Script repo:
https://github.com/Disassembler0/Win10-Initial-Setup-Script

Windows 10 Telemetry blocking hosts file was fetched from:
https://www.encrypt-the-planet.com/downloads/hosts
