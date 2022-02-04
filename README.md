# bootstrap-windows

&nbsp;

## Description

This repo is a PowerShell script for automation of routine tasks done after a fresh installation of Windows 10/11 and Windows Server 2016 / 2019. The repo does not hold a complete set of all existing Windows tweaks, nor is it a complete way of creating the fully hardened/locked down machine.

The functions of the script are focused on minimizing windows telemetry traffic and on the installation and configuration of a lot of standard tools for the typical technical user.


&nbsp;

## Installation
If you just want to run the script with the default preset, download and unpack the [latest release](https://github.com/tjuuljensen/bootstrap-windows) and then simply double-click on the *Default.cmd* file and confirm *User Account Control* prompt. Make sure your account is a member of *Administrators* group as the script attempts to run with elevated privileges.

The script supports command line options and parameters which can help you customize the tweak selection or even add your own custom tweaks, however these features require some basic knowledge of command line usage and PowerShell scripting. Refer to [Advanced usage](#advanced-usage) section for more details.


&nbsp;

## History


When Windows 10 was released, a lot of discussions emerged about the telemetry and dial-back functions that Microsoft implemented and which had very few configuration options for the normal user. Some people required a machine with a low footprint for privacy reasons, some just needed a machine that were more silent when listening on the network.

For years I maintained a PowerShell lockdown script to handle my Windows installations, but at some point
I realized that it was a hard game catching up with all the new changes every time a new Windows version was released. A part of the "catch-up game" was to search the internet (github rules!) for clever guys who had been collecting information and putting things into scripts. Most people did not use PowerShell to change the options configuration, so I often had to translate command line/GUI guides into PowerShell.

The purpose of my scripting was easy:
- maintain a PowerShell script of Windows 10 privacy/hardening features
- the script should take away 80-90% percent of "initial configuration" of a new Windows box (which meant I added browser, editors and VMware Workstation installation as part of the actions)
- cut installation time down from days/hours to minutes
- should be easy to share so other people had access to my work
- the script should be available for use on physical machines as well as VM's
- have it easily available ready for use everywhere/anytime (easy one - put it on github)

Even though the script worked and saved me hours of installation time, the ugly truth about my scripting was also:
- I was not catching up with recent Windows changes as often as I would
- It was not *easily* available for others (it was one long list of functions)

And then some day I visited Disassembler0's Win10-Initial-Setup-Script on github (https://github.com/Disassembler0/Win10-Initial-Setup-Script).
Wow. I immediately discarded a lot of my code and used the Disassembler0 repo for years next to a slimmer version of my own - now adjusted to fit the code structure of the Disassembler0 repo.

Disassembler0 archived his repo in 2021 (Thanks for all the fish!), so I adopted all his code in this repo - and I am back to self maintaining it.

And by the way: I am a Linux user and I created this script to make sure I remembered a lot of steps when installing a Windows machine.
I have a Linux repo and use the same script architecture in my Fedora Linux configuration: https://github.com/tjuuljensen/bootstrap-fedora.

## Credits
Disassembler0's (now archived) Win10-Initial-Setup-Script repo:
https://github.com/Disassembler0/Win10-Initial-Setup-Script

Telemetry blocking hosts file is fetched from:
https://www.encrypt-the-planet.com/downloads/hosts
