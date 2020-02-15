# win10-initial-customized
When Windows 10 was released, it became clear to everyone that telemetry and dial-back functions was
something that we all needed to care about if we care about our privacy.

For years I maintained a PowerShell lockdown script to handle my Windows installations, but at some point
I realized that it was a hard game catching up with all the new changes every time a new Windows version was released.
A part of the "catch-up game" was to search the internet (and github not the least) for clever guys who had been
collecting information and putting things into scripts. One of the problems here was obviously that not many people
used PowerShell solely to maintain the configuration, so I often had to translate bash/GUI guides into PowerShell.

The purpose of my scripting was easy:
- maintain a PowerShell script of Windows 10 privacy/hardening features
- the script should take away 80-90% percent of "initial configuration" of a new Windows box (which meant I added browser, editor and VMware Workstation installation as part of the actions)
- cut installation time down from days/hours to minutes
- should be easy to share so other people had access to my work
- the script should be available for use on physical machines as well as VM's
- have it easily available ready for use everywhere/anytime (easy one - put it on github)

Even though the script worked and saved me hours of installation time, the ugly truth about my scripting was also:
- I was not catching up with recent Windows changes as often as I would
- It was not *easily* available for others (it was one long list of functions)

And then some day I visited Disassembler0's Win10-Initial-Setup-Script on github (https://github.com/Disassembler0/Win10-Initial-Setup-Script).
Wow. So Disassembler0's repo in short:
- It was actively maintained
- It had most (~80%) of my privacy/hardening features implemented
- It had a cool configuration mechanism which would be easy to adopt for others

So I rewrote my script to fit his loader mechanism and I ended up with this repo. It has what Disassembler0/Win10-Initial-Setup-Script has not (privacy/hardening). If Disassembler0 implements the features, I will remove it from my repo.
I will add other resources that matches the purpose and which is easily configurable (encrypt-the-planet's hosts file is an example hereof)
I will also maintain automated browser privacy/hardening settings as part of my repo.

In fact, I use the same logic behind my Fedora Linux configuration. Please see my repo for inspiration: https://github.com/tjuuljensen/bootstrap-fedora

## Credits

Disassembler0's Win10-Initial-Setup-Script repo:
https://github.com/Disassembler0/Win10-Initial-Setup-Script

Telemetry blocking hosts file is fetched from:
https://www.encrypt-the-planet.com/downloads/hosts
