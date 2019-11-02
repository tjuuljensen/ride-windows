##########
# Customizer for Disassembler0's Win10-Initial-Setup-Script
# Win 10 / Server 2016 / Server 2019 Initial Setup Script
# Author: Torsten Juul-Jensen
# Version: v1.0, 2019-11-02
# Source: https://github.com/tjuuljensen/win10-initial-customized
##########

##########
#
##########

#
Function aaa {

}




##########
#region Auxiliary Functions
##########

# Wait for keypress
Function WaitForKey {
	Write-Output "`nPress any key to continue..."
	[Console]::ReadKey($true) | Out-Null
}

# Restart computer
Function Restart {
	Write-Output "Restarting..."
	Restart-Computer
}

##########
#endregion Auxiliary Functions
##########



# Export functions
Export-ModuleMember -Function *
