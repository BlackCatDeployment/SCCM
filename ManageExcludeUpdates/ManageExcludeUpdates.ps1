<#
.Synopsis
    Exclude Software Updates located in a specific folder from deployments 
.DESCRIPTION
    Exclude Software Updates located in a specific folder from deployments 
.PARAMETER File
    Name of the XML configuration file
    MUST BE placed on the script root path
.OUTPUTS
   Logs are stored in $PSScriptRoot\Logs\<date>_ManageExcludeUpdates.log
.NOTES
    Version:         1.0
    Author:          Florian Valente
    Date:            2020/03/13
    Version History: 1.0 : 2020/03/13 - Florian Valente
.EXAMPLE
    SyncAD_SCCM.ps1 -File "settings.xml"
.COMPONENT
   This script must be run on a ConfigMgr Current Branch server on Windows Server 2012 R2 minimum.
   It wasn't tested on ConfigMgr 2012 R2 neither on Windows Server 2008 R2.
   It uses the ConfigurationManager PoSh module
.LINK
    https://bcdeployment.wordpress.com
#>
PARAM(
    [Parameter(Mandatory=$false, Position=0)]
    [ValidateNotNullOrEmpty()]
    [ValidateScript({
        If (Test-Path -Path "$PSScriptRoot\$_" -PathType Leaf) {
            # Check if path contains a xml file
            if (((Get-ItemProperty "$PSScriptRoot\$_").Extension) -ne ".xml") {
                throw "$_ must contains a xml file!"
            }
            Else { return $true }
        }
        Else {
            throw "$_ not found!"
        }
    })]
    [String] $File = "$PSScriptRoot\settings.xml"
)


# Import the ConfigurationManager.psd1 module
Import-Module "$($ENV:SMS_ADMIN_UI_PATH)\..\ConfigurationManager.psd1"

# Global variables
$script_parent     = Split-Path -Parent $MyInvocation.MyCommand.Definition
$LogPath           = "$script_parent\Logs"
$sitecode          = (Get-PSDrive -PSProvider CMSite).name
$script:output     = "$LogPath\$(Get-Date -Format "yyyyMMddHHmmss")_$(($MyInvocation.MyCommand.Name) -replace ".ps1", ".log")"
$script:objResult  = @{ Success=0; Warning=0; Error=0 }

If (-not (Test-Path $LogPath)) { New-Item $LogPath -ItemType Directory | Out-Null }

# Load Write-Log function
. "$PSScriptRoot\bin\Write-Log.ps1"

Write-Log " " start
Write-Log "Processing Update exclusion..."

# Load XML settings file
try {
    $xml = [xml](Get-Content "$PSScriptRoot\$File")

    $Folder         = $xml.settings.folder
    $CustomSeverity = $xml.settings.customseverity
}
catch {
    Write-Log "Cannot initialize environment! $($_.Exception.Message)" error
}


# Initialize location for managing ConfigMgr! MANDATORY before continue
$InitialLocation = Get-Location

Write-Log "Successfully connected to $sitecode Site"

try {
    Set-Location "$($sitecode):"

    $FolderPath = "$($sitecode):\SoftwareUpdate\$Folder"  
    If (-not (Test-Path $FolderPath)) {
        Write-Log "Cannot find folder $FolderPath! $($_.Exception.Message)" error
    }

    Write-Log "Parsing Software Updates in [$FolderPath]..."
    try {
        $SoftwareUpdates = Get-CMSoftwareUpdate -Fast | ? {$_.ObjectPath -eq "/$Folder"}
    }
    catch {
        Write-Log "Cannot get Software Updates list! $($_.Exception.Message)" error
    }

    If ($SoftwareUpdates.Count -eq 0) {
        Write-Log "No Software Update found"
    }
    Else {
        ForEach ($oSU in $SoftwareUpdates) {
            Write-Log "Managing SU [$($oSU.LocalizedDisplayName)]"
            If ($oSU.CustomSeverityName -eq $CustomSeverity) {
                Write-Log "Custom Severity already set to [$CustomSeverity]"
            }
            Else {
                $oSU | Set-CMSoftwareUpdate -CustomSeverity $CustomSeverity
                Write-Log "Custom Severity set to [$CustomSeverity]"
            }

            Write-Log "Cleaning Software Update Groups..."
            ForEach ($oSUG in (Get-CMSoftwareUpdateGroup)) {
                try {
                    $oSUG | Remove-CMSoftwareUpdateFromGroup -SoftwareUpdate $oSU -Force
                }
                catch {
                    Write-Log "Error during SUG [$($oSUG.LocalizedDisplayName)] clean! $($_.Exception.Message)"
                }
            }
            Write-Log "SUGs cleaned"
            Write-Log "Software Update excluded" success
        }
    }
}
catch {
    Write-Log "An error occurred during SU exclusion! $($_.Exception.Message)" error
}
finally {
    Set-Location $InitialLocation
    Write-Log "Process done!" success
    Write-Log " " stop
}
