<#
.Synopsis
   Uninstall SCCM Client
.INPUTS
   Uninstall SCCM Client
   Perform ccmsetup /uninstall and files and registry keys cleanup to be sure SCCM is correctly uninstalled
.OUTPUTS
    CCM_uninstall.log
        Under C:\Windows\Temp of each listed device
        Summary of the uninstallation script
    Exit Codes:
        0  : Success
        1  : SCCM Client not installed
        2  : Cannot run the uninstallation program
        6  : SCCM Client install failed! Check the log on the computer
        7  : SCCM Client installed successfully but the computer needs a restart
        9  : SCCM Client install failed! Prerequisite evaluation failure
        10 : SCCM Client install failed! Setup manifest hash validation failure
.NOTES
    Author  : Florian VALENTE
    Version : 1.0
    Date    : 2020/08/21
    Version History:
        1.0 : 2020/08/21 - Florian Valente
            - Initial version
.EXAMPLE
   .\Uninstall.ps1
.LINK
    https://bcdeployment.wordpress.com
#>

# define Error handling
# note: do not change these values
$global:ErrorActionPreference = "Stop"
if($verbose){ $global:VerbosePreference = "Continue" }

$CCMExeFile = "$env:SystemRoot\ccmsetup\ccmsetup.exe"
$CCMLogFile = "$env:SystemRoot\ccmsetup\logs\ccmsetup.log"
$Log = "$PSScriptRoot\CCM_uninstall.log"

Write-Host "Uninstalling SCCM Client..." | Out-File $Log
If (Test-Path $CCMExeFile) {
    try {
        $o = Start-Process -FilePath $CCMExeFile -ArgumentList "/uninstall" -Wait -PassThru
    }
    catch {
        Write-Host "Cannot run the uninstallation program! $($_.Exception.Message)" | Out-File $Log -Append
        exit 2
    }
}
Else {
    Write-Host "SCCM Client not found" | Out-File $Log -Append
    exit 1
}
Start-Sleep 30

Write-Host "Checking log on: $CCMLogFile" | Out-File $Log -Append
$Result = @(Select-String -Path $CCMLogFile -Pattern "CcmSetup.*?with.*?code.*?")[-1] #Get the last installation status
$ResultCode = ($Result -split "code |]LOG")[1]
Switch ($ResultCode) {
    "0" { Write-Host "UNINSTALL RESULT - Success" | Out-File $Log -Append }
    "6" { Write-Warning "UNINSTALL RESULT - Error" | Out-File $Log -Append }
    "7" { Write-Warning "UNINSTALL RESULT - Reboot required" | Out-File $Log -Append }
    "8" { Write-Warning "UNINSTALL RESULT - Setup already running" | Out-File $Log -Append }
    "9" { Write-Warning "UNINSTALL RESULT - Prerequisite evaluation failure" | Out-File $Log -Append }
    "10" { Write-Warning "UNINSTALL RESULT - Setup manifest hash validation failure" | Out-File $Log -Append }
    Default { Write-Warning "UNINSTALL RESULT - Error" | Out-File $Log -Append }
}

If (($ResultCode -eq 0 )-or ($Result -eq 7)) {
    Write-Host "Cleaning the system..." | Out-File $Log -Append
    # Stop the Service "SMS Agent Host" which is a Process "CcmExec.exe"
    Get-Service -Name CcmExec -ErrorAction SilentlyContinue | Stop-Service -Force

    # Stop the Service "ccmsetup" which is also a Process "ccmsetup.exe" if it wasn't stopped in the services after uninstall
    Get-Service -Name ccmsetup -ErrorAction SilentlyContinue | Stop-Service -Force

    # Delete the folder of the SCCM Client installation: "C:\Windows\CCM"
    Remove-Item -Path "$($Env:WinDir)\CCM" -Force -Recurse -Confirm:$false -ErrorAction SilentlyContinue

    # Delete the folder of the SCCM Client Cache of all the packages and Applications that were downloaded and installed on the Computer: "C:\Windows\ccmcache"
    Remove-Item -Path "$($Env:WinDir)\CCMSetup" -Force -Recurse -Confirm:$false -ErrorAction SilentlyContinue

    # Delete the folder of the SCCM Client Setup files that were used to install the client: "C:\Windows\ccmsetup"
    Remove-Item -Path "$($Env:WinDir)\CCMCache" -Force -Recurse -Confirm:$false -ErrorAction SilentlyContinue

    # Delete the file with the certificate GUID and SMS GUID that current Client was registered with
    Remove-Item -Path "$($Env:WinDir)\smscfg.ini" -Force -Confirm:$false -ErrorAction SilentlyContinue

    # Delete the certificate itself
    Remove-Item -Path 'HKLM:\Software\Microsoft\SystemCertificates\SMS\Certificates\*' -Force -Confirm:$false -ErrorAction SilentlyContinue

    # Remove all the registry keys associated with the SCCM Client that might not be removed by ccmsetup.exe
    Remove-Item -Path 'HKLM:\SOFTWARE\Microsoft\CCM' -Force -Recurse -ErrorAction SilentlyContinue
    Remove-Item -Path 'HKLM:\SOFTWARE\Wow6432Node\Microsoft\CCM' -Force -Recurse -Confirm:$false -ErrorAction SilentlyContinue
    Remove-Item -Path 'HKLM:\SOFTWARE\Microsoft\SMS' -Force -Recurse -Confirm:$false -ErrorAction SilentlyContinue
    Remove-Item -Path 'HKLM:\SOFTWARE\Wow6432Node\Microsoft\SMS' -Force -Recurse -Confirm:$false -ErrorAction SilentlyContinue
    Remove-Item -Path 'HKLM:\Software\Microsoft\CCMSetup' -Force -Recurse -Confirm:$false -ErrorAction SilentlyContinue
    Remove-Item -Path 'HKLM:\Software\Wow6432Node\Microsoft\CCMSetup' -Force -Confirm:$false -Recurse -ErrorAction SilentlyContinue

    Write-Host "System cleaned" | Out-File $Log -Append
}

Exit $ResultCode

