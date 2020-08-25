<#
.Synopsis
   Uninstall SCCM Client from a list of devices
.INPUTS
   Uninstall SCCM Client from a list of devices. List file set in parameter
   As some access and WinRM issues should appear by using a PSSession, psexec is prefered.
.OUTPUTS
    Deploy.log
        Summary of the execution
    DeployStates_<yyyyMMddHHmmss>.csv
        CSV file summarize uninstallation status of the list of devices
        Exit codes:
            0  : Success
            1  : SCCM Client not installed
            2  : Cannot run the uninstallation program
            6  : SCCM Client install failed! Check the log on the computer
            7  : SCCM Client installed successfully but the computer needs a restart
            9  : SCCM Client install failed! Prerequisite evaluation failure
            10 : SCCM Client install failed! Setup manifest hash validation failure
            53 : Device unreachable on SMB port
            65 : Credentials used cannot access to the device
    CCM_uninstall.log
        Under C:\Windows\Temp of each listed device
        Summary of the uninstallation script
.PARAMETER File
    Path of the text file. Must be located on the script folder
.NOTES
    Author  : Florian VALENTE
    Version : 1.0
    Date    : 2020/08/21
    Version History:
        1.0 : 2020/08/21 - Florian Valente
            - Initial version
.EXAMPLE
   .\Deploy.ps1
.EXAMPLE
   .\Deploy.ps1 -File list.txt
.LINK
    https://bcdeployment.wordpress.com
#>
PARAM (
    [Parameter(Mandatory=$true,ValueFromPipeline=$true)][ValidateScript({Test-Path "$_" })][String]$File
)

# Require PowerShell v4 minimum
#Requires -version 4

# Require to be run as administrator
#Requires -RunAsAdministrator

# define Error handling
# note: do not change these values
$global:ErrorActionPreference = "Stop"
if($verbose){ $global:VerbosePreference = "Continue" }

$remotePath = "C$\Windows\Temp"
$PSdriveName = "sccmrun"
$UninstScript = "Uninstall.ps1"
$LogFile = "$PSScriptRoot\..\DeployStates_$(Get-Date -Format "yyyyMMddHHmmss").csv"
$LogLine = "{0},{1},{2}"


Function Write-SummaryLog {
    PARAM(
        [String] $Status,
        [Int] $Code,
        [String] $Computer
    )

    If (!(Test-Path $LogFile)) {
        ($LogLine -f "Computer", "Status", "ErrorCode") | Out-File $LogFile -Encoding utf8
    }
    
    ($LogLine -f $Computer, $Status, $Code) | Out-File $LogFile -Append -Encoding utf8
}


################
# Main section #
################
Start-Transcript -Path "$PSScriptRoot\..\Deploy.log" -Append | Out-Null

$arrList = Get-Content "$File"
$AdminCreds = Get-Credential -Message "Use account with admin rights on devices"

ForEach ($item in $arrList) {
    If ([string]::IsNullOrEmpty($item)) { Continue }

    Write-Host "Uninstalling SCCM Client on $item..."
    If (Test-NetConnection -ComputerName $item -CommonTCPPort SMB -InformationLevel Quiet) {
        Write-Progress -Activity "test" -Completed #Used to remove the progress bar persisting after the Test-NetConnection...
        try {
            try {
                Remove-PSDrive -Name $PSdriveName -ErrorAction SilentlyContinue
                New-PSDrive -Name $PSdriveName -PSProvider FileSystem -Scope Script -Root "\\$item\$remotePath" -Credential $AdminCreds | Out-Null
                Write-Host "$item reachable"
                Copy-Item -Path "$PSScriptRoot\$UninstScript" -Destination "$($PSdriveName):" -Force | Out-Null
            }
            catch {
                Write-SummaryLog -Status "FAIL" -Code 65 -Computer $item
                Write-Error $_.Exception.Message
            }

            $objProcess = Start-Process -FilePath "$PSScriptRoot\PsExec.exe" -ArgumentList "\\$item -s -accepteula -nobanner cmd /c ""echo . | powershell.exe -ExecutionPolicy Bypass -NoProfile -NoLogo -File $($remotePath -replace "\$",":")\$UninstScript""" -PassThru -Wait -NoNewWindow

            If ($objProcess.ExitCode -eq 0) {
                Write-SummaryLog -Status "GOOD" -Code $objProcess.ExitCode -Computer $item
                Write-Host "Uninstall succeed on $item!"
            }
            ElseIf ($objProcess.ExitCode -eq 1) {
                Write-SummaryLog -Status "GOOD" -Code $objProcess.ExitCode -Computer $item
                Write-Host "SCCM Client not installed on $item!"
            }
            ElseIf ($objProcess.ExitCode -eq 2) {
                Write-SummaryLog -Status "FAIL" -Code $objProcess.ExitCode -Computer $item
                Write-Error "SCCM Client cannot be uninstalled on $item! Check log locally"
            }
            ElseIf ($objProcess.ExitCode -eq 7) {
                Write-SummaryLog -Status "WARNING" -Code $objProcess.ExitCode -Computer $item
                Write-Host "Uninstall succeed BUT NEEDS A RESTART on $item!"
            }
            Else {
                Write-SummaryLog -Status "FAIL" -Code $objProcess.ExitCode -Computer $item
                Write-Error "Uninstall failed with Exit Code $($objProcess.ExitCode)! Check log locally"
            }
            Write-Host "YOU MUST PERFORM A RESTART OF $item BEFORE INSTALLING THE SCCM CLIENT AGAIN!" -BackgroundColor Red -ForegroundColor White
        }
        catch {
            Write-Warning "Error occurred for Machine $item. $($_.Exception.Message)"
        }

        Start-Sleep 2
        Remove-Item "$($PSdriveName):\$UninstScript" -Force -ErrorAction SilentlyContinue | Out-Null
        Remove-PSDrive -Name $PSdriveName -Force -ErrorAction SilentlyContinue
    }
    Else {
        Write-SummaryLog -Status "FAIL" -Code 53 -Computer $item
    }
}

Stop-Transcript | Out-Null