<#
.Synopsis
    Remove computers and send an HTML report by mail from a list file
.DESCRIPTION
    From a list file, an HTML report is generated and sent by mail to show removed computers
.PARAMETER File
    Name of the text file containing a list of computers to remove
.PARAMETER Config
    Name of the XML configuration file
    MUST BE placed on the script root path
.OUTPUTS
   HTML report stored in $PSScriptRoot\Reports\RemovedComputer-<date>.log
.NOTES
    Version:         1.0
    Author:          Florian Valente
    Date:            2019/06/25
    Version History: 1.0 : 2019/06/25 - Florian Valente
.EXAMPLE
    RemoveComputer.ps1 -File "list.txt"
.COMPONENT
   This script must be run on a ConfigMgr Current Branch server on Windows Server 2012 R2 minimum.
   It wasn't tested on ConfigMgr 2012 R2 neither on Windows Server 2008 R2.
   It uses the ConfigurationManager PoSh module
.LINK
    https://bcdeployment.wordpress.com
#>
PARAM (
    [Parameter(Mandatory=$true)][String] $File,
    [Parameter(Mandatory=$false)][ValidateNotNullOrEmpty()]
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
    [String] $Config = "$PSScriptRoot\settings.xml"
)

If (($File.Substring(0,2) -ne "\\") -and ($File.Substring(1,1) -ne ":")) {
    $List = "$PSScriptRoot\$File"
}
Else {
    $List = $File
}

# Global variables
$script_parent = Split-Path -Parent $MyInvocation.MyCommand.Definition
$ReportPath = "$script_parent\Reports"
If (-not (Test-Path $ReportPath)) { New-Item $ReportPath -ItemType Directory | Out-Null }
$strOutputFilePath = "$ReportPath\RemoveComputer-$((Get-Date).ToString("yyyyMMddHHmmss")).html"

$iSCCMLastSyncDay = 7

# Load XML settings file
$xml = [xml](Get-Content "$PSScriptRoot\$Config")

$MailFrom          = $xml.settings.mail.from
$MailTo            = @(($xml.settings.mail.to -split ",").Trim())
$MailCc            = @(($xml.settings.mail.cc -split ",").Trim())
$MailBcc           = @(($xml.settings.mail.bcc -split ",").Trim())
$MailSMTP          = $xml.settings.mail.server

$title = "Removed computers on $(Get-Date -Format "yyyy/MM/dd")"
# Create header of the HTML file
$header = "<style>"
$header += "BODY{background-color:WhiteSmoke;}"
$header += "TABLE{border-width:1px; width:100%; border-style:solid; border-color:black; border-collapse:collapse;}"
$header += "TH{border-width:1px; padding:5px; border-style:solid; border-color:black; background-color:IndianRed;}"
$header += "TD{border-width:1px; padding:5px; border-style:solid; border-color:black; background-color:LightCyan;}"
$header += "</style>"

# Create body of the HTML file
$body = "<h1><u><center>$title</center></u></h1>"

# Import the ConfigurationManager.psd1 module
Import-Module "$($ENV:SMS_ADMIN_UI_PATH)\..\ConfigurationManager.psd1"
$Sitecode = (Get-PSDRive -PSProvider CMSite).name
$InitialLocation = Get-Location

#filesystem:: used to detect UNC path with Test-Path cmdlet
If (!(Test-Path $("filesystem::$List"))) {
    Write-Error "$List file was not found!"
}

$oList = (Get-Content $List) | ? {-not [String]::IsNullOrWhiteSpace($_)} # Remove blank lines
$body += "<b>File found:</b> $List</br>"
$body += "<b>Computer found in file:</b> $($oList.Count)</br>"

Set-Location "$($Sitecode):"

$oRemoved = @()

Write-Host "Removing $($oList.Count) computers from SCCM..."
ForEach ($item in $oList) {
    $oParams = [ordered]@{
        Name = $item
        OS = "N/A"
        Domain = "N/A"
        LastClientConnection = "N/A"
        LastADLogon = "N/A"
        Approved = "N/A"
        RemovalStatus = "N/A"
    }

    $oDevice = Get-CMDevice -Name $item
    If ($oDevice -ne $null) {
        ForEach ($oItem in $oDevice) {
            $oParams.Name = $oItem.Name
            $oParams.OS = $oItem.DeviceOS
            $oParams.Domain = $oItem.Domain
            $oParams.LastClientConnection = $oItem.LastActiveTime
            $oParams.LastADLogon = $oItem.ADLastLogonTime
            $oParams.Approved = [System.Convert]::ToBoolean($oItem.IsApproved)

            try {
                If ($oItem.LastActiveTime -gt (Get-Date).AddDays(-$($iSCCMLastSyncDay))) {
                    $oParams.RemovalStatus = "Not removed due to last active state less than $iSCCMLastSyncDay days"
                    Write-Warning "Computer $($oItem.Name) was not removed"
                }
                Else {
                    $oItem | Remove-CMDevice -Force
                    $oParams.RemovalStatus = "Success"
                    Write-Host "Computer $($oItem.Name) removed"
                }
            }
            catch {
                $oParams.RemovalStatus = $_.Exception.Message
                Write-Warning "Error occurred for removing computer $($oItem.Name)! $($_.Exception.Message)"
            }
        }
    }
    Else {
        Write-Warning "Computer $item was not found"
    }

    $oRemoved += New-Object PSObject -Property $oParams
}

If (($oRemoved.Count -eq 0) -or (($oRemoved.RemovalStatus -eq "N/A").Count -eq $oList.Count)) {
    exit
}

# Computer to remove found -> generate and send HTML report
Add-Type -AssemblyName System.Web
$body += [System.Web.HttpUtility]::HtmlDecode(($oRemoved | ConvertTo-Html -Title "Approved Computers"))
$report = ConvertTo-Html -Body $body -Head $header -Title $title
   
try {
    $report | Set-Content $strOutputFilePath
    Write-Host "Report generated successfully on $strOutputFilePath"
}
catch {
    Write-Warning "Report was not generated! $($_.Exception.Message)"
}

# Reset the location to the previous state
Set-Location $InitialLocation.Path


# Send mail
$MailParams = @{
    From = $MailFrom
    To = $MailTo
    Body = $report | Out-String
    SmtpServer = $MailSMTP
    Subject = "[SCCM] $title"
}

If (![String]::IsNullOrEmpty($MailCc)) {
    $MailParams += @{ Cc = $MailCc }
}
If (![String]::IsNullOrEmpty($MailBcc)) {
    $MailParams += @{ Bcc = $MailBcc }
}

Write-Host "Sending report by email..."
try {
    Send-MailMessage @MailParams -BodyAsHtml
    Write-Host "Email was sent"
}
catch {
    Write-Warning "Email was not sent! $($_.Exception.Message)"
}
