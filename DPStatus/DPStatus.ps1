<#
.Synopsis
    Send DP on error status by email
.DESCRIPTION
    Check all DPs and send by email DPs on error
.PARAMETER Config
    Name of the XML configuration file
    MUST BE placed on the script root path
.OUTPUTS
   HTML report stored in $PSScriptRoot\Reports\DPStatus-<date>.log
.NOTES
    Version:         1.0
    Author:          Florian Valente
    Date:            2019/12/09
    Version History: 1.0 : 2019/12/09 - Florian Valente
.EXAMPLE
    DPStatus.ps1
.COMPONENT
   This script must be run on a ConfigMgr Current Branch server on Windows Server 2012 R2 minimum.
   It wasn't tested on ConfigMgr 2012 R2 neither on Windows Server 2008 R2.
   It uses the ConfigurationManager PoSh module
.LINK
    https://bcdeployment.wordpress.com
#>
PARAM (
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

# Global variables
$script_parent = Split-Path -Parent $MyInvocation.MyCommand.Definition
$ReportPath = "$script_parent\Reports"
If (-not (Test-Path $ReportPath)) { New-Item $ReportPath -ItemType Directory | Out-Null }
$strOutputFilePath = "$ReportPath\DPStatus-$((Get-Date).ToString("yyyyMMddHHmmss")).html"

# Load XML settings file
$xml = [xml](Get-Content "$PSScriptRoot\$Config")

$MailFrom          = $xml.settings.mail.from
$MailTo            = @(($xml.settings.mail.to -split ",").Trim())
$MailCc            = @(($xml.settings.mail.cc -split ",").Trim())
$MailBcc           = @(($xml.settings.mail.bcc -split ",").Trim())
$MailSMTP          = $xml.settings.mail.server

$title = "Distribution Points on error on $(Get-Date -Format "yyyy/MM/dd")"
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
$Sitecode = (Get-PSDrive -PSProvider CMSite).name
$InitialLocation = Get-Location

Set-Location "$($Sitecode):"

$oPkgs = @()
# Get unsuccessful distributions
$Query = "
Select PackageID,Name,MessageState,ObjectTypeID,MessageID,LastUpdateDate
from SMS_DistributionDPStatus
where MessageState<>1
order by LastUpdateDate Desc
"
 
# Get unsuccessful distributions
$oDPs = Get-WmiObject -Namespace "root\SMS\site_$SiteCode" -Query $Query
#$oDPs = Get-CMDistributionStatus | ? { $_.NumberErrors -gt 0 }

foreach ($oDist in $oDPs) {
    # Translate Package Type
    Switch ($oDist.ObjectTypeID) {
        "2"  { $Type = "Standard Package" }
        "14" { $Type = "OS Install Package" }
        "18" { $Type = "OS Image Package" }
        "19" { $Type = "Boot Image Package" }
        "21" { $Type = "Device Setting Package" }
        "23" { $Type = "Driver Package" }
        "24" { $Type = "Software Updates Package" }
        "31" { $Type = "Application Content Package" }
        Default { $Type = "Unknown" }
    }

    # Translate Distribution State
    Switch ($oDist.MessageState) {
        "2" { $Status = "In Progress" }
        "3" { $Status = "Error" }
        "4" { $Status = "Failed" }
        Default { $Status = "Unknown" }
    }
 
    # Translate Common MessageIDs
    Switch ($oDist.MessageID) {
        "2303" { $MSGID = "Content was successfully refreshed" }
        "2324" { $MSGID = "Failed to access or create the content share" }
        "2330" { $MSGID = "Content was distributed to distribution point" }
        "2384" { $MSGID = "Content hash has been successfully verified" }
        "2323" { $MSGID = "Failed to initialize NAL" }
        "2354" { $MSGID = "Failed to validate content status file" }
        "2357" { $MSGID = "Content transfer manager was instructed to send content to the distribution point" }
        "2360" { $MSGID = "Status message 2360 unknown" }
        "2370" { $MSGID = "Failed to install distribution point" }
        "2371" { $MSGID = "Waiting for prestaged content" }
        "2372" { $MSGID = "Waiting for content" }
        "2375" { $MSGID = "Created virtual directories on the defined share or volume on the distribution point succesfully" }
        "2380" { $MSGID = "Content evaluation has started" }
        "2381" { $MSGID = "An evaluation task is running. Content was added to the queue" }
        "2382" { $MSGID = "Content hash is invalid" }
        "2383" { $MSGID = "Failed to validate the package on the distribution point. The package may not be present or may be corrupt. Please redistribute it" }
        "2384" { $MSGID = "Package has been successfully verified on the distribution point" }
        "2388" { $MSGID = "Failed to retrieve the package list on the distribution point. Or the package list in content library doesn't match the one in WMI. Review smsdpmon.log for more information about this failure." }
        "2391" { $MSGID = "Failed to connect to remote distribution point" }
        "2397" { $MSGID = "Detail will be available after the server finishes processing the messages." }
        "2398" { $MSGID = "Content Status not found" }
        "2399" { $MSGID = "Successfully completed the installation or upgrade of the distribution point" }
        "8203" { $MSGID = "Failed to update package" }
        "8204" { $MSGID = "Content is being distributed to the distribution point" }
        "8211" { $MSGID = "Package Transfer Manager failed to update the package on the distribution point. Review PkgXferMgr.log for more information about this failure." }
        Default { $MSGID = "Unknown" }
    }
 
    # Get / Set Additional info
    $PKGID = $oDist.PackageID
    $LastUPDTime = [System.Management.ManagementDateTimeconverter]::ToDateTime($oDist.LastUpdateDate)
    $PKG = Get-WmiObject -Namespace "root\SMS\site_$SiteCode" -Query "Select * from SMS_PackageBaseclass where PackageID = '$PKGID'"
 
    # Add to a PS object
    $oParams = [ordered]@{
        'Package Name' = $PKG.Name
        PackageID = $oDist.PackageID
        'Package Type' = $Type
        'Distribution Point Name' = $oDist.Name
        'Distribution State' = $Status
        'Status Message' = $MSGID
        'Last Update Time' = $LastUPDTime
    }

    $oPkgs += New-Object psobject -Property $oParams
}

If ($oPkgs.Count -eq 0) {
    exit
}

# DP Status on error -> generate and send HTML report
Add-Type -AssemblyName System.Web
$body += [System.Web.HttpUtility]::HtmlDecode(($oPkgs | ConvertTo-Html -Title "DP Status"))
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
