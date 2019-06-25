<#
.Synopsis
    Approve computers and send an HTML report by mail
.DESCRIPTION
    From specific collection(s), an HTML report is generated and sent by mail to show approved computers
.PARAMETER File
    Name of the XML configuration file
    MUST BE placed on the script root path
.OUTPUTS
   HTML report stored in $PSScriptRoot\Reports\ApprovedComputer-<date>.log
.NOTES
    Version:         1.0
    Author:          Florian Valente
    Date:            2019/06/24
    Version History: 1.0 : 2019/06/24 - Florian Valente
.EXAMPLE
    ApproveComputer.ps1 -File "settings.xml"
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
$ReportPath        = "$script_parent\Reports"
$sitecode          = (Get-PSDrive -PSProvider CMSite).name

If (-not (Test-Path $ReportPath)) { New-Item $ReportPath -ItemType Directory | Out-Null }

# Load XML settings file
$xml = [xml](Get-Content "$PSScriptRoot\$File")

$MailFrom          = $xml.settings.mail.from
$MailTo            = @(($xml.settings.mail.to -split ",").Trim())
$MailCc            = @(($xml.settings.mail.cc -split ",").Trim())
$MailBcc           = @(($xml.settings.mail.bcc -split ",").Trim())
$MailSMTP          = $xml.settings.mail.server


# Initialize location for managing ConfigMgr! MANDATORY before continue
$InitialLocation = Get-Location

Write-Host "Successfully connected to $sitecode Site"

Write-Host "Generating report for Approved computers..."
$strOutputFilePath = "$ReportPath\ApprovedComputer-$((Get-Date).ToString("yyyyMMddHHmmss")).html"
$title = "Approved computers on $(Get-Date -Format "yyyy/MM/dd")"
# Create header of the HTML file
$header = "<style>"
$header += "BODY{background-color:WhiteSmoke;}"
$header += "TABLE{border-width:1px; width:100%; border-style:solid; border-color:black; border-collapse:collapse;}"
$header += "TH{border-width:1px; padding:5px; border-style:solid; border-color:black; background-color:IndianRed;}"
$header += "TD{border-width:1px; padding:5px; border-style:solid; border-color:black; background-color:LightCyan;}"
$header += "</style>"

# Create body of the HTML file
$body = "<h1><u><center>$title</center></u></h1>"

Set-Location "$($sitecode):"

$oApproved = @()

ForEach ($oCol in $xml.settings.collections.name) {
    try {
        # Get members not approved (IsApproved) and questionable (ClientCheckPass)
        $oMembers = Get-CMCollectionMember -CollectionName $oCol | ? { ($_.IsApproved -eq 0) -and ($_.ClientCheckPass -eq 3) } | Sort-Object
        If ($oMembers.Count -ne 0) {
            $body += "<b>Computers found:</b> $($oMembers.Count)</br>"
            ForEach ($item in $oMembers) {
                $oParams = [ordered]@{
                    Name = $item.Name
                    LastActiveTime = $item.LastActiveTime
                    Collection = $oCol
                }

                try {
                    Approve-CMDevice -DeviceName $item.Name
                    $oParams += @{
                        Approved = $true
                    }
                }
                catch {
                    $oParams += @{
                        Approved = $false
                    }
                }

                $oApproved += New-Object PSObject -Property $oParams
            }
        }
        Else {
            $oApproved += New-Object PSObject -Property ([ordered]@{
                Name = "N/A"
                LastActiveTime = "N/A"
                Collection = $oCol
                Approved = "N/A"
            })
        }
    }
    catch {
        Write-Warning "Collection $oCol not exists!"
        Continue
    }
}

If (($oApproved.Count -eq 0) -or ($oApproved[0].Approved.ToString() -eq "N/A")) {
    exit
}

# Computer to approve found -> generate and send HTML report
Add-Type -AssemblyName System.Web
$body += [System.Web.HttpUtility]::HtmlDecode(($oApproved | ConvertTo-Html -Title "Approved Computers"))
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
