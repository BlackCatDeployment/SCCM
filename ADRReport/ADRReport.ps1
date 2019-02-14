<#
.Synopsis
    Send an HTML report by mail of an ADR
.DESCRIPTION
    From an ADR Name, an HTML report is generated and sent by mail to show following information:
    - Approved updates on the ADR
    - Deployment schedules configured
.PARAMETER File
    Name of the XML configuration file
    MUST BE placed on the script root path
.OUTPUTS
   HTML report stored in $PSScriptRoot\<ADRName>-<date>.log
.NOTES
    Version:         2.0
    Author:          Florian Valente
    Date:            2019/02/14
    Version History: 1.0 : 2018/11/14 - Florian Valente
                     1.1 : 2019/02/13 - Florian Valente
                     2.0 : 2019/02/14 - Florian Valente
.EXAMPLE
    ADRReport.ps1 -File "settings.xml"
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
$Days              = 28

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
Set-Location "$($sitecode):"

Write-Host "Successfully connected to $sitecode Site"

ForEach ($oADR in $xml.settings.adrlist.adr) {
    $ADRTitle = $oADR.title
    $ADRName = $oADR.name
    Write-Host "Generating report for ADR ""$ADRName""..."

    $strOutputFilePath = "$script_parent\Reports\$($ADRName -replace " ", '')-$((Get-Date).ToString("yyyyMM")).html"
    If (Test-Path $strOutputFilePath) {
        # Report was already generated
        Write-Host "Report was already generated. Nothing to do"
        continue
    }

    $SUGName = (Get-CMSoftwareUpdateGroup -Name "$ADRName*" | Where-Object { $_.DateCreated -ge (Get-Date).AddDays(-$Days) }).LocalizedDisplayName
    If ($SUGName -eq $null) {
        Write-Host "No ADR was created for this month."
        $report = "No ADR was created for this month."
    }
    Else {
        Write-Host "ADR found"
        $oUpdates = (Get-CMSoftwareUpdate -UpdateGroupName $SUGName -Fast) | 
            Select-Object @{ N="Article ID"; E={"<a href=""$($_.LocalizedInformativeURL)"">"+$_.ArticleID+"</a>"} },
                @{ N="Update Name"; E={$_.LocalizedDisplayName} },
                @{ N="Severity"; E={$_.SeverityName} } | Sort-Object 'Update Name'
        Write-Host "$($oUpdates.Count) updates found"

        $oDeployments = Get-CMDeployment | ? {$_.SoftwareName -eq $SUGName} |
            Select-Object @{ N="Wave Name"; E={$_.CollectionName} },
                #@{ N="Available Time"; E={(Get-Date $_.DeploymentTime -Format "yyyy/MM/dd")} },
                @{ N="Deployment Date"; E={(Get-Date $_.EnforcementDeadline -Format "yyyy/MM/dd")} },
                @{ N="Systems Targeted"; E={$_.NumberTargeted} } | Sort-Object 'Deployment Date'

        # Create header of the HTML file
        $header = "<style>"
        $header += "BODY{background-color:WhiteSmoke;}"
        $header += "TABLE{border-width:1px; width:100%; border-style:solid; border-color:black; border-collapse:collapse;}"
        $header += "TH{border-width:1px; padding:5px; border-style:solid; border-color:black; background-color:IndianRed;}"
        $header += "TD{border-width:1px; padding:5px; border-style:solid; border-color:black; background-color:LightCyan;}"
        $header += "</style>"

        # Create body of the HTML file
        $title = "$(Get-Date -Format "MMMM") $ADRTitle"
        $body = "<h1><u><center>$title</center></u></h1>"
        $body += "<b>ADR used:</b> $ADRName</br>"
        $body += "<b>SUG created:</b> $($SUGName -join ", ")</br>"
        $body += "<b>Number of updates:</b> $($oUpdates.Count)</br></br>"
        $body += "<h2>Approved Updates</h2>"

        Add-Type -AssemblyName System.Web
        $body += [System.Web.HttpUtility]::HtmlDecode(($oUpdates | ConvertTo-Html -Title "Approved Updates"))
        $body += [System.Web.HttpUtility]::HtmlDecode(($oDeployments | ConvertTo-Html -Title "Deployment Schedules" -PreContent "<h2>Deployment Schedules</h2>"))

        $report = ConvertTo-Html -Body $body -Head $header -Title $title
        try {
            $report | Set-Content $strOutputFilePath
            Write-Host "Report generated successfully on $strOutputFilePath"
        }
        catch {
            Write-Warning "Report was not generated! $($_.Exception.Message)"
        }
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
}
