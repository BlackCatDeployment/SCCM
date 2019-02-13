<#
.Synopsis
    Send an HTML report by mail of an ADR
.DESCRIPTION
    From an ADR Name, an HTML report is generated and sent by mail to show following information:
    - Approved updates on the ADR
    - Deployment schedules configured
.PARAMETER ADRName
    Name of the Automatic Deployment Rule to report
.OUTPUTS
   HTML report stored in $PSScriptRoot\<ADRName>-<date>.log
.NOTES
    Version:         1.1
    Author:          Florian Valente
    Date:            2019/02/13
    Version History: 1.0 : 2018/11/14 - Florian Valente
                     1.1 : 2019/02/13 - Florian Valente
.EXAMPLE
    ADRReport.ps1 -ADRName "ADR Patch Tuesday"
.COMPONENT
   This script must be run on a ConfigMgr Current Branch server on Windows Server 2012 R2 minimum.
   It wasn't tested on ConfigMgr 2012 R2 neither on Windows Server 2008 R2.
   It uses the ConfigurationManager PoSh module
.LINK
    https://bcdeployment.wordpress.com
#>
PARAM(
    [Parameter(Mandatory=$true, Position=0)][String] $ADRName
)

# Import the ConfigurationManager.psd1 module
Import-Module "$($ENV:SMS_ADMIN_UI_PATH)\..\ConfigurationManager.psd1"

# Global variables
$script_parent     = Split-Path -Parent $MyInvocation.MyCommand.Definition
$sitecode          = (Get-PSDrive -PSProvider CMSite).name
$Days              = 28
$strOutputFilePath = "$script_parent\$($ADRName -replace " ", '')-$((Get-Date).ToString("yyyyMM")).html"

$MailFrom          = "mailfrom@bcd.com" #Mail sender
$MailTo            = @("toto@bcd.com","titi@bcd.com") #Mail recipients
$MailCc            = @("") #Mail Cc
$MailBcc           = @("") #Mail Bcc
$MailSMTP          = "smtp.bcd.com" #SMTP server to use


If (Test-Path $strOutputFilePath) {
    # Report was already generated
    exit
}


# Initialize location for managing ConfigMgr! MANDATORY before continue
$InitialLocation = Get-Location
Set-Location "$($sitecode):"

$SUGName = (Get-CMSoftwareUpdateGroup -Name "$ADRName*" | Where-Object { $_.DateCreated -ge (Get-Date).AddDays(-$Days) }).LocalizedDisplayName
If ($SUGName -eq $null) {
    $report = "No ADR was created for this month."
}
Else {
    $oUpdates = (Get-CMSoftwareUpdate -UpdateGroupName $SUGName -Fast) | 
        Select-Object @{ N="Article ID"; E={"<a href=""$($_.LocalizedInformativeURL)"">"+$_.ArticleID+"</a>"} },
            @{ N="Update Name"; E={$_.LocalizedDisplayName} },
            @{ N="Severity"; E={$_.SeverityName} } | Sort-Object 'Update Name'

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
    $title = "$(Get-Date -Format "MMMM") Approved Software Updates Report"
    $body = "<h1><u><center>$title</center></u></h1>"
    $body += "<b>ADR used:</b> $ADRName</br>"
    $body += "<b>SUG created:</b> $($SUGName -join ", ")</br>"
    $body += "<b>Number of updates:</b> $($oUpdates.Count)</br></br>"
    $body += "<h2>Approved Updates</h2>"

    Add-Type -AssemblyName System.Web
    $body += [System.Web.HttpUtility]::HtmlDecode(($oUpdates | ConvertTo-Html -Title "Approved Updates"))
    $body += [System.Web.HttpUtility]::HtmlDecode(($oDeployments | ConvertTo-Html -Title "Deployment Schedules" -PreContent "<h2>Deployment Schedules</h2>"))

    $report = ConvertTo-Html -Body $body -Head $header -Title $title
    $report  | Set-Content $strOutputFilePath
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

Send-MailMessage @MailParams -BodyAsHtml
