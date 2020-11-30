<#
.Synopsis
    Send an HTML report by mail of Compliance Collections
.DESCRIPTION
    From a collection folder, an HTML report is generated and sent by mail to show following information:
    - Collection members of each Compliance Collections to report
.PARAMETER File
    Name of the XML configuration file
    MUST BE placed on the script root path
.OUTPUTS
   HTML report stored in $PSScriptRoot\Reports\<date>-<ComplianceReport>.html
.NOTES
    Version:         1.0
    Author:          Florian Valente
    Date:            2020/03/12
    Version History: 1.0 : 2020/03/12 - Florian Valente
.EXAMPLE
    ComplianceReport.ps1 -File "settings.xml"
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
$strOutputFilePath = "$ReportPath\$(Get-Date -Format "yyyyMMddHHmmss")_$(($MyInvocation.MyCommand.Name) -replace ".ps1", ".html")"

If (-not (Test-Path $ReportPath)) { New-Item $ReportPath -ItemType Directory | Out-Null }

# Load XML settings file
$xml = [xml](Get-Content "$PSScriptRoot\$File")

$CollectionFolder  = $xml.settings.report.collectionfolder
$ReportTitle       = $xml.settings.report.title
$MailFrom          = $xml.settings.mail.from
$MailTo            = @(($xml.settings.mail.to -split ",").Trim())
$MailCc            = @(($xml.settings.mail.cc -split ",").Trim())
$MailBcc           = @(($xml.settings.mail.bcc -split ",").Trim())
$MailSMTP          = $xml.settings.mail.server


# Initialize location for managing ConfigMgr! MANDATORY before continue
$InitialLocation = Get-Location

Write-Host "Successfully connected to $sitecode Site"

Set-Location "$($sitecode):"

try {
    $FolderID = (Get-Item "$($sitecode):\DeviceCollection\$CollectionFolder").ContainerNodeID
    Write-Host "Collection folder [$CollectionFolder] was found"
}
catch {
    $report = "Collection folder [$CollectionFolder] was not found"
}

try {
    $Collections = (get-wmiobject -Namespace root\sms\site_$siteCode -class SMS_ObjectContainerItem -filter "ContainerNodeID = '$FolderID'" | % { Get-CMCollection -Id $_.InstanceKey }) | Sort-Object
    Write-Host "$($Collections.Count) Collections found in the Collection Folder"
}
catch {
    $report = "No collection found in folder $CollectionFolder"
}

# Create header of the HTML file
$header = "<style>"
$header += "BODY{background-color:WhiteSmoke;}"
$header += "TABLE{border-width:1px; width:100%; border-style:solid; border-color:black; border-collapse:collapse;}"
$header += "TH{border-width:1px; padding:5px; border-style:solid; border-color:black; background-color:IndianRed;}"
$header += "TD{border-width:1px; padding:5px; border-style:solid; border-color:black; background-color:LightCyan;}"
$header += "</style>"

# Create body of the HTML file
$body = "<h1><u><center>$ReportTitle on $(Get-Date -Format "MMMM dd, yyyy")</center></u></h1>"
$body += "<b>Collection Folder:</b> $CollectionFolder</br>"
Add-Type -AssemblyName System.Web

ForEach ($oCol in $Collections) {
    $colName = $oCol.Name
    $colDesc = $oCol.Comment
    $colMember = $oCol.MemberCount

    If ([String]::IsNullOrEmpty($colDesc)) {
        $colDesc = "Members of Compliance Collection [$($colName)]:"
    }
    Else {
        $colDesc += " [$($colName)]:"
    }

    If ($colMember -eq 0) {
        $body += [System.Web.HttpUtility]::HtmlDecode((New-Object psobject -Property @{'Device Name'="No Device"} | ConvertTo-Html -Title "$colDesc" -PreContent "<h2>$colDesc</h2>"))
        Write-Host "No device found in collection [$colName]"
        continue
    }
    Else {
        Write-Host "$colMember devices found in collection [$colName]"
    }

    $oColMembers = (Get-CMCollectionMember -CollectionName $colName) | 
        Select-Object @{ N="Device Name"; E={"<b>"+$_.Name+"</b>"} },
            @{ N="Device OS"; E={$_.DeviceOS} },
            @{ N="Domain"; E={$_.Domain} },
            @{ N="Active"; E={$_.IsActive} },
            @{ N="Last Active Time"; E={$_.LastActiveTime} },
            @{ N="Last Policy Request"; E={$_.LastPolicyRequest} } | Sort-Object 'Device Name'
    
    $body += [System.Web.HttpUtility]::HtmlDecode(($oColMembers | ConvertTo-Html -Title "$colDesc" -PreContent "<h2>$colDesc</h2>"))
}
$report = ConvertTo-Html -Body $body -Head $header -Title $ReportTitle

try {
    $report | Set-Content $strOutputFilePath
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
    Subject = "[SCCM] $ReportTitle"
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
