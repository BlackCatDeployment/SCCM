<#
.Synopsis
    Check ADR execution and send an HTML report by mail
.DESCRIPTION
    An HTML report is generated and sent by mail to summary ADR execution
.PARAMETER File
    Name of the XML configuration file
    MUST BE placed on the script root path
.OUTPUTS
   HTML report stored in $PSScriptRoot\Reports\CheckADRExecution-<date>.log
.NOTES
    Version:         1.0
    Author:          Florian Valente
    Date:            2019/07/11
    Version History: 1.0 : 2019/07/11 - Florian Valente
.EXAMPLE
    CheckADRExecution.ps1 -File "settings.xml"
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


function Get-CMLog {
<#
.SYNOPSIS
Parses logs for System Center Configuration Manager.
.DESCRIPTION
Accepts a single log file or array of log files and parses them into objects.  Shows both UTC and local time for troubleshooting across time zones.
.PARAMETER Path
Specifies the path to a log file or files.
.INPUTS
Path/FullName.  
.OUTPUTS
PSCustomObject.  
.EXAMPLE
C:\PS> Get-CMLog -Path Sample.log
Converts each log line in Sample.log into objects
UTCTime   : 7/15/2013 3:28:08 PM
LocalTime : 7/15/2013 2:28:08 PM
FileName  : sample.log
Component : TSPxe
Context   : 
Type      : 3
TID       : 1040
Reference : libsmsmessaging.cpp:9281
Message   : content location request failed
.EXAMPLE
C:\PS> Get-ChildItem -Path C:\Windows\CCM\Logs | Select-String -Pattern 'failed' | Select -Unique Path | Get-CMLog
Find all log files in folder, create a unique list of files containing the phrase 'failed, and convert the logs into objects
UTCTime   : 7/15/2013 3:28:08 PM
LocalTime : 7/15/2013 2:28:08 PM
FileName  : sample.log
Component : TSPxe
Context   : 
Type      : 3
TID       : 1040
Reference : libsmsmessaging.cpp:9281
Message   : content location request failed
.LINK
http://blog.richprescott.com
#>

    param (
        [Parameter(Mandatory=$true,
                   Position=0,
                   ValueFromPipelineByPropertyName=$true)]
        [Alias("FullName")]
        $Path
    )

    PROCESS {
        foreach ($File in $Path) {
            $FileName = Split-Path -Path $File -Leaf

            $oFile = Get-Content -Path $File -ErrorAction Stop
            ForEach ($line in $oFile) {
                If ($line.substring(0,7) -eq '<![LOG[') {
                    $line -match '\<\!\[LOG\[(?<Message>.*)?\]LOG\]\!\>\<time=\"(?<Time>.+)(?<TZAdjust>[+|-])(?<TZOffset>\d{2,3})\"\s+date=\"(?<Date>.+)?\"\s+component=\"(?<Component>.+)?\"\s+context="(?<Context>.*)?\"\s+type=\"(?<Type>\d)?\"\s+thread=\"(?<TID>\d+)?\"\s+file=\"(?<Reference>.+)?\"\>' | Out-Null
                }
                Else {
                    $line -match '(?<Message>.*)?  \$\$\<(?<Component>.*)?\>\<(?<Date>.+) (?<Time>.+)(?<TZAdjust>[+|-])(?<TZOffset>\d{2,3})?\>\<thread=(?<TID>.*)\>' | Out-Null
                }
                [pscustomobject]@{
                    UTCTime = [datetime]::ParseExact($("$($matches.date) $($matches.time)$($matches.TZAdjust)$($matches.TZOffset/60)"),"MM-dd-yyyy HH:mm:ss.fffz", $null, "AdjustToUniversal")
                    LocalTime = [datetime]::ParseExact($("$($matches.date) $($matches.time)"),"MM-dd-yyyy HH:mm:ss.fff", $null)
                    FileName = $FileName
                    Component = $matches.component
                    Context = $matches.context
                    Type = $matches.type
                    TID = $matches.TID
                    Reference = $matches.reference
                    Message = $matches.message
                }
            }
        }
    }
}



########
# MAIN #
########
$ParsingDate = Get-Date -Format 'yy-MM-dd'

# Global variables
$script_parent     = Split-Path -Parent $MyInvocation.MyCommand.Definition
$ReportPath        = "$script_parent\Reports"

If (-not (Test-Path $ReportPath)) { New-Item $ReportPath -ItemType Directory | Out-Null }

# Load XML settings file
$xml = [xml](Get-Content "$PSScriptRoot\$File")

$ADRLogPath        = @("$($xml.settings.cmpath)\Logs\ruleengine.lo_", "$($xml.settings.cmpath)\Logs\ruleengine.log")
$MailFrom          = $xml.settings.mail.from
$MailTo            = @(($xml.settings.mail.to -split ",").Trim())
$MailCc            = @(($xml.settings.mail.cc -split ",").Trim())
$MailBcc           = @(($xml.settings.mail.bcc -split ",").Trim())
$MailSMTP          = $xml.settings.mail.server

$oADRCheck = @()
$oLog = $null

try {
    ForEach ($logFile in $ADRLogPath) {
        If (Test-Path $logFile) {
            $oLog += Get-CMLog $logFile | ? { ($_.LocalTime).Date -eq ([datetime]::ParseExact($ParsingDate, 'yy-MM-dd', $null).Date) }
        }
    }
}
catch {
    Write-Warning $_.Exception.Message
    exit 1
}

ForEach ($line in $oLog.Message) {
    If ($line.Trim() -match '^(?<UpdatesDL>.*)? update?.*\"(?<PkgID>.*)?\" \((?<PkgPath>.*)?\)') {
        Write-Host "$($Matches.UpdatesDL) updates have to be downloaded in $($Matches.PkgPath)"
        $oParams = [ordered]@{
            'Package Path' = $Matches.PkgPath
        }
        $bFound = $true
    }
    If ($bFound) {
        If ($line.Trim() -match '\~\s(?<UpdatesDL>.*)? of (?<UpdatesAll>.*)? updates (.*)') {
            $oParams += [ordered]@{
                'Total Updates' = ($Matches.UpdatesAll).Trim()
                'Updates Downloaded' = ($Matches.UpdatesDL).Trim()
            }
            If (($Matches.UpdatesDL).Trim() -eq ($Matches.UpdatesAll).Trim()) {
                Write-Host "Updates deployed successfully"
                $oParams += @{
                    Status = "SUCCESS! All updates downloaded and deployed"
                }
            }
            Else {
                Write-Warning "$($Matches.UpdatesAll - $Matches.UpdatesDL) updates not downloaded!"
                $oParams += @{
                    Status = "ERROR! $($Matches.UpdatesAll - $Matches.UpdatesDL) updates not downloaded"
                }
            }

            $oADRCheck += New-Object PSObject -Property $oParams
            $bFound = $false
        }
    }
}

If ($oADRCheck.Count -eq 0) {
    exit
}

Write-Host "Generating report for ADR Execution Check..."
$strOutputFilePath = "$ReportPath\CheckADRExecution-$((Get-Date).ToString("yyyyMMddHHmmss")).html"
$title = "ADR Execution Check on $(Get-Date -Format "yyyy/MM/dd")"
# Create header of the HTML file
$header = "<style>"
$header += "BODY{background-color:WhiteSmoke;}"
$header += "TABLE{border-width:1px; width:100%; border-style:solid; border-color:black; border-collapse:collapse;}"
$header += "TH{border-width:1px; padding:5px; border-style:solid; border-color:black; background-color:IndianRed;}"
$header += "TD{border-width:1px; padding:5px; border-style:solid; border-color:black; background-color:LightCyan;}"
$header += "</style>"

# Create body of the HTML file
$body = "<h1><u><center>$title</center></u></h1>"

# Computer to approve found -> generate and send HTML report
Add-Type -AssemblyName System.Web
$body += [System.Web.HttpUtility]::HtmlDecode(($oADRCheck | ConvertTo-Html -Title "ADR Execution Check"))
$report = ConvertTo-Html -Body $body -Head $header -Title $title
   
try {
    $report | Set-Content $strOutputFilePath
    Write-Host "Report generated successfully on $strOutputFilePath"
}
catch {
    Write-Warning "Report was not generated! $($_.Exception.Message)"
}

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
