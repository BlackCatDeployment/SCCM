<#
.SYNOPSIS
   This script exports User and Device Collections in ConfigMgr Current Branch on an output CSV file.
.DESCRIPTION
   This script is able to export ConfigMgr collections.
.EXAMPLE
   .\ExportCollections.ps1 -File "ExportCollections.csv"
.INPUTS
   None
.OUTPUTS
   CSV file with ";" delimiter
   Log file stored in $PSScriptRoot\ExportCollections.log
.PARAMETER File
   Set the CSV file name to save.
   It will be located in the script folder.
.NOTES
    Version:         1.0
    Author:          Florian Valente
    Date:            2018/11/19
    Version History: 1.0 : 2018/11/19 - Florian Valente
                         - Initial version
.COMPONENT
   This script must be run on a ConfigMgr Current Branch server on Windows Server 2012 R2 minimum.
   It wasn't tested on ConfigMgr 2012 R2 neither on Windows Server 2008 R2.
   It uses the ConfigurationManager PoSh module
.LINK
    https://bcdeployment.wordpress.com
#>
Param (
    [Parameter(Mandatory=$False)][String] $File = "ExportCollections.csv"
)

#ERROR REPORTING ALL
Set-StrictMode -Version latest

# Import the ConfigurationManager.psd1 module
Import-Module "$($ENV:SMS_ADMIN_UI_PATH)\..\ConfigurationManager.psd1"

# Global variables
$script_parent        = Split-Path -Parent $MyInvocation.MyCommand.Definition
$csv_path             = $script_parent + "\$File"
$script:sitecode      = (Get-PSDRive -PSProvider CMSite).name
$script:SMSProvider   = (Get-PSDRive -PSProvider CMSite).Root
$script:output        = $script_parent + "\$(($MyInvocation.MyCommand.Name) -replace ".ps1", ".log")"
$CollectionTypeUser   = "User"
$CollectionTypeDevice = "Device"
$DefaultSchedule      = "D7" #7 days
$script:objResult     = @{ Success=0; Warning=0; Error=0 }



#############
# FUNCTIONS #
#############
Function Start-CollectionExport {
    $nbItem = 0
    $oCollections = Get-CMCollection | Sort-Object CollectionId | ? {-not $_.IsBuiltIn}
    $nbTotalItems = $oCollections.Count

    $oOutput = @()

    try {
        ForEach ($oCol In $oCollections) {
            $sColName = $oCol.Name
            Write-Progress -Activity "Exporting ConfigMgr Collections..." -Status "Collection: $sColName ($($nbItem+1) of $nbTotalItems)" -PercentComplete ((($nbItem+1)/$nbTotalItems)*100)
            Write-Log "Exporting [$sColName] Collection..."

            $props = [ordered]@{
                Implement = "A"
                CollectionName = $sColName
            }

            If ($oCol.CollectionType -eq 1) {
                $props += @{ CollectionType = $CollectionTypeUser }
            }
            ElseIf ($oCol.CollectionType -eq 2) {
                $props += @{ CollectionType = $CollectionTypeDevice }
            }
            Else {
                $props += @{ CollectionType =  "Unknown" }
            }

            $props += @{
                CollectionLimit = $oCol.LimitToCollectionName
            }

            $sColFolder = (Get-WmiObject -Namespace "root\sms\site_$script:sitecode" -Class "SMS_Collection" -Filter "CollectionId = '$($oCol.CollectionID)'" -ComputerName $script:SMSProvider).ObjectPath
            $sColFolder = $sColFolder.Substring(1) -replace "/", "\"
            $props += @{
                CollectionFolder = $sColFolder
            }

            $props += @{
                CollectionComment = $oCol.Comment
            }

            $aSchedule = @()
            If ($oCol.RefreshType -eq 1) {
                Write-Log "No Schedule found" warning
            }
            If (($oCol.RefreshType -eq 4) -or ($oCol.RefreshType -eq 6)) {
                $aSchedule += @("I")
            }
            If (($oCol.RefreshType -eq 2) -or ($oCol.RefreshType -eq 6)) {
                $aSchedule += @(Get-CollectionSchedule -InputObject $oCol.RefreshSchedule)
            }
            $props += @{
                RefreshSchedule = $aSchedule -join ","
            }

            $oAdmUsers = Get-CMAdministrativeUser | Where-Object { $_.CollectionNames -eq $oCol.Name }
            If (($oAdmUsers -ne $null) -and ($oAdmUsers.Count -ne 0)) {
                $props += @{
                    User = $oAdmUsers.LogonName -join ","
                }
                Write-Log "User(s) found"
            }
            Else {
                $props += @{ User = "" }
                Write-Log "No User found"
            }

            If ($oCol.CollectionRules) {
                $oRules = Get-CollectionRule -InputObject $oCol.CollectionRules
                $props += @{
                    RuleType = $oRules.Type -join "||"
                    RuleName = $oRules.Name -join "||"
                    RuleQuery = $oRules.Query -join "||"
                }
            }
            Else {
                $props += @{
                    RuleType = ""
                    RuleName = ""
                    RuleQuery = ""
                }
                Write-Log "No Rule found" warning
            }

            $oOutput += New-Object -TypeName PSObject -Property $props
            Write-Log "Collection exported successfully" success

            $nbItem++
        }
    }
    catch {
        Write-Log "Collection [$sColName] cannot be exported! $($_.Exception.Message)" error
    }

    Write-Progress -Activity "Exporting ConfigMgr Collections..." -Completed

    $oOutput | Export-Csv -Path $csv_path -Delimiter ";" -Encoding UTF8 -Force -NoTypeInformation
}


Function Get-CollectionSchedule {
    [CmdletBinding()]
    Param (
	    [Parameter(Mandatory=$true)] $InputObject
    )

    $sSchedule = $DefaultSchedule
    If ($InputObject.SmsProviderObjectPath -eq "SMS_ST_RecurInterval") {
        If ($InputObject.DaySpan -ne 0) {
            $sSchedule = "D" + $InputObject.DaySpan
        }
        ElseIf ($InputObject.MinuteSpan -ne 0) {
            $sSchedule = "M" + $InputObject.MinuteSpan
        }
        ElseIf ($InputObject.HourSpan -ne 0) {
            $sSchedule = "H" + $InputObject.HourSpan
        }

        Write-Log "Schedule found: $sSchedule"
    }
    Else {
        Write-Log "Only custom interval is supported! Schedule was set to $sSchedule" warning
    }

    return $sSchedule
}


Function Get-CollectionRule {
    [CmdletBinding()]
    Param (
	    [Parameter(Mandatory=$true)] $InputObject
    )

    $oRules = @()

    $oRulesDirect = $InputObject | ? { $_.SmsProviderObjectPath -eq "SMS_CollectionRuleDirect" }
    If ($oRulesDirect) {
        $props = @{
            Type = "Direct"
            Name = ""
            Query = $oRulesDirect.RuleName -join ","
        }

        $oRules += New-Object -TypeName PSObject -Property $props
        Write-Log "Direct rule(s) found"
    }

    $oRulesQuery = ($InputObject | ? { $_.SmsProviderObjectPath -eq "SMS_CollectionRuleQuery" }) | Sort-Object QueryID
    If ($oRulesQuery) {
        ForEach ($Rule in $oRulesQuery) {
            $props = @{
                Type = "Query"
                Name = $Rule.RuleName
                Query = $Rule.QueryExpression
            }

            $oRules += New-Object -TypeName PSObject -Property $props
        }

        Write-Log "Query rule(s) found"
    }

    $oRulesInclude = $InputObject | ? { $_.SmsProviderObjectPath -eq "SMS_CollectionRuleIncludeCollection" }
    If ($oRulesInclude) {
        $props = @{
            Type = "Include"
            Name = ""
        }
        $aCollections = @()
        ForEach ($Rule in $oRulesInclude) {
            $aCollections += @(Get-CMCollection -Id $Rule.IncludeCollectionID).Name
        }
        $props += @{
            Query = $aCollections -join ","
        }

        $oRules += New-Object -TypeName PSObject -Property $props
        Write-Log "Include Collection Rule(s) found"
    }

    $oRulesExclude = $InputObject | ? { $_.SmsProviderObjectPath -eq "SMS_CollectionRuleExcludeCollection" }
    If ($oRulesExclude) {
        $props = @{
            Type = "Exclude"
            Name = ""
        }
        $aCollections = @()
        ForEach ($Rule in $oRulesExclude) {
            $aCollections += @(Get-CMCollection -Id $Rule.ExcludeCollectionID).Name
        }
        $props += @{
            Query = $aCollections -join ","
        }

        $oRules += New-Object -TypeName PSObject -Property $props
        Write-Log "Exclude Collection Rule(s) found"
    }

    return $oRules
}


Function Write-Log {
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory=$true)][String] $message,
        [ValidateSet("start", "stop", "info","warning","error","success")][String] $Status = "info"
    )

    $logdate = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")

    Switch ($Status) {
        "info" { $colormsg = "White"; $statusmsg = "INFO" }
        "warning" { $colormsg = "Yellow"; $statusmsg = "WARN"; $objResult.Warning++ }
        "error" { $colormsg = "Red"; $statusmsg = "FAIL"; $objResult.Error++ }
        "success" { $colormsg = "Green"; $statusmsg = "GOOD"; $objResult.Success++ }
        "start" {
            $message = "--- Started Script Execution (USER: $env:USERDOMAIN\$env:USERNAME) ---"
            $colormsg = "Cyan"
            $statusmsg = "INFO"
        }
        "stop" {
            $message = "--- Stopped Script Execution ---`r"
            $colormsg = "Cyan"
            $statusmsg = "INFO"
        }
        default { $colormsg = "White"; $statusmsg = "INFO" }
    }

    Write-Host "[$statusmsg]`t $message" -ForegroundColor $colormsg
    "[$statusmsg][$($logdate)]`t $message" | Out-File $output -Append
}


########
# MAIN #
########
Write-Log "Starting..." start

# Initialize location for managing ConfigMgr! MANDATORY before continue
$InitialLocation = Get-Location
Set-Location "$($sitecode):"

# Export collections
try {
    Start-CollectionExport
}
finally {
    Write-Log "$($objResult.Success) Success, $($objResult.Warning) Warnings, $($objResult.Error) Errors"
    Write-Log "end" stop

    # Reset the location to the previous state
    Set-Location $InitialLocation.Path
}
