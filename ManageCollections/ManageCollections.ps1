<#
.SYNOPSIS
   This script manages User and Device Collections in ConfigMgr Current Branch based on an input CSV file.
.DESCRIPTION
   This script is able to add, remove, replace ConfigMgr collections.
   It also creates necessary Collections folder tree automatically.
   For a collection creation, it's possible to set:
    - A name
    - A type (user or device collection)
    - A comment
    - A folder
    - A limiting collection
    - A schedule or an incremental update
    - One or more membership rules like query rule, direct rule, include collection rule or exclude collection rule
    - One or more administrative users (v1.1)
.EXAMPLE
   .\ManageCollections.ps1
.EXAMPLE
   .\ManageCollections.ps1 -File "CreateCollections.csv"
.INPUTS
   CSV file with ";" delimiter
.OUTPUTS
   Log file stored in $PSScriptRoot\ManageCollection.log
.PARAMETER File
   Set the CSV file to use.
   It must be located on the script folder.
.NOTES
    Version:         1.4
    Author:          Florian Valente
    Date:            2018/11/20
    Version History: 1.0 : 2017/09/04 - Florian Valente
                         - Initial version
                     1.1 : 2017/09/18 - Florian Valente
                         - Add Administrative User management
                     1.2 : 2017/09/20 - Florian Valente
                         - Improve the Remove-Collection function
                           - Check Collection references
                           - Check Collection Membership Rules dependences
                           - Check Collection Administrative User(s) permissions
                     1.3 : 2018/03/16 - Florian Valente
                           - Improve the New-Collection function
                           - Add random hour:minute for the New-CMSchedule to avoid overload during SCCM collection updates
                     1.4 : 2018/11/20 - Florian Valente
                           - Review Log management
    Helpers:         Marius / Hican - http://www.hican.nl - @hicannl
                     https://gallery.technet.microsoft.com/scriptcenter/SCCM-2012-Management-b36e7aeb
                     Benoit Lecours
                     https://gallery.technet.microsoft.com/Set-of-Operational-SCCM-19fa8178
.COMPONENT
   This script must be run on a ConfigMgr Current Branch server on Windows Server 2012 R2 minimum.
   It wasn't tested on ConfigMgr 2012 R2 neither on Windows Server 2008 R2.
   It uses the ConfigurationManager PoSh module
.LINK
    https://bcdeployment.wordpress.com
#>
Param (
    [Parameter(Mandatory=$False)][String] $File = "ManageCollections.csv"
)

#ERROR REPORTING ALL
Set-StrictMode -Version latest

# Import the ConfigurationManager.psd1 module
Import-Module "$($ENV:SMS_ADMIN_UI_PATH)\..\ConfigurationManager.psd1"

# Global variables
$script_parent        = Split-Path -Parent $MyInvocation.MyCommand.Definition
$csv_path             = $script_parent + "\$File"
$script:sitecode      = (Get-PSDRive -PSProvider CMSite).name
$script:output        = $script_parent + "\$(($MyInvocation.MyCommand.Name) -replace ".ps1", ".log")"
$AllDevicesCollection = "All Systems"
$AllUsersCollection   = "All Users and User Groups"
$CollectionTypeUser   = "User"
$CollectionTypeDevice = "Device"
$script:objResult     = @{ Success=0; Warning=0; Error=0 }



#############
# FUNCTIONS #
#############
Function New-Collection {
    [CmdletBinding()]
    Param (
	    [Parameter(Mandatory=$true)][String] $Name,
        [Parameter(Mandatory=$true)][String] $Type,
        [Parameter(Mandatory=$false)][String] $Comment = "",
        [Parameter(Mandatory=$false)][String] $Folder = "",
        [Parameter(Mandatory=$false)][String] $LimitingCollection = "",
        [Parameter(Mandatory=$false)][String] $Schedule = "",
        [Parameter(Mandatory=$false)][String] $RuleType = "",
        [Parameter(Mandatory=$false)][String] $RuleName = "",
        [Parameter(Mandatory=$false)][String] $RuleQuery = "",
        [Parameter(Mandatory=$false)][String] $User = ""
    )

    $CollectionPath = "$($sitecode):\$($Type)Collection"
    $CollectionReturned = $null

    # Get Collection object
    $objCollection = . "Get-CM$($Type)Collection" -Name $Name

    Write-Log "==> Creating [$Type] Collection [$Name]..."

    If ($objCollection -eq $null) {
        #region ColProps
        ## Defining Collection Properties
        $CollectionProperties = @{
            Name = $Name
            Comment = "$Comment"
        }
        #endregion ColProps

        #region ColLimit
        ## Defining Collection limit
        # Set default limiting collection depending on the collection type
        If ($Type -eq $CollectionTypeUser) { $CollectionLimitName = $AllUsersCollection }
        Else { $CollectionLimitName = $AllDevicesCollection }

        If (!([String]::IsNullOrEmpty($LimitingCollection))) { 
            $objCollectionLimit = . "Get-CM$($Type)Collection" -Name $LimitingCollection
            If ($objCollectionLimit -eq $null) {
                Write-Log "Collection limit [$LimitingCollection] was not found. [$CollectionLimitName] defined" warning
            }
            Else {
                $CollectionLimitName = $LimitingCollection
                Write-Log "Collection Limit [$CollectionLimitName] defined"
            }
        }
        Else {
            Write-Log "No Collection limit was set in the CSV file. [$CollectionLimitName] defined" warning
        }

        $CollectionProperties += @{ LimitingCollectionName = $CollectionLimitName }
        #endregion ColLimit

        #region ColSchedule
        ## Defining Collection Shedule
        If (!([String]::IsNullOrEmpty($Schedule))) {
            $objSchedule = Set-CollectionSchedule -Value $Schedule
            $CollectionProperties += @{
                RefreshSchedule = New-CMSchedule -Start (Get-Date -Hour (Get-Random 23) -Minute (Get-Random 59)) -RecurInterval $objSchedule.RefreshInterval -RecurCount $objSchedule.RefreshCount
                RefreshType = $objSchedule.RefreshType
            }
        }
        Else {
            Write-Log "No Refresh Schedule was set in the CSV File. [Incremental Updates] defined" warning
            $CollectionProperties += @{ RefreshType = 4 } # Use Incremental Updates
        }
        #endregion ColSchedule

        try {
            $objNewCollection = . "New-CM$($Type)Collection" @CollectionProperties
        }
        catch {
            Write-Log "Collection can't be created! $($_.Exception.Message)" error
            return $CollectionReturned
        }

        Write-Log "Collection created"

        #region ColMove
        If (!([String]::IsNullOrEmpty($Folder))) {
            $CollectionFolderPath = $CollectionPath + "\" + $Folder

            # Create tree recursively if needed
            If (!(Test-Path $CollectionFolderPath)) {
                $arrFolders = $Folder -split "\\"
                $FolderPath = $CollectionPath
                ForEach ($fld in $arrFolders) {
                    $FolderPath += "\$fld"
                    If (!(Test-Path $FolderPath)) { New-Item -Path $FolderPath | Out-Null }
                }
                Write-Log "Folder [$($Folder)] created"
            }

            Try {
                Move-CMObject -InputObject $objNewCollection -FolderPath $CollectionFolderPath
                Write-Log "Collection moved to Folder [$($Folder)]"
            }
            Catch {
                Write-Log "Can't move Collection to Folder [$($Folder)]! $($_.Exception.Message)" error
            }
        }
        #endregion ColMove

        #region ColRule
        If (!([String]::IsNullOrEmpty($RuleType))) {
            Add-CollectionRule -Collection $objNewCollection -Name $RuleName -Type $RuleType -Query $RuleQuery
        }
        #endregion ColRule

        #region ColPermission
        If (!([String]::IsNullOrEmpty($User))) {
            Add-CollectionPermission -Collection $objNewCollection -User $User
        }
        #endregion ColPermission

        $CollectionReturned = . "Get-CM$($Type)Collection" -Name $Name
        Write-Log "Collection [$Name] configured" success
    }
    Else {
        $CollectionReturned = $objCollection
        Write-Log "[$Type] Collection [$Name] already exists with ID [$($objCollection.CollectionID)]" warning
    }

    return ($CollectionReturned | Out-Null)
}


Function Restore-Collection {
    [CmdletBinding()]
    Param (
	    [Parameter(Mandatory=$true)][String] $Name,
        [Parameter(Mandatory=$true)][String] $Type,
        [Parameter(Mandatory=$false)][String] $Comment = "",
        [Parameter(Mandatory=$false)][String] $Folder = "",
        [Parameter(Mandatory=$false)][String] $LimitingCollection = "",
        [Parameter(Mandatory=$false)][String] $Schedule = "",
        [Parameter(Mandatory=$false)][String] $RuleType = "",
        [Parameter(Mandatory=$false)][String] $RuleName = "",
        [Parameter(Mandatory=$false)][String] $RuleQuery = "",
        [Parameter(Mandatory=$false)][String] $User = ""
    )

    # Get Collection object
    $objCollection = . "Get-CM$($Type)Collection" -Name $Name

    Write-Log "==> Replacing [$Type] Collection [$Name]..."

    If ($objCollection -ne $null) {
        If (!(Remove-Collection -Name $Name -Type $Type)) {
            Write-Log "An error occured during Collection deletion. Cannot replace it"
            return
        }
    }

    New-Collection -Name $Name `
        -Type $Type `
        -Comment $Comment `
        -Folder $Folder `
        -LimitingCollection $LimitingCollection `
        -Schedule $Schedule `
        -RuleType $RuleType -RuleName $RuleName -RuleQuery $RuleQuery `
        -User $User
        
    Write-Log "Collection [$Name] replaced"
}


Function Remove-Collection {
    [CmdletBinding()]
    Param (
	    [Parameter(Mandatory=$true)][String] $Name,
        [Parameter(Mandatory=$true)][String] $Type
    )

    # Get Collection object
    $objCollection = . "Get-CM$($Type)Collection" -Name $Name

    Write-Log "==> Deleting [$Type] Collection [$Name]..."
    If ($objCollection -eq $null) {
        Write-Log "Collection was not found. Nothing to do."
        return $true
    }

    # Check if the collection to delete is a limiting collection of other collection(s)
    Write-Log "Checking Collection references..."
    $objLimitingCollections = . "Get-CM$($Type)Collection" | Where-Object { $_.LimitToCollectionName -eq $objCollection.Name }
    If (($objLimitingCollections -ne $null) -and ($objLimitingCollections.Count -ne 0)) {
        Write-Log "Collection can't be deleted because referring to $($objLimitingCollections.Count) following collections:"
        Write-Log "$($objLimitingCollections.Name -join ", ")" error
        return $false
    }
    Write-Log "Check done"


    # Check if the collection to delete is a include/exclude membership rule of other collection(s)
    $DisplayWarning = $false
    Write-Log "Checking Collection Membership Rules dependences..."
    # To reduce process delay, get all collections with Include/Exclude Collection Membership rule(s)
    $objMembershipCollections = . "Get-CM$($Type)Collection" | Where-Object { $_.IncludeExcludeCollectionsCount -ne 0 }
    If (($objMembershipCollections -ne $null) -and ($objMembershipCollections.Count -ne 0)) {
        ForEach ($objMemberCollection in $objMembershipCollections) {
            # Check Include Membership Rules
            # If the collection to delete is on an Include Membership Rule of another collection -> Delete
            $objMember = . "Get-CM$($Type)CollectionIncludeMembershipRule" -InputObject $objMemberCollection -IncludeCollection $objCollection
            If ($objMember -ne $null) {
                try {
                    . "Remove-CM$($Type)CollectionIncludeMembershipRule" -InputObject $objMemberCollection -IncludeCollection $objCollection -Confirm:$false -Force
                    Write-Log "WARNING! Collection removed from Include Membership Rule of Collection [$($objMemberCollection.Name)]"
                    $DisplayWarning = $true
                }
                catch {
                    Write-Log "Cannot remove Collection from Include Rule! $($_.Exception.Message)" error
                    return $false
                }
            }

            # Check Exclude Membership Rules
            # If the collection to delete is on an Exclude Membership Rule of another collection -> Delete
            $objMember = . "Get-CM$($Type)CollectionExcludeMembershipRule" -InputObject $objMemberCollection -ExcludeCollection $objCollection
            If ($objMember -ne $null) {
                try {
                    . "Remove-CM$($Type)CollectionExcludeMembershipRule" -InputObject $objMemberCollection -ExcludeCollection $objCollection -Confirm:$false -Force
                    Write-Log "WARNING! Collection removed from Exclude Membership Rule of Collection [$($objMemberCollection.Name)]"
                    $DisplayWarning = $true
                }
                catch {
                    Write-Log "Cannot remove Collection from Exclude Rule! $($_.Exception.Message)" error
                    return $false
                }
            }
        }
    }
    If ($DisplayWarning) { $objResult.Warning++ }
    Write-Log "Check done"

    
    # Check if the collection to delete is granted to administrative user(s)
    Write-Log "Checking Collection Administrative User(s) permissions..."
    $objAdmUsers = Get-CMAdministrativeUser | Where-Object { $_.CollectionNames -eq $objCollection.Name }
    If (($objAdmUsers -ne $null) -and ($objAdmUsers.Count -ne 0)) {
        Write-Log "Removing Collection from Administrative User(s) permissions..."
        ForEach ($objUser in $objAdmUsers) {
            try {
                Remove-CMCollectionFromAdministrativeUser -InputObject $objCollection -User $objUser -Confirm:$false -Force
                Write-Log "Collection removed from user [$($objUser.LogonName)]"
            }
            catch {
                Write-Log "Cannot remove Collection from user [$($objUser.LogonName)]! $($_.Exception.Message)" error
                return $false
            }
        }
    }
    Write-Log "Check done"


    # Remove the collection
    try {
        Remove-CMCollection -InputObject $objCollection -Confirm:$false -Force
        Write-Log "Collection deleted" success
        return $true
    }
    catch {
        Write-Log "Collection can't be deleted! $($_.Exception.Message)" error
        return $false
    }
}


Function Start-CollectionManagement {
    $nbItem = 0
    $nbTotalItems = $csv_import.Count

    ForEach ($item In $csv_import) {
        If ($item.CollectionType.ToLower() -eq "user") {
            $CollectionTypeName = $CollectionTypeUser
        }
        Else {
            $CollectionTypeName = $CollectionTypeDevice
        }

        If ([String]::IsNullOrEmpty($item.CollectionName)) {
            Write-Log "No Collection Name was filled in the CSV file! Next"
            $nbItem++
            Continue
        }
        
        Write-Progress -Activity "Managing ConfigMgr Collections..." -Status "Collection: $($item.CollectionName) ($($nbItem+1) of $nbTotalItems)" -PercentComplete ((($nbItem+1)/$nbTotalItems)*100)

        Switch ($item.Implement.ToLower()) {
            "a" {
                New-Collection -Name $item.CollectionName `
                    -Type $CollectionTypeName `
                    -Comment $item.CollectionComment `
                    -Folder $item.CollectionFolder `
                    -LimitingCollection $item.CollectionLimit `
                    -Schedule $item.RefreshSchedule `
                    -RuleType $item.RuleType -RuleName $item.RuleName -RuleQuery $item.RuleQuery `
                    -User $item.User
            }

            "r" {
                Restore-Collection -Name $item.CollectionName `
                    -Type $CollectionTypeName `
                    -Comment $item.CollectionComment `
                    -Folder $item.CollectionFolder `
                    -LimitingCollection $item.CollectionLimit `
                    -Schedule $item.RefreshSchedule `
                    -RuleType $item.RuleType -RuleName $item.RuleName -RuleQuery $item.RuleQuery `
                    -User $item.User
            }

            "d" {
                Remove-Collection -Name $item.CollectionName -Type $CollectionTypeName | Out-Null
            }

            "n" {
                Write-Log "Processing is disabled for Collection [$($item.CollectionName)]" warning
            }

            Default {
                Write-Log "Switch [$($item.Implement)] is not managed for Collection [$($item.CollectionName)]! Nothing to do" error
            }
        }

        $nbItem++
    }
    Write-Progress -Activity "Managing ConfigMgr Collections..." -Completed
}


Function Add-CollectionRule {
    [CmdletBinding()]
    Param (
	    [Parameter(Mandatory=$true)] $Collection,
        [Parameter(Mandatory=$false)][String] $Name = "",
        [Parameter(Mandatory=$false)][String] $Type = "",
        [Parameter(Mandatory=$false)][String] $Query = ""
    )

    $i = 0
    # Use ,0,"SimpleMatch" with the split to only match with ||
    # A collection name or a rule name can contain a | char, so I prefered to use || as separator
    $arrRuleTypes   = @(($Type -split "||",0,"SimpleMatch").Trim())
    $arrRuleNames   = @(($Name -split "||",0,"SimpleMatch").Trim())
    $arrRuleQueries = @(($Query -split "||",0,"SimpleMatch").Trim())

    If ($Collection.CollectionType -eq 1) {
        $CollectionTypeName = $CollectionTypeUser
    }
    Else {
        $CollectionTypeName = $CollectionTypeDevice
    }

    ForEach ($RType in $arrRuleTypes) {
        try { $strRuleQuery = $arrRuleQueries[$i] }
        catch { $strRuleQuery = "" }

        If (!([String]::IsNullOrEmpty($strRuleQuery))) {
            try {
                If ([String]::IsNullOrEmpty($arrRuleNames[$i])) { $strRuleName = $Collection.Name }
                Else { $strRuleName = $arrRuleNames[$i] }
            }
            catch { $strRuleName = $Collection.Name }

            #region ColRuleQuery
            If ($RType.ToLower() -eq "query") {
                try {
                    # Call Add-CMUserCollectionQueryMembershipRule or Add-CMDeviceCollectionQueryMembershipRule cmdlet depending the need
                    . "Add-CM$($CollectionTypeName)CollectionQueryMembershipRule" -CollectionID $Collection.CollectionID -QueryExpression $strRuleQuery -RuleName $strRuleName
                    Write-Log "Collection Query Rule [$strRuleName] added"
                }
                catch {
                    Write-Log "Collection Query Rule $($i+1) can't be added! $($_.Exception.Message)" error
                }
            }
            #endregion ColRuleQuery
            #region ColRuleDirect
            ElseIf ($RType.ToLower() -eq "direct") {
                $colQry = @()
                $colQry = ($strRuleQuery).Split(",")

                ForEach ($elt In $colQry) {
                    try {
                        # Call Get-CMUser or Get-CMDevice cmdlet depending the need
                        $objResource = . "Get-CM$($CollectionTypeName)" -Name $elt
                        
                        If ($objResource -ne $null) {
                            # Call Add-CMUserCollectionDirectMembershipRule or Add-CMDeviceCollectionDirectMembershipRule cmdlet depending the need
                            . "Add-CM$($CollectionTypeName)CollectionDirectMembershipRule" -CollectionID $Collection.CollectionID -ResourceID $objResource.ResourceID
                            Write-Log "Collection Direct Rule for [$elt] added"
                        }
                        Else {
                            Write-Log "Resource [$elt] wasn't found! Can't add Direct Rule $($i+1)" warning
                        }
                    }
                    catch {
                        Write-Log "Collection Direct Rule $($i+1) can't be added for [$elt]! $($_.Exception.Message)" error
                    }
                }
            }
            #endregion ColRuleDirect
            #region ColRuleInclude
            ElseIf ($RType.ToLower() -eq "include") {
                $colQry = @()
                $colQry = ($strRuleQuery).Split(",")

                ForEach ($elt In $colQry) {
                    try {
                        $objResource = . "Get-CM$($CollectionTypeName)Collection" -Name $elt
                        
                        If ($objResource -ne $null) {
                            # Call Add-CMUserCollectionIncludeMembershipRule or Add-CMDeviceCollectionIncludeMembershipRule cmdlet depending the need
                            . "Add-CM$($CollectionTypeName)CollectionIncludeMembershipRule" -CollectionID $Collection.CollectionID -IncludeCollection $objResource
                            Write-Log "Collection Include Rule for [$elt] added"
                        }
                        Else {
                            Write-Log "Collection [$elt] wasn't found! Can't add Include Rule $($i+1)" warning
                        }
                    }
                    catch {
                        Write-Log "Collection Include Rule $($i+1) can't be added for [$elt]! $($_.Exception.Message)" error
                    }
                }
            }
            #endregion ColRuleInclude
            #region ColRuleExclude
            ElseIf ($RType.ToLower() -eq "exclude") {
                $colQry = @()
                $colQry = ($strRuleQuery).Split(",")

                ForEach ($elt In $colQry) {
                    try {
                        $objResource = . "Get-CM$($CollectionTypeName)Collection" -Name $elt
                        
                        If ($objResource -ne $null) {
                            # Call Add-CMUserCollectionExcludeMembershipRule or Add-CMDeviceCollectionExcludeMembershipRule cmdlet depending the need
                            . "Add-CM$($CollectionTypeName)CollectionExcludeMembershipRule" -CollectionID $Collection.CollectionID -ExcludeCollection $objResource
                            Write-Log "Collection Exclude Rule for [$elt] added"
                        }
                        Else {
                            Write-Log "Collection [$elt] wasn't found! Can't add Exclude Rule $($i+1)" warning
                        }
                    }
                    catch {
                        Write-Log "Collection Include Rule $($i+1) can't be added for [$elt]! $($_.Exception.Message)" error
                    }
                }
            }
            #endregion ColRuleExclude
            Else {
                Write-Log "Rule Type [$RType] is invalid! Skip" warning
            }
        }
        Else {
            Write-Log "No Collection Query was filled in the CSV file for the Rule [$RType] n°$($i+1)" warning
        }

        $i++
    }
}

Function Set-CollectionSchedule {
    [CmdletBinding()]
    Param (
	    [Parameter(Mandatory=$true)][String] $Value
    )

    # Default SCCM Schedule to set
    $objSchedule = @{
        RefreshInterval = "days"
        RefreshCount = 7
        RefreshType = 4
    }

    If ($Value.Length -ge 2) {
        $refreshCheck    = $Value.SubString(0,1)
        $refreshInterval = $Value.Length - $refreshCheck.Length
        $refreshTime     = $Value.SubString($Value.Length - $refreshInterval, $refreshInterval)

        If ($refreshCheck.ToLower() -eq "m") {
            $objSchedule.RefreshInterval = "minutes"
            If ($refreshTime -match "^([1-9]|[1-5][0-9])$") {
                $objSchedule.RefreshCount = [int]$refreshTime
            }
            Else {
                $objSchedule.RefreshCount = 59
                Write-Log "No valid time entered" warning
            }
        }
        ElseIf ($refreshCheck.ToLower() -eq "h") {
            $objSchedule.RefreshInterval = "hours"
            If ($refreshTime -match "^([1-9]|1[0-9]|2[0-3])$") {
                $objSchedule.RefreshCount = [int]$refreshTime
            }
            Else {
                $objSchedule.RefreshCount = 3
                Write-Log "No valid time entered" warning
            }
        }
        ElseIf ($refreshCheck.ToLower() -eq "d") {
            $objSchedule.RefreshInterval = "days"
            If ($refreshTime -match "^([1-9]|[12][0-9]|3[01])$") {
                $objSchedule.RefreshCount = [int]$refreshTime
            }
            Else {
                Write-Log "No valid time entered" warning
            }
        }
        Else {
            Write-Log "No valid time entered" warning
        }

        $objSchedule.RefreshType = 2
        Write-Log "RefreshSchedule defined to $($objSchedule.RefreshCount) $($objSchedule.RefreshInterval)"
    }
    Else {
        $objSchedule.RefreshType = 4 # Use Incremental Updates
        Write-Log "RefreshSchedule should be 2 characters long and in the format of <letter><number>! [Incremental Updates] defined" error
    }

    return $objSchedule
}


Function Add-CollectionPermission {
    [CmdletBinding()]
    Param (
	    [Parameter(Mandatory=$true)] $Collection,
        [Parameter(Mandatory=$true)][String] $User
    )

    $arrUsers = @(($User -split ",").Trim())

    ForEach ($strUser in $arrUsers) {
        $objUser = Get-CMAdministrativeUser -Name $strUser
        If ($objUser -ne $null) {
            try {
                Add-CMCollectionToAdministrativeUser -InputObject $Collection -User $objUser
                Write-Log "Collection granted to Administrative User [$strUser]"
            }
            catch {
                Write-Log "Collection can't be granted to Administrative User [$strUser]! $($_.Exception.Message)" error
            }
        }
        Else {
            Write-Log "Administrative User [$strUser] wasn't found! Cannot grant it to collection" warning
        }
    }
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

If (!(Test-Path $csv_path)) {
    Write-Log "$csv_path File was not found! Exit" error
    Write-Log "end" stop
    Exit
}

# Import the CSV file
try {
    $script:csv_import = Import-Csv $csv_path -Delimiter ";"
}
catch {
    Write-Log "Error during $csv_import import! $($_.Exception.Message)" error
    Write-Log "end" stop
    Exit
}

# Initialize location for managing ConfigMgr! MANDATORY before continue
$InitialLocation = Get-Location
Set-Location "$($sitecode):"

# Manage collections according to CSV import
try {
    Start-CollectionManagement
}
finally {
    Write-Log "$($objResult.Success) Success, $($objResult.Warning) Warnings, $($objResult.Error) Errors"
    Write-Log "end" stop

    # Reset the location to the previous state
    Set-Location $InitialLocation.Path
}
