# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
#                                                                        Florian Valente - bcdeployment.wordpress.com
#  Usage:
#   Save the file as SCCM-Commands.psm1
#   PS:>Import-Module SCCM-Commands
#   PS:>Get-SCCMCommands
#
#  2009-04-07   Michael Niehaus     Original code posted at http://blogs.technet.com/mniehaus/
#  2010-03-10   Rikard Ronnkvist    Major makeover and first snowland.se release
#  2010-03-23   Rikard Ronnkvist    Fixed some small bugs and added limitToCollectionId in Add-SCCMCollectionRule
#  2010-03-26   Rikard Ronnkvist    New function: New-SCCMPackage
#  2010-09-13   Rikard Ronnkvist    Bugfixes to Add-SCCMCollectionRule and Get-SCCMCollectionMembers (Thanks to comments on snowland.se from Milos and Luigi)
#  2010-10-06   Stefan Ringler      New and updated functions from http://www.stefanringler.com/?p=150 (New-SCCMPackage, New-SCCMAdvertisement, New-SCCMProgram, Add-SCCMDistributionPoint)
#  2010-10-29   Rikard Ronnkvist    New functions: Update-SCCMDriverPkgSourcePath, Update-SCCMPackageSourcePath, Update-SCCMDriverSourcePath
#  2013-02-26   Florian Valente     New functions: Get-SCCMDCMAssignment, Get-SCCMReport, Get-SCCMSUMDeploymentTemplate, Get-SCCMSUMUpdatesInfo, Get-SCCMTaskSequence, Import-SCCMTaskSequence,
#                                   Export-SCCMTaskSequence, Copy-SCCMTaskSequence, New-SCCMSUMDeploymentTemplate, Remove-SCCMCollection, Remove-SCCMCollectionRule, Remove-SCCMAdvertisement,
#                                   Remove-SCCMPackage, Remove-SCCMTaskSequence, Remove-SCCMBootImagePackage, Remove-SCCMDriverPackage, Remove-SCCMReport, Remove-SCCMSUMDeploymentTemplate, Clear-SCCMLastPXEAdvertisement
#                                   Updated functions: Add-SCCMDirUserCollectionRule, Get-SCCMComputer, New-SCCMAdvertisement, Get-SCCMTaskSequence
#                                   Commented all functions
#                                   Added and adapted functions of Jeremy Young about SCCM Collection Variables management
#                                   Added New-SCCMAppVPackage function of Stephane Van Gulick
#  2013-03-08   Florian Valente     New functions: Get-SCCMFolder, Get-SCCMFolderNode, New-SCCMFolder, Remove-SCCMFolder
#                                   Updated functions: New-SCCMAdvertisement, New-SCCMPackage, Import-SCCMTaskSequence
#  2013-03-14   Florian Valente     New function: Get-SCCMIsR3
#                                   Updated function: New-SCCMCollection
#
# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

Function Get-SCCMCommands {
    <#
    .SYNOPSIS
        List all SCCM-commands
    .EXAMPLE
        Get-SCCMCommands
    .NOTES 
        -Author: Florian Valente
        -LastModifiedDate: 2013/03/14
        -Version: 10.0
    .LINK
        Actual version: http://bcdeployment.wordpress.com/

        Original version: http://blogs.technet.com/mniehaus/
        Updated version: http://www.snowland.se/sccm-posh/
        Added link 1: http://myitforum.com/cs2/blogs/jeremyyoung/
        Added link 2: http://www.powershellDistrict.com/
    #>
    [CmdletBinding()]
    PARAM ()
    PROCESS {
        return Get-Command -Name *-SCCM* -CommandType Function  | Sort-Object Name | Format-Table Name, Module
    }
}
 
Function Connect-SCCMServer {
    <#
    .SYNOPSIS
        Connect to one SCCM server
    .EXAMPLE
        $sccm = Connect-SCCMServer <Server_name>
    .EXAMPLE
        $secPwd = ConvertTo-SecureString "<Password>" -AsPlainText -Force
        $creds = New-Object System.Management.Automation.PSCredential("<User_name>", $secPwd)
        $sccm = Connect-SCCMServer -HostName <Server_name> -Credential $creds
    #>
    [CmdletBinding()]
    PARAM (
        [Parameter(Mandatory=$false,HelpMessage="SCCM Server Name or FQDN",ValueFromPipeline=$true)][Alias("ServerName","FQDN","ComputerName")][String] $HostName = (Get-Content env:computername),
        [Parameter(Mandatory=$false,HelpMessage="Optional SCCM Site Code",ValueFromPipelineByPropertyName=$true )][String] $SiteCode = $null,
        [Parameter(Mandatory=$false,HelpMessage="Credentials to use" )][System.Management.Automation.PSCredential] $Credential = $null
    )
 
    PROCESS {
        # Get the pointer to the provider for the site code
        if ($SiteCode -eq $null -or $SiteCode -eq "") {
            Write-Verbose "Getting provider location for default site on server $HostName"
            if ($Credential -eq $null) {
                $sccmProviderLocation = Get-WmiObject -query "select * from SMS_ProviderLocation where ProviderForLocalSite = true" -Namespace "root\sms" -computername $HostName -errorAction Stop
            } else {
                $sccmProviderLocation = Get-WmiObject -query "select * from SMS_ProviderLocation where ProviderForLocalSite = true" -Namespace "root\sms" -computername $HostName -credential $Credential -errorAction Stop
            }
        } else {
            Write-Verbose "Getting provider location for site $siteCode on server $HostName"
            if ($Credential -eq $null) {
                $sccmProviderLocation = Get-WmiObject -query "SELECT * FROM SMS_ProviderLocation where SiteCode = '$SiteCode'" -Namespace "root\sms" -computername $HostName -errorAction Stop
            } else {
                $sccmProviderLocation = Get-WmiObject -query "SELECT * FROM SMS_ProviderLocation where SiteCode = '$SiteCode'" -Namespace "root\sms" -computername $HostName -credential $Credential -errorAction Stop
            }
        }
 
        # Split up the namespace path
        $parts = $sccmProviderLocation.NamespacePath -split "\\", 4
        Write-Verbose "Provider is located on $($sccmProviderLocation.Machine) in namespace $($parts[3])"
 
        # Create a new object with information
        $retObj = New-Object -TypeName System.Object
        $retObj | add-Member -memberType NoteProperty -name Machine -Value $HostName
        $retObj | add-Member -memberType NoteProperty -name Namespace -Value $parts[3]
        $retObj | add-Member -memberType NoteProperty -name SccmProvider -Value $sccmProviderLocation
 
        return $retObj
    }
}
 
Function Get-SCCMObject {
    <#
    .SYNOPSIS
        Generic query tool
    .EXAMPLE
        Get-SCCMObject -SccmServer $sccm -Class "SMS_Collection"
    .EXAMPLE
        Get-SCCMObject -SccmServer $sccm -Class "SMS_Package" -Filter "PackageID='xxxxxxxx'"
    #>
    [CmdletBinding()]
    PARAM (
        [Parameter(Mandatory=$true, HelpMessage="SCCM Server",ValueFromPipelineByPropertyName=$true)][Alias("Server","SmsServer")][System.Object] $SccmServer,
        [Parameter(Mandatory=$true, HelpMessage="SCCM Class to query",ValueFromPipeline=$true)][Alias("Table","View")][String] $class,
        [Parameter(Mandatory=$false,HelpMessage="Optional Filter on query")][String] $Filter = $null
    )
 
    PROCESS {
        if ($Filter -eq $null -or $Filter -eq "")
        {
            Write-Verbose "WMI Query: SELECT * FROM $class"
            $retObj = get-wmiobject -class $class -computername $SccmServer.Machine -namespace $SccmServer.Namespace
        }
        else
        {
            Write-Verbose "WMI Query: SELECT * FROM $class WHERE $Filter"
            $retObj = get-wmiobject -query "SELECT * FROM $class WHERE $Filter" -computername $SccmServer.Machine -namespace $SccmServer.Namespace
        }
 
        return $retObj
    }
}

Function Get-SCCMPackage {
    <#
    .SYNOPSIS
        Get SCCM Package
    .EXAMPLE
        Returns all packages from a $sccm site
        Get-SCCMPackage -SccmServer $sccm
    .EXAMPLE
        Returns a specific package from a $sccm site
        Get-SCCMPackage -SccmServer $sccm -Filter "PackageID='xxxxxxxx'"
    #>
    [CmdletBinding()]
    PARAM (
        [Parameter(Mandatory=$true, HelpMessage="SCCM Server",ValueFromPipeline=$true)][Alias("Server","SmsServer")][System.Object] $SccmServer,
        [Parameter(Mandatory=$false, HelpMessage="Optional Filter on query")][String] $Filter = $null
    )
 
    PROCESS {
        return Get-SCCMObject -sccmServer $SccmServer -class "SMS_Package" -Filter $Filter
    }
}
 
Function Get-SCCMCollection {
    <#
    .SYNOPSIS
        Get SCCM Collection
    .EXAMPLE
        Returns all collections from a $sccm site
        Get-SCCMCollection -SccmServer $sccm
    .EXAMPLE
        Returns a specific collection from a $sccm site
        Get-SCCMCollection -SccmServer $sccm -Filter "CollectionID='xxxxxxxx'"
    #>
    [CmdletBinding()]
    PARAM (
        [Parameter(Mandatory=$true, HelpMessage="SCCM Server",ValueFromPipeline=$true)][Alias("Server","SmsServer")][System.Object] $SccmServer,
        [Parameter(Mandatory=$false, HelpMessage="Optional Filter on query")][String] $Filter = $null
    )
 
    PROCESS {
        return Get-SCCMObject -sccmServer $SccmServer -class "SMS_Collection" -Filter $Filter
    }
}
 
Function Get-SCCMAdvertisement {
    <#
    .SYNOPSIS
        Get SCCM Advertisement
    .EXAMPLE
        Returns all advertisement from a $sccm site
        Get-SCCMAdvertisement -SccmServer $sccm
    .EXAMPLE
        Returns a specific advertisement from a $sccm site
        Get-SCCMAdvertisement -SccmServer $sccm -Filter "AdvertisementID='xxxxxxxx'"
    #>
    [CmdletBinding()]
    PARAM (
        [Parameter(Mandatory=$true, HelpMessage="SCCM Server",ValueFromPipeline=$true)][Alias("Server","SmsServer")][System.Object] $SccmServer,
        [Parameter(Mandatory=$false, HelpMessage="Optional Filter on query")][String] $Filter = $null
    )
 
    PROCESS {
        return Get-SCCMObject -sccmServer $SccmServer -class "SMS_Advertisement" -Filter $Filter
    }
}
 
Function Get-SCCMDriver {
    <#
    .SYNOPSIS
        Get SCCM Driver
    .EXAMPLE
        Returns all drivers from a $sccm site
        Get-SCCMDriver -SccmServer $sccm
    .EXAMPLE
        Returns all drivers enabled from a $sccm site
        Get-SCCMDriver -SccmServer $sccm -Filter "IsEnabled='TRUE'"
    #>
    [CmdletBinding()]
    PARAM (
        [Parameter(Mandatory=$true, HelpMessage="SCCM Server",ValueFromPipeline=$true)][Alias("Server","SmsServer")][System.Object] $SccmServer,
        [Parameter(Mandatory=$false, HelpMessage="Optional Filter on query")][String] $Filter = $null
    )
 
    PROCESS {
        return Get-SCCMObject -sccmServer $SccmServer -class "SMS_Driver" -Filter $Filter
    }
}
 
Function Get-SCCMDriverPackage {
    <#
    .SYNOPSIS
        Get SCCM Driver Package
    .EXAMPLE
        Returns all driver packages from a $sccm site
        Get-SCCMDriverPackage -SccmServer $sccm
    .EXAMPLE
        Returns a specific driver package from a $sccm site
        Get-SCCMDriverPackage -SccmServer $sccm -Filter "PackageID='xxxxxxxx'"
    #>
    [CmdletBinding()]
    PARAM (
        [Parameter(Mandatory=$true, HelpMessage="SCCM Server",ValueFromPipeline=$true)][Alias("Server","SmsServer")][System.Object] $SccmServer,
        [Parameter(Mandatory=$false, HelpMessage="Optional Filter on query")][String] $Filter = $null
    )
 
    PROCESS {
        return Get-SCCMObject -sccmServer $SccmServer -class "SMS_DriverPackage" -Filter $Filter
    }
}
 
Function Get-SCCMTaskSequence {
    <#
    .SYNOPSIS
        Get SCCM Task Sequence
    .EXAMPLE
        Returns all task sequences from a $sccm site
        Get-SCCMTaskSequence -SccmServer $sccm
    .EXAMPLE
        Returns a specific package from a $sccm site
        Get-SCCMTaskSequence -SccmServer $sccm -Filter "PackageID='xxxxxxxx'"
    #>
    [CmdletBinding()]
    PARAM (
        [Parameter(Mandatory=$true, HelpMessage="SCCM Server",ValueFromPipeline=$true)][Alias("Server","SmsServer")][System.Object] $SccmServer,
        [Parameter(Mandatory=$false, HelpMessage="Optional Filter on query")][String] $Filter = $null
    )
 
    PROCESS {
        return Get-SCCMObject -sccmServer $SccmServer -class "SMS_TaskSequencePackage" -Filter $Filter
    }
}
 
Function Get-SCCMSite {
    <#
    .SYNOPSIS
        Get SCCM Site
    .EXAMPLE
        Returns all sites
        Get-SCCMSite -SccmServer $sccm
    .EXAMPLE
        Returns a specific site
        Get-SCCMSite -SccmServer $sccm -Filter "SiteCode='xxxxxxxx'"
    #>
    [CmdletBinding()]
    PARAM (
        [Parameter(Mandatory=$true, HelpMessage="SCCM Server",ValueFromPipeline=$true)][Alias("Server","SmsServer")][System.Object] $SccmServer,
        [Parameter(Mandatory=$false, HelpMessage="Optional Filter on query")][String] $Filter = $null
    )
 
    PROCESS {
        return Get-SCCMObject -sccmServer $SccmServer -class "SMS_Site" -Filter $Filter
    }
}
 
Function Get-SCCMImagePackage {
    <#
    .SYNOPSIS
        Get SCCM Image Package
    .EXAMPLE
        Returns all image packages from a $sccm site
        Get-SCCMImagePackage -SccmServer $sccm
    .EXAMPLE
        Returns a specific image package from a $sccm site
        Get-SCCMImagePackage -SccmServer $sccm -Filter "PackageID='xxxxxxxx'"
    #>
    [CmdletBinding()]
    PARAM (
        [Parameter(Mandatory=$true, HelpMessage="SCCM Server",ValueFromPipeline=$true)][Alias("Server","SmsServer")][System.Object] $SccmServer,
        [Parameter(Mandatory=$false, HelpMessage="Optional Filter on query")][String] $Filter = $null
    )
 
    PROCESS {
        return Get-SCCMObject -sccmServer $SccmServer -class "SMS_ImagePackage" -Filter $Filter
    }
}
 
Function Get-SCCMOperatingSystemInstallPackage {
    <#
    .SYNOPSIS
        Get SCCM Operating System Install Package
    .EXAMPLE
        Returns all operating system install packages from a $sccm site
        Get-SCCMOperatingSystemImagePackage -SccmServer $sccm
    .EXAMPLE
        Returns a specific operating system install package from a $sccm site
        Get-SCCMOperatingSystemImagePackage -SccmServer $sccm -Filter "PackageID='xxxxxxxx'"
    #>
    [CmdletBinding()]
    PARAM (
        [Parameter(Mandatory=$true, HelpMessage="SCCM Server",ValueFromPipeline=$true)][Alias("Server","SmsServer")][System.Object] $SccmServer,
        [Parameter(Mandatory=$false, HelpMessage="Optional Filter on query")][String] $Filter = $null
    )
 
    PROCESS {
        return Get-SCCMObject -sccmServer $SccmServer -class "SMS_OperatingSystemInstallPackage" -Filter $Filter
    }
}
 
Function Get-SCCMBootImagePackage {
    <#
    .SYNOPSIS
        Get SCCM Boot Image Package
    .EXAMPLE
        Returns all boot image packages from a $sccm site
        Get-SCCMBootImagePackage -SccmServer $sccm
    .EXAMPLE
        Returns a specific boot image package from a $sccm site
        Get-SCCMBootImagePackage -SccmServer $sccm -Filter "PackageID='xxxxxxxx'"
    #>
    [CmdletBinding()]
    PARAM (
        [Parameter(Mandatory=$true, HelpMessage="SCCM Server",ValueFromPipeline=$true)][Alias("Server","SmsServer")][System.Object] $SccmServer,
        [Parameter(Mandatory=$false, HelpMessage="Optional Filter on query")][String] $Filter = $null
    )
 
    PROCESS {
        return Get-SCCMObject -sccmServer $SccmServer -class "SMS_BootImagePackage" -Filter $Filter
    }
}
 
# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
 
Function Get-SCCMComputer {
    <#
    .SYNOPSIS
        Get SCCM Computer
    .EXAMPLE
        Returns all computers from a $sccm site
        Get-SCCMComputer -SccmServer $sccm
    .EXAMPLE
        Returns a specific computer from a $sccm site
        Get-SCCMComputer -SccmServer $sccm -NetBiosName "SERVER-2008-01"
    .EXAMPLE
        Returns all obsolete computers from a $sccm site
        Get-SCCMComputer -SccmServer $sccm -Obsolete
    #>
    [CmdletBinding()]
    PARAM (
        [Parameter(Mandatory=$true, HelpMessage="SCCM Server")][Alias("Server","SmsServer")][System.Object] $SccmServer,
        [Parameter(Mandatory=$false, HelpMessage="Filter on SCCM Resource ID",ValueFromPipelineByPropertyName=$true)][int32] $ResourceID = $false,
        [Parameter(Mandatory=$false, HelpMessage="Filter on Netbiosname on computer",ValueFromPipeline=$true)][String] $NetbiosName = "",
        [Switch] $Obsolete
        #[Parameter(Mandatory=$false, HelpMessage="Filter on Domain name",ValueFromPipelineByPropertyName=$true)][Alias("Domain", "Workgroup")][String] $ResourceDomainOrWorkgroup = "",
        #[Parameter(Mandatory=$false, HelpMessage="Filter on SmbiosGuid (UUID)")][String] $SmBiosGuid = ""
    )
 
    PROCESS {
        if ($Obsolete) {
            return Get-SCCMObject -sccmServer $SccmServer -class "SMS_R_System" -Filter "Obsolete = 1"
        }
        
        #if ($ResourceID -eq $false -and $NetbiosName -eq "" -and $ResourceDomainOrWorkgroup -eq "" -and $SmBiosGuid -eq "%") {
        if ($ResourceID -eq $false -and $NetbiosName -eq "") {
             $Host.UI.WriteErrorLine("Need at least one filter...")
        }
 
        if ($ResourceID -eq $false) {
            #return Get-SCCMObject -sccmServer $SccmServer -class "SMS_R_System" -Filter "NetbiosName = '$NetbiosName' AND ResourceDomainOrWorkgroup LIKE '$ResourceDomainOrWorkgroup' AND SmBiosGuid LIKE '$SmBiosGuid'"
            return Get-SCCMObject -sccmServer $SccmServer -class "SMS_R_System" -Filter "NetbiosName = '$NetbiosName'"
        }
        else {
            return Get-SCCMObject -sccmServer $SccmServer -class "SMS_R_System" -Filter "ResourceID = $ResourceID"
        }
    }
}
 
Function Get-SCCMUser {
    <#
    .SYNOPSIS
        Get SCCM User
        Be sure that Active Directory User Discovery is enabled
    .EXAMPLE
        Returns all users from a $sccm site
        Get-SCCMUser -SccmServer $sccm
    .EXAMPLE
        Returns a specific user from a $sccm site
        Get-SCCMUser -SccmServer $sccm -UserName "AdminSccm"
    #>
    [CmdletBinding()]
    PARAM (
        [Parameter(Mandatory=$true, HelpMessage="SCCM Server")][Alias("Server","SmsServer")][System.Object] $SccmServer,
        [Parameter(Mandatory=$false, HelpMessage="Filter on SCCM Resource ID",ValueFromPipelineByPropertyName=$true)][int32] $ResourceID = $false,
        [Parameter(Mandatory=$false, HelpMessage="Filter on unique username in form DOMAIN\UserName",ValueFromPipelineByPropertyName=$true)][String] $UniqueUserName = "%",
        [Parameter(Mandatory=$false, HelpMessage="Filter on Domain name",ValueFromPipelineByPropertyName=$true)][Alias("Domain")][String] $WindowsNTDomain = "%",
        [Parameter(Mandatory=$false, HelpMessage="Filter on UserName",ValueFromPipeline=$true)][String] $UserName = "%"
    )
 
    PROCESS {
        if ($ResourceID -eq $false -and $UniqueUserName -eq "%" -and $WindowsNTDomain -eq "%" -and $UserName -eq "%") {
            throw "Need at least one filter..."
        }
 
        if ($ResourceID -eq $false) {
            return Get-SCCMObject -sccmServer $SccmServer -class "SMS_R_User" -Filter "UniqueUserName LIKE '$UniqueUserName' AND WindowsNTDomain LIKE '$WindowsNTDomain' AND UserName LIKE '$UserName'"
        } else {
            return Get-SCCMObject -sccmServer $SccmServer -class "SMS_R_User" -Filter "ResourceID = $ResourceID"
        }
    }
}
 
Function Get-SCCMCollectionMembers {
    <#
    .SYNOPSIS
        Get SCCM Collection Members
    .EXAMPLE
        Returns all collection members from a $sccm site
        Get-SCCMCollectionMembers -SccmServer $sccm
    .EXAMPLE
        Returns members of a collection from a $sccm site
        Get-SCCMCollectionMembers -SccmServer $sccm -CollectionID "xxxxxxxx"
    #>
    [CmdletBinding()]
    PARAM (
        [Parameter(Mandatory=$true, HelpMessage="SCCM Server")][Alias("Server","SmsServer")][System.Object] $SccmServer,
        [Parameter(Mandatory=$false, HelpMessage="CollectionID", ValueFromPipeline=$true)][String] $CollectionID
    )
 
    PROCESS {
        return Get-SCCMObject -sccmServer $SccmServer -class "SMS_CollectionMember_a" -Filter "CollectionID = '$CollectionID'"
    }
}
 
Function Get-SCCMSubCollections {
    <#
    .SYNOPSIS
        Get SCCM Sub Collections
    .EXAMPLE
        Returns all sub collections of a collection from a $sccm site
        Get-SCCMSubCollections -SccmServer $sccm -CollectionID "xxxxxxxx"
    #>
    [CmdletBinding()]
    PARAM (
        [Parameter(Mandatory=$true, HelpMessage="SCCM Server")][Alias("Server","SmsServer")][System.Object] $SccmServer,
        [Parameter(Mandatory=$true, HelpMessage="CollectionID",ValueFromPipeline=$true)][Alias("parentCollectionID")][String] $CollectionID
    )
 
    PROCESS {
        return Get-SCCMObject -sccmServer $SccmServer -class "SMS_CollectToSubCollect" -Filter "parentCollectionID = '$CollectionID'"
    }
}
 
Function Get-SCCMParentCollection {
    <#
    .SYNOPSIS
        Get SCCM Parent Collection
    .EXAMPLE
        Returns the parent collection of a collection from a $sccm site
        Get-SCCMParentCollection -SccmServer $sccm -CollectionID "xxxxxxxx"
    #>
    [CmdletBinding()]
    PARAM (
        [Parameter(Mandatory=$true, HelpMessage="SCCM Server")][Alias("Server","SmsServer")][System.Object] $SccmServer,
        [Parameter(Mandatory=$true, HelpMessage="CollectionID",ValueFromPipeline=$true)][Alias("subCollectionID")][String] $CollectionID
    )
 
    PROCESS {
        $parentCollection = Get-SCCMObject -sccmServer $SccmServer -class "SMS_CollectToSubCollect" -Filter "subCollectionID = '$CollectionID'"
 
        return Get-SCCMCollection -sccmServer $SccmServer -Filter "CollectionID = '$($parentCollection.parentCollectionID)'"
    }
}
 
Function Get-SCCMSiteDefinition {
    <#
    .SYNOPSIS
        Get all definitions for one SCCM site
    .EXAMPLE
        Get-SCCMSiteDefinition -SccmServer $sccm
    #>
    [CmdletBinding()]
    PARAM (
        [Parameter(Mandatory=$true, HelpMessage="SCCM Server",ValueFromPipeline=$true)][Alias("Server","SmsServer")][System.Object] $SccmServer
    )
 
    PROCESS {
        Write-Verbose "Refresh the site $($SccmServer.SccmProvider.SiteCode) control file"
        Invoke-WmiMethod -path SMS_SiteControlFile -name RefreshSCF -argumentList $($SccmServer.SccmProvider.SiteCode) -computername $SccmServer.Machine -namespace $SccmServer.Namespace
 
        Write-Verbose "Get the site definition object for this site"
        return get-wmiobject -query "SELECT * FROM SMS_SCI_SiteDefinition WHERE SiteCode = '$($SccmServer.SccmProvider.SiteCode)' AND FileType = 2" -computername $SccmServer.Machine -namespace $SccmServer.Namespace
    }
}
 
Function Get-SCCMSiteDefinitionProps {
    <#
    .SYNOPSIS
        Get definition properties for one SCCM site
    .EXAMPLE
        Get-SCCMSiteDefinitionProps -SccmServer $sccm
    #>
    [CmdletBinding()]
    PARAM (
        [Parameter(Mandatory=$true, HelpMessage="SCCM Server",ValueFromPipeline=$true)][Alias("Server","SmsServer")][System.Object] $SccmServer
    )
 
    PROCESS {
        return Get-SCCMSiteDefinition -sccmServer $SccmServer | ForEach-Object { $_.Props }
    }
}
 
Function Get-SCCMIsR2 {
    <#
    .SYNOPSIS
        Return $true if the SCCM server is R2 capable
    .EXAMPLE
        Get-SCCMIsR2 -SccmServer $sccm
    #>
    [CmdletBinding()]
    PARAM (
        [Parameter(Mandatory=$true, HelpMessage="SCCM Server",ValueFromPipeline=$true)][Alias("Server","SmsServer")][System.Object] $SccmServer
    )
 
    PROCESS {
        $result = Get-SCCMSiteDefinitionProps -sccmServer $SccmServer | ? {$_.PropertyName -eq "IsR2CapableRTM"}
        if (-not $result) {
            return $false
        } elseif ($result.Value = 31) {
            return $true
        } else {
            return $false
        }
    }
}

Function Get-SCCMIsR3 {
    <#
    .SYNOPSIS
        Return $true if the SCCM server is R3 capable
    .EXAMPLE
        Get-SCCMIsR3 -SccmServer $sccm
    #>
    [CmdletBinding()]
    PARAM (
        [Parameter(Mandatory=$false, HelpMessage="SCCM Server",ValueFromPipeline=$true)][Alias("Server","SmsServer")][System.Object] $SccmServer
    )
 
    PROCESS {
        # No property found in WMI to check if R3 capable... So passed by registry
        $result = Get-ChildItem "HKLM:\SOFTWARE\Wow6432Node\Microsoft\SMS\R3\" -ErrorAction SilentlyContinue
        if (-not $result) {
            return $false
        } else {
            return $true
        }
    }
}
 
Function Get-SCCMCollectionRules {
    <#
    .SYNOPSIS
        Get Collection rules
    .EXAMPLE
        Returns all collection rules from a $sccm site
        Get-SCCMCollectionRules -SccmServer $sccm
    .EXAMPLE
        Returns all collection rules of a collection from a $sccm site
        Get-SCCMCollectionRules -SccmServer $sccm -CollectionID "xxxxxxxx"
    #>
    [CmdletBinding()]
    PARAM (
        [Parameter(Mandatory=$true, HelpMessage="SCCM Server")][Alias("Server","SmsServer")][System.Object] $SccmServer,
        [Parameter(Mandatory=$false, HelpMessage="CollectionID", ValueFromPipeline=$true)][String] $CollectionID
    )
 
    PROCESS {
        Write-Verbose "Collecting rules for $CollectionID"
        $col = [wmi]"$($SccmServer.SccmProvider.NamespacePath):SMS_Collection.CollectionID='$($CollectionID)'"
 
        return $col.CollectionRules
    }
}
 
Function Get-SCCMInboxes {
    <#
    .SYNOPSIS
        Give a count of files in the SCCM-inboxes
    .EXAMPLE
        Get-SCCMInboxes -SccmServer $sccm
    #>
    [CmdletBinding()]
    PARAM (
        [Parameter(Mandatory=$true, HelpMessage="SCCM Server",ValueFromPipeline=$true)][Alias("Server","SmsServer")][System.Object] $SccmServer,
        [Parameter(Mandatory=$false, HelpMessage="Minimum number of files in directory")][int32] $minCount = 1
    )
 
    PROCESS {
        Write-Verbose "Reading \\$($SccmServer.Machine)\SMS_$($SccmServer.SccmProvider.SiteCode)\inboxes"
        return Get-ChildItem \\$($SccmServer.Machine)\SMS_$($SccmServer.SccmProvider.SiteCode)\inboxes -Recurse | Group-Object Directory | Where { $_.Count -gt $minCount } | Format-Table Count, Name -AutoSize
    }
}
# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
 
Function New-SCCMCollection {
    <#
    .SYNOPSIS
        Create a new SCCM Collection
    .EXAMPLE
        Create a default collection
        New-SCCMCollection -SccmServer $sccm -Name "TEST"
    .EXAMPLE
        Create a sub collection a the collection "TEST" with specific refresh rates
        $colTest = Get-SCCMCollection -SccmServer $sccm -Filter "Name='TEST'"
        New-SCCMCollection -SccmServer $sccm -Name "SUBTEST" -RefreshHours 8 -ParentCollectionID $colTest.CollectionID
    .EXAMPLE
        Create a default collection with dynamically add new resources (only for SCCM 2007 R3). Refresh parameter is mandatory
        New-SCCMCollection -SccmServer $sccm -Name "TEST" -RefreshDays 1 -DynamicAddResources
    #>
    [CmdletBinding()]
    PARAM (
        [Parameter(Mandatory=$true, HelpMessage="SCCM Server")][Alias("Server","SmsServer")][System.Object] $SccmServer,
        [Parameter(Mandatory=$true, HelpMessage="Collection Name", ValueFromPipeline=$true)][String] $Name,
        [Parameter(Mandatory=$false, HelpMessage="Collection comment")][String] $Comment = "",
        [Parameter(Mandatory=$false, HelpMessage="Refresh Rate in Minutes")] [ValidateRange(0, 59)][int] $RefreshMinutes = 0,
        [Parameter(Mandatory=$false, HelpMessage="Refresh Rate in Hours")] [ValidateRange(0, 23)][int] $RefreshHours = 0,
        [Parameter(Mandatory=$false, HelpMessage="Refresh Rate in Days")] [ValidateRange(0, 31)][int] $RefreshDays = 0,
        [Switch] $DynamicAddResources,
        [Parameter(Mandatory=$false, HelpMessage="Parent CollectionID")][String] $ParentCollectionID = "COLLROOT"
    )
 
    PROCESS {
        # Build the parameters for creating the collection
        $arguments = @{Name = $Name; Comment = $Comment; OwnedByThisSite = $true}
        $newColl = Set-WmiInstance -class "SMS_Collection" -arguments $arguments -computername $SccmServer.Machine -namespace $SccmServer.Namespace
 
        # Hack - for some reason without this we don't get the CollectionID value
        $hack = $newColl.PSBase | select * | out-null
 
        # It's really hard to set the refresh schedule via Set-WmiInstance, so we'll set it later if necessary
        if ($RefreshMinutes -gt 0 -or $RefreshHours -gt 0 -or $RefreshDays -gt 0)
        {
            Write-Verbose "Create the recur interval object"
            $intervalClass = [WMICLASS]"\\$($SccmServer.Machine)\$($SccmServer.Namespace):SMS_ST_RecurInterval"
            $interval = $intervalClass.CreateInstance()
            if ($RefreshMinutes -gt 0) {
                $interval.MinuteSpan = $RefreshMinutes
            }
            if ($RefreshHours -gt 0) {
                $interval.HourSpan = $RefreshHours
            }
            if ($RefreshDays -gt 0) {
                $interval.DaySpan = $RefreshDays
            }
 
            Write-Verbose "Set the refresh schedule"
            $newColl.RefreshSchedule = $interval
            if ($DynamicAddResources) {
                if (Get-SCCMIsR3) {
                    $newColl.RefreshType=6 # Only available in SCCM 2007 R3
                }
                else {
                    Write-Verbose "R3 is not installed! Dynamically add resources cannot be applied"
                    $newColl.RefreshType=2
                }
            } else {
                $newColl.RefreshType=2
            }
            $path = $newColl.Put()
        }   
 
        Write-Verbose "Setting the new $($newColl.CollectionID) parent to $parentCollectionID"
        $subArguments  = @{SubCollectionID = $newColl.CollectionID}
        $subArguments += @{ParentCollectionID = $ParentCollectionID}
 
        # Add the link
        $newRelation = Set-WmiInstance -Class "SMS_CollectToSubCollect" -arguments $subArguments -computername $SccmServer.Machine -namespace $SccmServer.Namespace
 
        Write-Verbose "Return the new collection with ID $($newColl.CollectionID)"
        return $newColl
    }
}
 
Function Add-SCCMCollectionRule {
    <#
    .SYNOPSIS
        Create a new SCCM Collection Rule
    .EXAMPLE
        Create a collection rule on the collection TEST based on a WQL query which filter all Windows 7 OS
        $colTest = Get-SCCMCollection -SccmServer $sccm -Filter "Name='TEST'"
        $query = "SELECT * FROM SMS_R_System WHERE OperatingSystemNameAndVersion like "%Workstation 6.1%"
        Add-SCCMCollectionRule -SccmServer $sccm -CollectionID $colTest.CollectionID -QueryExpression $query -QueryRuleName "All Windows 7 Systems"
    .EXAMPLE
        Add the resource CLI-WIN7-01 to the collection TEST
        $colTest = Get-SCCMCollection -SccmServer $sccm -Filter "Name='TEST'"
        Add-SCCMCollectionRule -SccmServer $sccm -CollectionID $colTest.CollectionID -Name "CLI-WIN7-01" -QueryRuleName "CLI-WIN7-01"
    #>
    [CmdletBinding()]
    PARAM (
        [Parameter(Mandatory=$true,  HelpMessage="SCCM Server")][Alias("Server","SmsServer")][System.Object] $SccmServer,
        [Parameter(Mandatory=$true,  HelpMessage="CollectionID", ValueFromPipelineByPropertyName=$true)][String] $CollectionID,
        [Parameter(Mandatory=$true,  HelpMessage="Rule Name", ValueFromPipeline=$true)][String] $RuleName,
        [Parameter(Mandatory=$false, HelpMessage="Computer name to add (direct)", ValueFromPipeline=$true)][String] $ResourceName,
        [Parameter(Mandatory=$false, HelpMessage="WQL Query Expression", ValueFromPipeline=$true)][String] $QueryExpression = $null,
        [Parameter(Mandatory=$false, HelpMessage="Limit to collection (Query)", ValueFromPipeline=$false)][String] $LimitToCollectionId = $null
    )
 
    PROCESS {
        # Get the specified collection (to make sure we have the lazy properties)
        $coll = [wmi]"$($SccmServer.SccmProvider.NamespacePath):SMS_Collection.CollectionID='$CollectionID'"
 
        # Build the new rule
        if ($QueryExpression.Length -gt 0) {
            # Create a query rule
            $ruleClass = [WMICLASS]"$($SccmServer.SccmProvider.NamespacePath):SMS_CollectionRuleQuery"
            $newRule = $ruleClass.CreateInstance()
            $newRule.RuleName = $RuleName
            $newRule.QueryExpression = $QueryExpression
            if ($LimitToCollectionId -ne $null) {
                $newRule.LimitToCollectionID = $LimitToCollectionId
            }
 
            $null = $coll.AddMembershipRule($newRule)
            Write-Verbose "Rule $RuleName created for the collection"
        } else {
            $ruleClass = [WMICLASS]"$($SccmServer.SccmProvider.NamespacePath):SMS_CollectionRuleDirect"
 
            # Find each computer
            $computer = Get-SCCMComputer -sccmServer $SccmServer -NetbiosName $ResourceName
            # See if the computer is already a member
            $found = $false
            if ($coll.CollectionRules -ne $null) {
                foreach ($member in $coll.CollectionRules) {
                    if ($member.ResourceID -eq $computer.ResourceID) {
                        $found = $true
                    }
                }
            }
            if (-not $found) {
                Write-Verbose "Adding new rule for computer $ResourceName"
                $newRule = $ruleClass.CreateInstance()
                $newRule.RuleName = $ResourceName
                $newRule.ResourceClassName = "SMS_R_System"
                $newRule.ResourceID = $computer.ResourceID
 
                $null = $coll.AddMembershipRule($newRule)
                Write-Verbose "Computer $ResourceName added to the collection"
            } else {
                Write-Verbose "Computer $ResourceName is already in the collection"
            }
        }
    }
}
 
Function Add-SCCMDirUserCollectionRule {
    <#
    .SYNOPSIS
        Add a user Rule to a collection
        Be sure that Active Directory User Discovery is enabled
    .EXAMPLE
        Add-SCCMDirUserCollectionRule -SccmServer $sccm -CollectionID "xxxxxxxx" -UserName "user1"
    #>
    [CmdletBinding()]
    PARAM (
        [Parameter(Mandatory=$true, HelpMessage="SCCM Server")][Alias("Server","SmsServer")][System.Object] $SccmServer,
        [Parameter(Mandatory=$true, ValueFromPipelineByPropertyName=$true, HelpMessage="SCCM Collection ID")][String] $CollectionID,
        [Parameter(Mandatory=$true, ValueFromPipeline=$true, HelpMessage="SCCM User Name")][String] $UserName
    )
 
    PROCESS {
        $coll = [wmi]"\\$($SccmServer.Machine)\$($SccmServer.Namespace):SMS_Collection.CollectionID='$CollectionID'"
        $ruleClass = [WMICLASS]"\\$($SccmServer.Machine)\$($SccmServer.Namespace):SMS_CollectionRuleDirect"
 
        #$RuleClass
        $UserRule = Get-SCCMUser -SccmServer $SccmServer -UserName $UserName
        if ($UserRule -eq $null) {
            $Host.UI.WriteErrorLine("No User found with the name $UserName. Exit")
            return
        }
        $NewRuleName=$UserRule.name
        $NewRuleResourceID = $UserRule.ResourceID
        $newRule = $ruleClass.CreateInstance()
 
        $newRule.RuleName = $NewRuleName
        $newRule.ResourceClassName = "SMS_R_User"
        $newRule.ResourceID = $NewRuleResourceID
 
        $null = $coll.AddMembershipRule($newRule)
        $coll.requestrefresh()
        Clear-Variable -name oldrule -errorAction SilentlyContinue
        Clear-Variable -name Coll -errorAction SilentlyContinue
    }
}
 
Function New-SCCMPackage {
    <#
    .SYNOPSIS
        Create a new SCCM Package
    .EXAMPLE
        Create a new package 7Zip
        New-SCCMPackage -SccmServer $sccm -Name "7Zip" -Version "1.0" -Language "English" -PkgSourcePath "\\sharedata\software\7zip"
    .EXAMPLE
        Create a new Package 7Zip under the folder "Tools"
        $folder = Get-SCCMFolder -SccmServer $sccm -Filter "Name='Deploy'" -FolderNodeID (Get-SCCMFolderNode -NodeName "Packages")
        New-SCCMPackage -SccmServer $sccm -Name "7Zip" -Version "1.0" -Language "English" -PkgSourcePath "\\sharedata\software\7zip" -FolderID $folder.ContainerNodeID
    #>
    [CmdletBinding()]
    PARAM (
        [Parameter(Mandatory=$true, HelpMessage="SCCM Server")][Alias("Server","SmsServer")][System.Object] $SccmServer,
        [Parameter(Mandatory=$true, HelpMessage="Package Name", ValueFromPipeline=$true)][String] $Name,
        [Parameter(Mandatory=$false, HelpMessage="Package Version")][String] $Version = "",
        [Parameter(Mandatory=$false, HelpMessage="Package Manufacturer")][String] $Manufacturer = "",
        [Parameter(Mandatory=$false, HelpMessage="Package Language")][String] $Language = "",
        [Parameter(Mandatory=$false, HelpMessage="Package Description")][String] $Description = "",
        [Parameter(Mandatory=$false, HelpMessage="Package Data Source Path")][String] $PkgSourcePath = "",
        [Parameter(Mandatory=$false, HelpMessage="Package Sharename")][String] $PkgShareName = "",
        [Parameter(Mandatory=$false, HelpMessage="Folder ID")][String] $FolderID = ""
    )
 
    PROCESS {
        $packageClass = [WMICLASS]"\\$($SccmServer.Machine)\$($SccmServer.Namespace):SMS_Package"
        $newPackage = $packageClass.createInstance() 
 
        $newPackage.Name = $Name
        if ($Version -ne "")        { $newPackage.Version = $Version }
        if ($Manufacturer -ne "")   { $newPackage.Manufacturer = $Manufacturer }
        if ($Language -ne "")       { $newPackage.Language = $Language }
        if ($Description -ne "")    { $newPackage.Description = $Description }
 
        if ($PkgSourcePath -ne "") {
            $newPackage.PkgSourceFlag = 2  # Direct (3 = Compressed)
            $newPackage.PkgSourcePath = $PkgSourcePath
            if ($PkgShareName -ne "") {
                $newPackage.ShareName = $PkgShareName
                $newPackage.ShareType = 2
            }
        } else {
            $newPackage.PkgSourceFlag = 1  # No source
            $newPackage.PkgSourcePath = $null
        }
        $newPackage.Put()
 
        if ($FolderID -ne "") {
            $folder = Get-SCCMFolder -sccmServer $SccmServer -Filter "ContainerNodeID='$FolderID'"
            if ($folder -ne $null) {
                if ($folder.ObjectType -eq 2) { # The folder is a Packages folder
                    $wmiObj = [wmiclass]("\\" + $SccmServer.Machine + "\" + $SccmServer.Namespace + ":SMS_ObjectContainerItem")
                    Write-Verbose "Moving the Package to the folder $($folder.Name)..."
                    $Instance = $wmiObj.CreateInstance()
                    $Instance.ContainerNodeID = $FolderID
                    $newPackage.Get()
                    $Instance.InstanceKey = $($newPackage.PackageID)
                    $Instance.ObjectType = "2"
                    $Instance.psbase.Put()
                    Write-Verbose "Package created successfully in the folder $($folder.Name)"
                }
                else {
                    Write-Host "The folder $($folder.Name) is not a Packages Folder! Package created on the default location."
                    Write-Verbose "Package created successfully"
                }
            }
            else {
                Write-Host "No folder with the ID $FolderID was found! Package created on the default location."
                Write-Verbose "Package created successfully"
            }
        }
        else {
            Write-Verbose "Package created successfully"
        }
        
        $newPackage.Get()
        Write-Verbose "Return the new package with ID $($newPackage.PackageID)"
        return $newPackage
    }
}
 
Function New-SCCMAdvertisement {
    <#
    .SYNOPSIS
        Create a new SCCM Advertisement
    .EXAMPLE
        Create an advertisement with default option for the package 7Zip, and affect it to collection TEST
        $colTest = Get-SCCMCollection -SccmServer $sccm -Filter "Name='TEST'"
        $pkg = Get-SCCMPackage -SccmServer $sccm -Filter "Name='7Zip'"
        New-SCCMadvertisement -SccmServer $sccm -AdvertisementName "Adv7Zip" -CollectionID $colTest.CollectionID -PackageID $pkg.PackageID -ProgramName "Install 7Zip"
    .EXAMPLE
        Create an advertisement for a task sequence with mandatory as soon as possible, priority high and rerun if failed. Download sources, include sub collections and show the progress bar
        $colTest = Get-SCCMCollection -SccmServer $sccm -Filter "Name='TEST'"
        $ts = Get-SCCMTaskSequence -SccmServer $sccm -Filter "Name='TS deploy'"
        New-SCCMAdvertisement -SccmServer $sccm -AdvertisementName "AdvTS" -CollectionID $colTest.CollectionID -IncludeSubCollection -PackageID $ts.PackageID -ProgramName "*" -MandatoryTime "asap" -Priority "High" -RerunBehavior "IfFailed" -Download -TSShowProgressBar
    .EXAMPLE
        Create an advertisement with default option for the package 7Zip, and affect it to collection TEST, in the folder "Deploy"
        $colTest = Get-SCCMCollection -SccmServer $sccm -Filter "Name='TEST'"
        $pkg = Get-SCCMPackage -SccmServer $sccm -Filter "Name='7Zip'"
        $folder = Get-SCCMFolder -SccmServer $sccm -Filter "Name='Deploy'" -FolderNodeID (Get-SCCMFolderNode -NodeName "Advertisements")
        New-SCCMadvertisement -SccmServer $sccm -AdvertisementName "Adv7Zip" -CollectionID $colTest.CollectionID -PackageID $pkg.PackageID -ProgramName "Install 7Zip" -FolderID $folder.ContainerNodeID
    #>
    [CmdletBinding()]
    PARAM (
        [Parameter(Mandatory=$true, HelpMessage="SCCM Server")][Alias("Server","SmsServer")][System.Object] $SccmServer,
        [Parameter(Mandatory=$true, HelpMessage="Advertisement Name")][String] $AdvertisementName,
        [Parameter(Mandatory=$true, HelpMessage="Collection ID")][String] $CollectionID,
        [Parameter(Mandatory=$true, HelpMessage="Package ID")][String] $PackageID,
        [Parameter(Mandatory=$true, HelpMessage="Program Name")][String] $ProgramName,
        [Parameter(Mandatory=$false, HelpMessage="Folder ID")][String] $FolderID,
        [Switch] $Download,
        [Switch] $IncludeSubCollection,
        [Parameter(Mandatory=$false, HelpMessage="Priority: Low, Medium or High")][String] $Priority = "Medium",
        [Parameter(Mandatory=$false, HelpMessage="Rerun Behavior: Always, Never, IfFailed, IfSucceeded")][String] $RerunBehavior = "Never",
        [Parameter(Mandatory=$false, HelpMessage="YYYYMMDDhhmm")] $StartTime,
        [Parameter(Mandatory=$false, HelpMessage="YYYYMMDDhhmm")] $EndTime,
        [Parameter(Mandatory=$false, HelpMessage="YYYYMMDDhhmm or asap, logon, logoff")] $MandatoryTime,
        [Switch] $EnableWOL,
        [Switch] $IgnoreMaintenance,
        [Switch] $AllowRestart,
        [Switch] $TSUseRemoteDP,
        [Switch] $TSUseUnprotectedDP,
        [Switch] $TSShowProgressBar
    )
    PROCESS {
        $strServer = $SccmServer.machine
        $strNamespace= $SccmServer.namespace
        $AdvClass = [WmiClass]("\\$strServer\" + "$strNameSpace" + ":SMS_Advertisement")
        # Definition of the RemoteClientFlags property
        
        # For flags values, refer to the technet: http://msdn.microsoft.com/en-us/library/cc146108.aspx
        $RemoteClientFlags = 0 # RemoteClientFlags
        $advFlags = 0 # AdvertFlags
        
        if ($Download) {
            if ($ProgramName -ne "*") {$RemoteClientFlags += 80} # Download from local DP + remote DP
            else {$RemoteClientFlags += 292} # TS: Download content locally when needed
        } else {
            if ($ProgramName -ne "*") {$RemoteClientFlags += 136} # Run from local DP + remote DP
            else {$RemoteClientFlags += 40} # TS: Access content directly from DP
        }
        if ($ProgramName -eq "*") { # It is a Task Sequence
            if ($TSUseRemoteDP) {$RemoteClientFlags += 32}#256}
            if (!($TSUseUnprotectedDP)) {$AdvFlags += 131072} # If NOT checked, increase AdvertFlags...
        }
        
        # Include sub collection or not
    	if ($IncludeSubCollection) {
            $IncSubCol = $true
        } else {
            $IncSubCol = $false
        }
        
    	if ($StartTime -ne $null) {
            $PresentTime = $StartTime + "00.000000+***"
        } else {
            $PresentTime = "20120110000000.000000+***"
        }
        
        if ($EndTime -ne $null) {
            $ExpirationTime = $Endtime + "00.000000+***"
            $ExpirationTimeEnabled = $true
        } else {
            $ExpirationTime = "20200113000000.000000+***"
            $ExpirationTimeEnabled = $false
        }
        
        # Definition of Deadline and advFlags properties
        if ($MandatoryTime -ne $null) {
            if ($MandatoryTime.ToLower() -eq "asap") {$advFlags += 32} # Mandatory assignment defined to As soon as possible
            elseif ($MandatoryTime.ToLower() -eq "logon") {$advFlags += 512} # Mandatory assignment defined to Log On
            elseif ($MandatoryTime.ToLower() -eq "logoff") {$advFlags += 1024} # Mandatory assignment defined to Log Off
            else {$Deadline = $MandatoryTime + "00.000000+***"}
            $advFlags += 33554432 # To define that the user SHOULD NOT run programs independently of the assignment
            
            if ($EnableWOL) {$EW = 4194304} else {$EW = 0} # Enable Wake On LAN
            if ($IgnoreMaintenance) {$IM = 1048576} else {$IM = 0} # Ignore maintenance windows when running program
            if ($AllowRestart) {$AR = 2097152} else {$AR = 0} # Allow system restart outside maintenance windows
            
            if ($RerunBehavior.ToLower() -eq "always") {$RemoteClientFlags += 2048} # Always rerun the program
            elseif ($RerunBehavior.ToLower() -eq "never") {$RemoteClientFlags += 4096} # Never rerun the program
            elseif ($RerunBehavior.ToLower() -eq "iffailed") {$RemoteClientFlags += 8192} # Rerun the program if execution previously failed
            elseif ($RerunBehavior.ToLower() -eq "ifsucceeded") {$RemoteClientFlags += 16384} # Rerun the program if execution previously succeeded
            else {$RemoteClientFlags += 4096} #Never by default
        } else {
            $Deadline = $null
        }
        $advFlags += ($EW + $IM + $AR)
        if ($ProgramName -eq "*" -and $TSShowProgressBar) {$advFlags += 8388608} # if TS, show progress bar
 
        # Get the all the Advertisement Properties
        $newAdvertisement = $AdvClass.CreateInstance()
        $newAdvertisement.AdvertisementName = $AdvertisementName
        $newAdvertisement.CollectionID = $CollectionID
        $newAdvertisement.PackageID = $PackageID
        $newAdvertisement.ProgramName = $ProgramName
        $newAdvertisement.AdvertFlags = $advFlags
        $newAdvertisement.RemoteClientFlags = $RemoteClientFlags
        $newAdvertisement.PresentTime = $PresentTime
        $newAdvertisement.ExpirationTime = $ExpirationTime
        $newAdvertisement.ExpirationTimeEnabled = $ExpirationTimeEnabled
        $newAdvertisement.PresentTimeEnabled = $true
        #$newAdvertisement.TimeFlags = "24593"
        if ($Priority.ToLower() -eq "low") {$newAdvertisement.Priority = "3"}
        elseif ($Priority.ToLower() -eq "medium") {$newAdvertisement.Priority = "2"}
        elseif ($Priority.ToLower() -eq "high") {$newAdvertisement.Priority = "1"}
        else {$newAdvertisement.Priority = "2"}
        $newAdvertisement.IncludeSubCollection = $IncSubCol
 
        # Create Advertisement
        $retval = $newAdvertisement.psbase.Put()
        if ($Deadline -ne $null) {
            # Create Mandatory Schedule
            $wmiClassSchedule = [WmiClass]("\\$strServer\" + "$strNameSpace" + ":SMS_ST_NonRecurring")
            $AssignedSchedule = $wmiClassSchedule.psbase.createinstance()
            $AssignedSchedule.starttime = $Deadline
            $newAdvertisement.AssignedSchedule = $AssignedSchedule
            $newAdvertisement.AssignedScheduleEnabled = $true
            $newAdvertisement.psbase.put()
            $NewAdvertisementProperties = $newAdvertisement.AssignedSchedule
            foreach ($Adv in $NewAdvertisementProperties) {
                write-verbose "Created Advertisement. Name = $($newAdvertisement.AdvertisementName)"
                write-verbose "Created Advertisement. ID = $newAdvertisement"
                Write-Verbose "Mandatory Deadline created: $($Adv.StartTime)"
            }
        } else {
            write-verbose "Created Advertisement. Name = $($newAdvertisement.AdvertisementName)"
            write-verbose "Created Advertisement. ID = $newAdvertisement"
            if ($MandatoryTime -ne $null) {
                write-verbose "Mandatory-Deadline defined to $MandatoryTime"
            }
            else {write-verbose "No Mandatory-Deadline defined"}
        }
        
        if ($FolderID -ne "") {
            $folder = Get-SCCMFolder -sccmServer $SccmServer -Filter "ContainerNodeID='$FolderID'"
            if ($folder -ne $null) {
                if ($folder.ObjectType -eq 3) { # The folder is an Advertisements Folder
                    $wmiObj = [wmiclass]("\\" + $SccmServer.Machine + "\" + $SccmServer.Namespace + ":SMS_ObjectContainerItem")
                    Write-Verbose "Moving the Advertisement to the folder $($folder.Name)..."
                    $Instance = $wmiObj.CreateInstance()
                    $Instance.ContainerNodeID = $FolderID
                    $newAdvertisement.Get()
                    $Instance.InstanceKey = $($newAdvertisement.AdvertisementID)
                    $Instance.ObjectType = "3"
                    $Instance.psbase.Put()
                    Write-Verbose "Advertisement created successfully in the folder $($folder.Name)"
                }
                else {
                    Write-Host "The folder $($folder.Name) is not an Advertisements Folder! Advertisement created on the default location."
                    Write-Verbose "Advertisement created successfully"
                }
            }
            else {
                Write-Host "No folder with the ID $FolderID was found! Advertisement created on the default location."
                Write-Verbose "Advertisement created successfully"
            }
        }
        else {
            Write-Verbose "Advertisement created successfully"
        }
    }
}
 
Function New-SCCMProgram {
    <#
    .SYNOPSIS
        Create a new SCCM Program
    .EXAMPLE
        Create a program for the package 7Zip
        $pkg = Get-SCCMPackage -SccmServer $sccm -Filter "Name='7Zip'"
        New-SCCMProgram -SccmServer $sccm -PrgName "Install 7Zip" -PrgPackageID $pkg.PackageID -PrgCommandLine "msiexec.exe /I 7ZipInstaller.msi"
    #>
    [CmdletBinding()]
    PARAM (
        [Parameter(Mandatory=$true, HelpMessage="SCCM Server")][Alias("Server","SmsServer")][System.Object] $SccmServer,
        [Parameter(Mandatory=$true, HelpMessage="Program Name")][String] $PrgName = "",
        [Parameter(Mandatory=$true, HelpMessage="Program PackageID")][String] $PrgPackageID,
        [Parameter(Mandatory=$false, HelpMessage="Program Comment")][String] $PrgComment = "",
        [Parameter(Mandatory=$false, HelpMessage="Program CommandLine")][String] $PrgCommandLine = "",
        [Parameter(Mandatory=$false, HelpMessage="Program MaxRunTime")] $PrgMaxRunTime,
        [Parameter(Mandatory=$false, HelpMessage="Program Diskspace Requirement")] $PrgSpaceReq,
        [Parameter(Mandatory=$false, HelpMessage="Program Working Directory")][String] $PrgWorkDir = "",
        [Parameter(Mandatory=$false, HelpMessage="Program Flags")] $PrgFlags
    )
    PROCESS {
        $programClass = [WMICLASS]"\\$($SccmServer.Machine)\$($SccmServer.Namespace):SMS_Program"
        $newProgram = $programClass.createInstance()
        $newProgram.ProgramName = $PrgName
        $newProgram.PackageID = $PrgPackageID
        if ($PrgComment -ne "") { $newProgram.Comment = $PrgComment }
        if ($PrgCommandLine -ne "") { $newProgram.CommandLine = $PrgCommandLine }
        if ($PrgMaxRunTime -ne $null) { $newProgram.Duration = $PrgMaxRunTime} else { $newProgram.Duration = "0" }
        if ($PrgSpaceReq -ne $null) { $newProgram.DiskSpaceReq = $PrgSpaceReq }
        if ($PrgWorkDir -ne "") { $newProgram.WorkingDirectory = $PrgWorkDir }
        if ($PrgFlags -ne $null) { $newProgram.ProgramFlags = $PrgFlags} else { $newProgram.ProgramFlags = "135290880" }
        $newProgram.Put()
        $newProgram.Get()
        Write-Verbose "Return the new program for Package $($newProgram.PackageID)"
        return $newProgram
    }
}
 
Function Add-SCCMDistributionPoint {
    <#
    .SYNOPSIS
        Create a new SCCM Distribution Point
    #>
    [CmdletBinding()]
    PARAM (
        [Parameter(Mandatory=$true, HelpMessage="SCCM Server")][Alias("Server","SmsServer")][System.Object] $SccmServer,
        [Parameter(Mandatory=$true, HelpMessage="PackageID")][String] $DPPackageID,
        [Parameter(Mandatory=$false, HelpMessage="DistributionPoint Servername")][String]$DPName = "",
        [Parameter(Mandatory=$false, HelpMessage="All DistributionPoints of SiteCode")][String] $DPsSiteCode = "",
        [Parameter(Mandatory=$false, HelpMessage="Distribution Point Group")][String] $DPGroupName = "",
        [Switch] $AllDPs
    )
    PROCESS {
        if ($DPName -ne "") {
            $Resource = Get-SCCMObject -SccmServer $SccmServer -class SMS_SystemResourceList -Filter "RoleName = 'SMS Distribution Point' and Servername = '$DPName'"
            $DPClass = [WMICLASS]"\\$($SccmServer.Machine)\$($SccmServer.Namespace):SMS_DistributionPoint"
            $newDistributionPoint = $DPClass.createInstance()
            $newDistributionPoint.PackageID = $DPPackageID
            $newDistributionPoint.ServerNALPath = $Resource.NALPath
            $newDistributionPoint.SiteCode = $Resource.SiteCode
            $newDistributionPoint.Put()
            $newDistributionPoint.Get()
            Write-Verbose "Assigned Package: $($newDistributionPoint.PackageID)"
        }
        if ($DPsSiteCode -ne "") {
            $ListOfResources = Get-SCCMObject -SccmServer $SccmServer -class SMS_SystemResourceList -Filter "RoleName = 'SMS Distribution Point' and SiteCode = '$DPsSiteCode'"
            $DPClass = [WMICLASS]"\\$($SccmServer.Machine)\$($SccmServer.Namespace):SMS_DistributionPoint"
            $newDistributionPoint = $DPClass.createInstance()
            $newDistributionPoint.PackageID = $DPPackageID
            foreach ($resource in $ListOfResources) {
                $newDistributionPoint.ServerNALPath = $Resource.NALPath
                $newDistributionPoint.SiteCode = $Resource.SiteCode
                $newDistributionPoint.Put()
                $newDistributionPoint.Get()
                Write-Verbose "Assigned Package: $($newDistributionPoint.PackageID)"
            }
        }
        if ($DPGroupName -ne "") {
            $DPGroup = Get-SCCMObject -sccmserver $SccmServer -class SMS_DistributionPointGroup -Filter "sGroupName = '$DPGroupName'"
            $DPGroupNALPaths = $DPGroup.arrNALPath
            $DPClass = [WMICLASS]"\\$($SccmServer.Machine)\$($SccmServer.Namespace):SMS_DistributionPoint"
            $newDistributionPoint = $DPClass.createInstance()
            $newDistributionPoint.PackageID = $DPPackageID
            foreach ($DPGroupNALPath in $DPGroupNALPaths) {
                $DPResource = Get-SCCMObject -SccmServer $SccmServer -class SMS_SystemResourceList -Filter "RoleName = 'SMS Distribution Point'" | Where-Object {$_.NALPath -eq $DPGroupNALPath}
                if ($DPResource -ne $null) {
                    Write-Verbose "$DPResource"
                    $newDistributionPoint.ServerNALPath = $DPResource.NALPath
                    Write-Verbose "ServerNALPath = $($newDistributionPoint.ServerNALPath)"
                    $newDistributionPoint.SiteCode = $DPResource.SiteCode
                    Write-Verbose "SiteCode = $($newDistributionPoint.SiteCode)"
                    $newDistributionPoint.Put()
                    $newDistributionPoint.Get()
                    Write-Host "Assigned Package: $($newDistributionPoint.PackageID) to $($DPResource.ServerName)"
                } else {
                    Write-Host "DP not found = $DPGroupNALPath"
                }
            }
        }
        if ($AllDPs) {
            $ListOfResources = Get-SCCMObject -SccmServer $SccmServer -class SMS_SystemResourceList -Filter "RoleName = 'SMS Distribution Point'"
            $DPClass = [WMICLASS]"\\$($SccmServer.Machine)\$($SccmServer.Namespace):SMS_DistributionPoint"
            $newDistributionPoint = $DPClass.createInstance()
            $newDistributionPoint.PackageID = $DPPackageID
            foreach ($resource in $ListOfResources) {
                $newDistributionPoint.ServerNALPath = $Resource.NALPath
                $newDistributionPoint.SiteCode = $Resource.SiteCode
                $newDistributionPoint.Put()
                $newDistributionPoint.Get()
                Write-Verbose "Assigned Package: $($newDistributionPoint.PackageID) $($newDistributionPoint.ServerNALPath)"
            }
        }
    }
}
 
Function Update-SCCMDriverPkgSourcePath {
    <#
    .SYNOPSIS
        Update Driver Package Source path
    .EXAMPLE
        Update-SCCMDriverPkgSourcePath -SccmServer $sccm -CurrentPath "\\sharedata\drivers\HP\ILO" -NewPath "\\sharedata\drivers\network\HP\ILO"
    #>
    [CmdletBinding()]
    PARAM (
        [Parameter(Mandatory=$true, HelpMessage="SCCM Server")][Alias("Server","SmsServer")][System.Object] $SccmServer,
        [Parameter(Mandatory=$true, HelpMessage="Current Path", ValueFromPipeline=$true)][String] $CurrentPath,
        [Parameter(Mandatory=$true, HelpMessage="New Path", ValueFromPipeline=$true)][String] $NewPath
    )
 
    PROCESS {
        Get-SCCMDriverPackage -sccmserver $SccmServer | Where-Object {$_.PkgSourcePath -ilike "*$($CurrentPath)*" } | Foreach-Object {
            $newSourcePath = ($_.PkgSourcePath -ireplace [regex]::Escape($CurrentPath), $NewPath)
            Write-Verbose "Changing from '$($_.PkgSourcePath)' to '$($newSourcePath)' on $($_.PackageID)"
            $_.PkgSourcePath = $newSourcePath
            $_.Put() | Out-Null
        }
    }
}
 
Function Update-SCCMPackageSourcePath {
    <#
    .SYNOPSIS
        Update Package Source path
    .EXAMPLE
        Update-SCCMPackageSourcePath -SccmServer $sccm -CurrentPath "\\sharedata\software\7zip" -NewPath "\\sharedata\software\tools\7Zip"
    #>
    [CmdletBinding()]
    PARAM (
        [Parameter(Mandatory=$true, HelpMessage="SCCM Server")][Alias("Server","SmsServer")][System.Object] $SccmServer,
        [Parameter(Mandatory=$true, HelpMessage="Current Path", ValueFromPipeline=$true)][String] $CurrentPath,
        [Parameter(Mandatory=$true, HelpMessage="New Path", ValueFromPipeline=$true)][String] $NewPath
    )
 
    PROCESS {
        Get-SCCMPackage -sccmserver $SccmServer | Where-Object {$_.PkgSourcePath -ilike "*$($CurrentPath)*" } | Foreach-Object {
            $newSourcePath = ($_.PkgSourcePath -ireplace [regex]::Escape($CurrentPath), $NewPath)
            Write-Verbose "Changing from '$($_.PkgSourcePath)' to '$($newSourcePath)' on $($_.PackageID)"
            $_.PkgSourcePath = $newSourcePath
            $_.Put() | Out-Null
        }
    }
}
 
Function Update-SCCMDriverSourcePath {
    <#
    .SYNOPSIS
        Update Driver Source path
    .EXAMPLE
        Update-SCCMDriverSourcePath -SccmServer $sccm -CurrentPath "\\sharedata\drivers\HP\ILO" -NewPath "\\sharedata\drivers\network\HP\ILO"
    #>
    [CmdletBinding()]
    PARAM (
        [Parameter(Mandatory=$true, HelpMessage="SCCM Server")][Alias("Server","SmsServer")][System.Object] $SccmServer,
        [Parameter(Mandatory=$true, HelpMessage="Current Path", ValueFromPipeline=$true)][String] $CurrentPath,
        [Parameter(Mandatory=$true, HelpMessage="New Path", ValueFromPipeline=$true)][String] $NewPath
    )
 
    PROCESS {
        Get-SCCMDriver -sccmserver $SccmServer | Where-Object {$_.ContentSourcePath -ilike "*$($CurrentPath)*" } | Foreach-Object {
            $newSourcePath = ($_.ContentSourcePath -ireplace [regex]::Escape($CurrentPath), $NewPath)
            Write-Verbose "Changing from '$($_.ContentSourcePath)' to '$($newSourcePath)' on $($_.PackageID)"
            $_.ContentSourcePath = $newSourcePath
            $_.Put() | Out-Null
        }
    }
}

# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
# Add FVE | (c) Florian Valente
Function Export-SCCMTaskSequence {
    <#
    .SYNOPSIS
        Export a task sequence
        The XML exported here is TOTALLY different from the XML exported via the SCCM Console!
        If the path was not found, it saves the XML file under %TEMP%
        The XML file is named <task_sequence_ID>.xml
    .EXAMPLE
        $ts = Get-SCCMTaskSequence -SccmServer $sccm -Filter "Name='TS Deploy'"
        Export-SCCMTaskSequence -SccmServer $sccm -TaskSequenceID $ts.PackageID -Path "d:\test"
    #>
    [CmdletBinding()]
    PARAM (
        [Parameter(Mandatory=$true, HelpMessage="SCCM Server",ValueFromPipeline=$true)][Alias("Server","SmsServer")][System.Object] $SccmServer,
        [Parameter(Mandatory=$true, HelpMessage="Task Sequence ID")][String] $TaskSequenceID,
        [Parameter(Mandatory=$true, HelpMessage="Folder Path where XML File will be saved")][String] $Path
    )
 
    PROCESS {
        # Get Task Sequence Object
        $retObj = Get-SCCMTaskSequence -sccmServer $SccmServer -Filter "PackageID='$TaskSequenceID'"
        if ($retObj -eq $null) {
            $Host.UI.WriteErrorLine("No Task Sequence found with the ID $TaskSequenceID")
            return
        }
        
        $tsObj = [wmi]"$($retObj.__PATH)"
        Write-Verbose "Task Sequence found. Name= $($tsObj.Name)"
        if (!(Test-Path $Path)) {
            $Path = $env:temp
            Write-Verbose "Path not found! New path is $Path"
        }
        Set-Content -Path "$Path\$($tsObj.PackageId).xml" -Value $tsObj.Sequence
        Write-Verbose "Task Sequence exported in $Path\$($tsObj.PackageId).xml"
    }
}

Function Import-SCCMTaskSequence {
    <#
    .SYNOPSIS
        Import a task sequence
        The XML imported MUST BE a XML file created by the cmdlet Export-SCCMTaskSequence!
    .EXAMPLE
        Import a Task Sequence based on the file xxxxxxxx.xml and named "TS Deploy v2"
        Import-SCCMTaskSequence -SccmServer $sccm -TaskSequenceName "TS Deploy v2" -Path "d:\test\xxxxxxxx.xml"
    .EXAMPLE
        Import a Task Sequence based on the file xxxxxxxx.xml and named "TS Deploy v2" under the folder "Deploy"
        $folder = Get-SCCMFolder -SccmServer $sccm -Filter "Name='Deploy'" -FolderNodeID (Get-SCCMFolderNode -NodeName "TaskSequences")
        Import-SCCMTaskSequence -SccmServer $sccm -TaskSequenceName "TS Deploy v2" -Path "d:\test\xxxxxxxx.xml" -FolderID $folder.ContainerNodeID
    #>
    [CmdletBinding()]
    PARAM (
        [Parameter(Mandatory=$true, HelpMessage="SCCM Server",ValueFromPipeline=$true)][Alias("Server","SmsServer")][System.Object] $SccmServer,
        [Parameter(Mandatory=$true, HelpMessage="Task Sequence Name")][String] $Name,
        [Parameter(Mandatory=$true, HelpMessage="XML File used for import")][String] $Path,
        [Parameter(Mandatory=$false,HelpMessage="Folder ID")][String] $FolderID = "",
        [Parameter(Mandatory=$false,HelpMessage="Description")][String] $Description = "",
        [Parameter(Mandatory=$false,HelpMessage="Custom progress notification text")][String] $CustomText = "",
        [Parameter(Mandatory=$false,HelpMessage="Duration")][Int] $Duration = 360
    )
 
    PROCESS {
        if (!(Test-Path $Path)) {
            $Host.UI.WriteErrorLine("File $Path not found!")
            return
        }
        
        $tsContent = gc "$Path"
        $wmiObj = [wmiclass]("\\" + $SccmServer.Machine + "\" + $SccmServer.Namespace + ":SMS_TaskSequencePackage")
        $tsObj = $wmiObj.ImportSequence($tsContent)

        Write-Verbose "Importing Task Sequence..."
        $Instance = $wmiObj.CreateInstance()
        $DefaultSequence = $tsObj.TaskSequence
        $Instance.Name = $Name
        if ($Description -ne "") {
            $Instance.Description = $Description
            Write-Verbose "Description defined: $Description"
        }
        else {
            Write-Verbose "No Description defined"
        }
        if ($CustomText -ne "") {
            $Instance.CustomProgressMsg = $CustomText
            $Instance.ProgramFlags = 152084498
            Write-Verbose "Custom progress notification text defined: $CustomText"
        }
        else {
            $Instance.ProgramFlags = 152084496
            Write-Verbose "No custom progress notification text defined"
        }
        $Instance.Duration = $Duration
        Write-Verbose "Duration defined: $Duration"
        
        #Commit changes
        ($wmiObj.SetSequence($Instance,$defaultSequence)).SavedTaskSequencePackagePath
        
        if ($FolderID -ne "") {
            $folder = Get-SCCMFolder -sccmServer $SccmServer -Filter "ContainerNodeID='$FolderID'"
            if ($folder -ne $null) {
                if ($folder.ObjectType -eq 20) { # The folder is a Task Sequences Folder
                    $wmiObj = [wmiclass]("\\" + $SccmServer.Machine + "\" + $SccmServer.Namespace + ":SMS_ObjectContainerItem")
                    Write-Verbose "Moving the Task Sequence to the folder $FolderName..."
                    $newFolderasso = $wmiObj.CreateInstance()
                    $newFolderasso.ContainerNodeID = $FolderID
                    $newFolderasso.InstanceKey = ($(Get-SCCMTaskSequence -sccmServer $SccmServer -Filter "Name='$Name'")).PackageID
                    $newFolderasso.ObjectType = "20"
                    $newFolderasso.psbase.Put()
                    Write-Verbose "Task Sequence imported successfully in the folder $($folder.Name)"
                }
                else {
                    Write-Host "The folder $($folder.Name) is not a Task Sequences Folder! Task Sequence imported on the default location."
                    Write-Verbose "Task Sequence imported successfully"
                }
            }
            else {
                Write-Host "No folder with the ID $FolderID was found! Task Sequence imported on the default location."
                Write-Verbose "Task Sequence imported successfully"
            }
        }
        else {
            Write-Verbose "Task Sequence imported successfully"
        }
    }
}

Function Copy-SCCMTaskSequence {
    <#
    .SYNOPSIS
        Copy a task sequence
    .EXAMPLE
        Copy a Task Sequence
        $ts = Get-SCCMTaskSequence -SccmServer $sccm -Filter "Name='TS Deploy'"
        Copy-SCCMTaskSequence -SccmServer $sccm -TaskSequenceID $ts.PackageID -NewName "TS Deploy v2"
    .EXAMPLE
        Copy a Task Sequence and create the new under the folder "Deploy"
        $folder = Get-SCCMFolder -SccmServer $sccm -Filter "Name='Deploy'" -FolderNodeID (Get-SCCMFolderNode -NodeName "TaskSequences")
        Copy-SCCMTaskSequence -SccmServer $sccm -TaskSequenceID $ts.PackageID -NewName "TS Deploy v2" -FolderID $folder.ContainerNodeID
    #>
    [CmdletBinding()]
    PARAM (
        [Parameter(Mandatory=$true, HelpMessage="SCCM Server",ValueFromPipeline=$true)][Alias("Server","SmsServer")][System.Object] $SccmServer,
        [Parameter(Mandatory=$true, HelpMessage="Reference Task Sequence ID")][String] $TaskSequenceID,
        [Parameter(Mandatory=$true, HelpMessage="New Task Sequence Name")][String] $NewName,
        [Parameter(Mandatory=$false,HelpMessage="Folder Name")][String] $FolderID = "",
        [Parameter(Mandatory=$false,HelpMessage="Description")][String] $Description = "",
        [Parameter(Mandatory=$false,HelpMessage="Custom progress notification text")][String] $CustomText = "",
        [Parameter(Mandatory=$false,HelpMessage="Duration")][Int] $Duration = 360
    )
 
    PROCESS {
        # Get Task Sequence Object
        Export-SCCMTaskSequence -sccmServer $SccmServer -TaskSequenceID $TaskSequenceID -Path $env:temp
        if (Test-Path "$env:temp\$TaskSequenceID.xml") {
            Import-SCCMTaskSequence -sccmServer $SccmServer -Name $NewName -Path ("$env:temp\$TaskSequenceID.xml") -Description $Description -CustomText $CustomText -Duration $Duration -FolderID $FolderID
            
            #Delete temporary XML file
            Remove-Item -Path ("$env:temp\$TaskSequenceID.xml") -Force      
        }
        else {
            $Host.UI.WriteErrorLine("Error during the copy. Cancel.")
        }
    }
}

Function Get-SCCMDCMAssignment {
    <#
    .SYNOPSIS
        Get Desired Configuration Management assignment
    .EXAMPLE
        Get all DCM assignments
        Get-SCCMDCMAssignment -SccmServer $sccm
    .EXAMPLE
        Get DCM Assignments for a specific collection
        $col = Get-SCCMCollection -SccmServer $sccm -Filter "Name='TEST'"
        Get-SCCMDCMAssignment -SccmServer $sccm -CollectionID $col.CollectionID
    #>
    [CmdletBinding()]
    PARAM (
        [Parameter(Mandatory=$true, HelpMessage="SCCM Server",ValueFromPipeline=$true)][Alias("Server","SmsServer")][System.Object] $SccmServer,
        [Parameter(Mandatory=$false, HelpMessage="DCM Assignment ID")][String] $CollectionID = ""
    )
 
    PROCESS {
        if ($CollectionID -eq "") {
            $dcmObj = Get-SCCMObject -sccmServer $SccmServer -Class "SMS_BaselineAssignment"
        }
        else {
            $dcmObj = Get-SCCMObject -sccmServer $SccmServer -Class "SMS_BaselineAssignment" -Filter "TargetCollectionID='$CollectionID'"
        }
        
        if ($dcmObj -eq $null) {
            Write-Host "No DCM Assignments"
        }
        else {
            return $dcmObj
        }
    }
}

Function Get-SCCMFolder {
    <#
    .SYNOPSIS
        Get SCCM Folder
        Use Get-SCCMFolderNode to get Folder Node ID
    .EXAMPLE
        Get all folders
        Get-SCCMFolder -SccmServer $sccm
    .EXAMPLE
        Get all folders named "Test Folder"
        Get-SCCMFolder -SccmServer $sccm -Filter "Name='Test Folder'"
    .EXAMPLE
        Get folder(s) named "Test Folder" in the Node "TaskSequences"
        $folderNode = Get-SCCMFolderNode -SccmServer $sccm -Name "TaskSequences"
        Get-SCCMFolder -SccmServer $sccm -Filter "Name='Test Folder'" -FolderNodeID $folderNode
    .EXAMPLE
        Get folder "Homo" in the Node "Advertisements" that as a parent folder "Deploy"
        Very usefull if there are many folders with the same same
        $folderNode = Get-SCCMFolderNode -SccmServer $sccm -Name "Advertisements"
        $parentFolder = Get-SCCMFolder -SccmServer $sccm -Filter "Name='Deploy'" -FolderNodeID $folderNode
        Get-SCCMFolder -SccmServer $sccm -Filter "Name='Test Folder'" -FolderNodeID $folderNode -ParentFolderID $parentFolder.ContainerNodeID
    #>
    [CmdletBinding()]
    PARAM (
        [Parameter(Mandatory=$true, HelpMessage="SCCM Server",ValueFromPipeline=$true)][Alias("Server","SmsServer")][System.Object] $SccmServer,
        [Parameter(Mandatory=$false, HelpMessage="Folder Name")][String] $Filter = "",
        [Parameter(Mandatory=$false, HelpMessage="Folder Node ID")][String] $FolderNodeID = "",
        [Parameter(Mandatory=$false, HelpMessage="Parent Folder ID")][String] $ParentFolderID = ""
    )
 
    PROCESS {
        if ($FolderNodeID -ne "" -and $FolderNodeID -ne $null) {
            if ($Filter -ne "") {$Filter += " AND ObjectType='$FolderNodeID'"}
            else {$Filter = "ObjectType='$FolderNodeID'"}
        }
        if ($ParentFolderID -ne "" -and $ParentFolderID -ne $null) {
            if ($filter -ne "") {$Filter += " AND ParentContainerNodeID='$ParentFolderID'"}
            else {$Filter = "ParentContainerNodeID='$ParentFolderID'"}
        }
        
        return Get-SCCMObject -sccmServer $SccmServer -Class "SMS_ObjectContainerNode" -Filter $Filter
    }
}

Function Get-SCCMFolderNode {
    <#
    .SYNOPSIS
        Get SCCM Folder Node
        Available Folder Nodes:
        - Packages
        - Advertisements
        - Queries
        - Reports
        - SoftwareMetering
        - DCMConfigurationBaselines
        - DCMConfigurationItems
        - OSInstallPackages
        - OSImages
        - ComputerAssociation
        - TaskSequences
        - DriverPackages
        - Drivers      
    .EXAMPLE
        Get all folder nodes available
        Get-SCCMFolderNode
    .EXAMPLE
        Get "TaskSequence" folder node
        Get-SCCMFolderNode -NodeName "TaskSequence"
    #>

    [CmdletBinding()]
    PARAM (
        [Parameter(Mandatory=$false, HelpMessage="Folder Node Name")][String] $NodeName = ""
    )
 
    PROCESS {
        $data = @{"Packages" = "2";
            "Advertisements" = "3";
            "Queries" = "7";
            "Reports" = "8";
            "SoftwareMetering" = "9";
            "DCMConfigurationItems" = "11";
            "OSInstallPackages" = "14";
            "ComputerAssociation" = "17";
            "OSImages" = "18";
            "BootImages" = "19";
            "TaskSequences" = "20";
            "DriverPackages" = "23";
            "Drivers" = "25";
            "DCMConfigurationBaselines" = "2011"
        }
        
        if ($NodeName -ne "") {
            return $data."$NodeName"
        }
        
        $columns = @{Expression={$_.Name};Label="NodeName"}, @{Expression={$_.Value};Label="NodeID"}
        return ($data.GetEnumerator() | Sort-Object Name | Format-Table $columns)
    }
}

Function Get-SCCMReport {
    <#
    .SYNOPSIS
        Get SCCM Report
    .EXAMPLE
        Get all reports
        Get-SCCMReport -SccmServer $sccm
    .EXAMPLE
        Get a specific report
        Get-SCCMReport -SccmServer $sccm -Filter "ReportID='389'"
    #>
    [CmdletBinding()]
    PARAM (
        [Parameter(Mandatory=$true, HelpMessage="SCCM Server",ValueFromPipeline=$true)][Alias("Server","SmsServer")][System.Object] $SccmServer,
        [Parameter(Mandatory=$false, HelpMessage="Optional Filter on query")][String] $Filter = $null
    )
 
    PROCESS {
        return Get-SCCMObject -sccmServer $SccmServer -Class "SMS_Report" -Filter $Filter
    }
}

Function Get-SCCMSUMDeploymentTemplate {
    <#
    .SYNOPSIS
        Get SCCM Software Update Deployment Templates
    .EXAMPLE
        Get all SUM templates
        Get-SCCMSUMDeploymentTemplate -SccmServer $sccm
    .EXAMPLE
        Get a specific template
        Get-SCCMSUMDeploymentTemplate -SccmServer $sccm -Filter "Name='Test Template'"
    #>
    [CmdletBinding()]
    PARAM (
        [Parameter(Mandatory=$true, HelpMessage="SCCM Server",ValueFromPipeline=$true)][Alias("Server","SmsServer")][System.Object] $SccmServer,
        [Parameter(Mandatory=$false, HelpMessage="Optional Filter on query")][String] $Filter = $null
    )
 
    PROCESS {
        return Get-SCCMObject -sccmServer $SccmServer -Class "SMS_Template" -Filter $Filter
    }
}

Function Get-SCCMSUMUpdatesInfo {
    <#
    .SYNOPSIS
        Get SCCM Software Update Information
    .EXAMPLE
        Get all Software Updates
        Get-SCCMSUMUpdatesInfo -SccmServer $sccm
    .EXAMPLE
        Get all Software Updates already been deployed
        Get-SCCMSUMUpdatesInfo -SccmServer $sccm -Deployed
    .EXAMPLE
        Get all Software Updates with Critical severity level
        Get-SCCMSUMUpdatesInfo -SccmServer $sccm -Severity "Critical"
    .EXAMPLE
        Get a specific Software Update
        Get-SCCMSUMUpdatesInfo -SccmServer $sccm -ArticleID "1239898"
    #>
    [CmdletBinding()]
    PARAM (
        [Parameter(Mandatory=$true, HelpMessage="SCCM Server",ValueFromPipeline=$true)][Alias("Server","SmsServer")][System.Object] $SccmServer,
        [Parameter(Mandatory=$false, HelpMessage="Article ID")][String] $ArticleID = "",
        [Switch] $Downloaded,
        [Switch] $Deployed,
        [Parameter(Mandatory=$false, HelpMessage="Severity Level (Critical, Important, Moderate, Low)")][String] $Severity = ""
    )
 
    PROCESS {
        if ($ArticleID -eq "") {
            # Return all updates that have already been downloaded
            if ($Downloaded) {
                return Get-SCCMObject -sccmServer $SccmServer -Class "SMS_SoftwareUpdate" -Filter "IsContentProvisioned=1"
            }
            # Return the updates that have already been deployed
            if ($Deployed) {
                return Get-SCCMObject -sccmServer $SccmServer -Class "SMS_SoftwareUpdate" -Filter "IsDeployed=1"
            }
            # Return the updates that have a particular severity name
            if ($Severity -ne "") {
                return Get-SCCMObject -sccmServer $SccmServer -Class "SMS_SoftwareUpdate" -Filter "SeverityName='$Severity'"
            }
        }
        # Return software updates associated with a specific KB
        else {
            return Get-SCCMObject -sccmServer $SccmServer -Class "SMS_SoftwareUpdate" -Filter "ArticleID='$ArticleID'"
        }
    }
}

Function New-SCCMFolder {
    <#
    .SYNOPSIS
        Create a SCCM Folder
        MANDATORY: Use Get-FolderNode to get the Folder Node ID
    .EXAMPLE
        Create a folder under Task Sequences Node
        $folderNode = Get-SCCMFolderNode -NodeName "TaskSequences"
        New-SCCMFolder -SccmServer $sccm -FolderName "Win7 Deploy" -FolderNodeID $folderNode
    .EXAMPLE
        Create a sub folder "run" of the "adv" folder placed under Advertisements Node
        $folderNode = Get-SCCMFolderNode -NodeName "Advertisements"
        $advFolder = Get-SCCMFolder -SccmServer $sccm -Filter "Name='adv'" -FolderNodeID $folderNode
        New-SCCMFolder -SccmServer $sccm -FolderName "run" -FolderNodeID $folderNode -ParentFolderID $advFolder.ContainerNodeID
    #>   
    [CmdletBinding()]
    PARAM (
        [Parameter(Mandatory=$true, HelpMessage="SCCM Server",ValueFromPipeline=$true)][Alias("Server","SmsServer")][System.Object] $SccmServer,
        [Parameter(Mandatory=$true, HelpMessage="Folder Name")][String] $FolderName,
        [Parameter(Mandatory=$true, HelpMessage="Folder Node ID")] $FolderNodeID,
        [Parameter(Mandatory=$false, HelpMessage="Parent Folder ID")][Int] $ParentFolderID = 0
    )
    
    PROCESS {
        if ($ParentFolderID -ne 0) {
            $test = Get-SCCMFolder -sccmServer $SccmServer -Filter "ContainerNodeID='$ParentFolderID'"
            if ($test -eq $null) {
                $Host.UI.WriteErrorLine("Parent Folder ID does not exists. Exit")
                return
            }
            else {
                $testFolder = Get-SCCMFolder -sccmServer $SccmServer -Filter "Name='$FolderName' AND ParentContainerNodeID='$ParentFolderID'" -FolderNodeID $FolderNodeID
            }
        }
        else {
            $testFolder = Get-SCCMFolder -sccmServer $SccmServer -Filter "Name='$FolderName'" -FolderNodeID $FolderNodeID
        }
        
        if ($testFolder -eq $null) {
            Write-Verbose "Creating Folder..."
            $wmiObj = [wmiclass]("\\" + $SccmServer.Machine + "\" + $SccmServer.Namespace + ":SMS_ObjectContainerNode")
            $newFolder = $wmiObj.CreateInstance()
            $newFolder.Name = $FolderName
            $newFolder.ObjectType = $FolderNodeID
            $newFolder.ParentContainerNodeID = $ParentFolderID
            $newFolder.psbase.Put()
            
            Write-Verbose "Folder created successfully"
        }
        else {
            Write-Host "A Folder named $FolderName was found on the same Node AND/OR the same Parent Folder"
        }
    }
}

Function New-SCCMSUMDeploymentTemplate {
    <#
    .SYNOPSIS
        Create a SCCM Software Update Deployment Template
    .EXAMPLE
        Create a default SUM deployment template to the TEST collection (including sub collections), with default duration of 2 weeks
        $col = Get-SCCMCollection -SccmServer $sccm -Filter "Name='TEST'"
        New-SCCMSUMDeploymentTemplate -SccmServer $sccm -Name "SUM DT" -CollectionID $col.CollectionID -IncludeSubCollection
    .EXAMPLE
        Create a custom SUM deployment template to the TEST Collection, with duration of 10 days, download updates from local and unprotected DP
        $col = Get-SCCMCollection -SccmServer $sccm -Filter "Name='TEST'"
        New-SCCMSUMDeploymentTemplate -SccmServer $sccm -Name "SUM DT" -CollectionID $col.CollectionID -IncludeSubCollection -Duration 10 -DurationUnit "Days" -DownloadFromLocalDP -DownloadFromUnprotectedDP
    #>
    [CmdletBinding()]
    PARAM (
        [Parameter(Mandatory=$true, HelpMessage="SCCM Server",ValueFromPipeline=$true)][Alias("Server","SmsServer")][System.Object] $SccmServer,
        [Parameter(Mandatory=$true, HelpMessage="Name")][String] $Name,
        [Parameter(Mandatory=$false, HelpMessage="Description")][String] $Description = "",
        [Parameter(Mandatory=$true, HelpMessage="CollectionID")][String] $CollectionID,
        [Switch] $IncludeSubCollection,
        [Switch] $AllowNotification,
        [Switch] $ScheduleUTC,
        [Parameter(Mandatory=$false, HelpMessage="Duration number")][Int] $Duration = 2,
        [Parameter(Mandatory=$false, HelpMessage="Duration unit (Hours, Days, Weeks, Months)")][String] $DurationUnit = "Weeks",
        [Switch] $RestartServers,
        [Switch] $RestartWorkstations,
        [Switch] $RestartOutsideMaintenance,
        [Switch] $DownloadFromLocalDP,
        [Switch] $DownloadFromUnprotectedDP        
    )
    
    PROCESS {
    
        $tplObj = Get-SCCMSUMDeploymentTemplate -sccmServer $SccmServer -Filter "Name='$Name'"
        if ($tplObj -ne $null) {
            $Host.UI.WriteErrorLine("SUM Template found with the name $Name. Exit")
            return
        }
        
        $colObj = Get-SCCMCollection -sccmServer $SccmServer -Filter "CollectionID='$CollectionID'"
        if ($colObj -eq $null) {
            $Host.UI.WriteErrorLine("No Collection found with the ID $CollectionID. Exit")
            return
        }
    
        $DepTempSettings = "<TemplateDescription xmlns:xsi=""http://www.w3.org/2001/XMLSchema-instance"" xmlns:xsd=""http://www.w3.org/2001/XMLSchema"">
        <CollectionId>$CollectionID</CollectionId>"
        if ($IncludeSubCollection) {
            $DepTempSettings += "<IncludeSub>true</IncludeSub>"
        } else {
            $DepTempSettings += "<IncludeSub>false</IncludeSub>"
        }
        if ($AllowNotification) {
            $DepTempSettings += "<AttendedInstall>true</AttendedInstall>"
        } else {
            $DepTempSettings += "<AttendedInstall>false</AttendedInstall>"
        }
        if ($ScheduleUTC) {
            $DepTempSettings += "<UTC>true</UTC>"
        } else {
            $DepTempSettings += "<UTC>false</UTC>"
        }
        $DepTempSettings += "<Duration>$Duration</Duration>"
        $DurationUnit = $DurationUnit.Substring(0,1).ToUpper() + $DurationUnit.Substring(1).ToLower()
        if ($DurationUnit -ne "Hours" -and $DurationUnit -ne "Days" -and $DurationUnit -ne "Weeks" -and $DurationUnit -ne "Months") {
            $Host.UI.WriteErrorLine("Duration unit incorrect. Please type only Hours, Days, Weeks or Months")
            return
        }
        $DepTempSettings += "<DurationUnits>$DurationUnit</DurationUnits>"
        if ($RestartServers) {
            $DepTempSettings += "<SuppressServers>Checked</SuppressServers>"
        } else {
            $DepTempSettings += "<SuppressServers>Unchecked</SuppressServers>"
        }
        if ($RestartWorkstations) {
            $DepTempSettings += "<SuppressWorkstations>Checked</SuppressWorkstations>"
        } else {
            $DepTempSettings += "<SuppressWorkstations>Unchecked</SuppressWorkstations>"
        }
        if ($RestartOutsideMaintenance) {
            $DepTempSettings += "<AllowRestart>true</AllowRestart>"
        } else {
            $DepTempSettings += "<AllowRestart>false</AllowRestart>"
        }
        $DepTempSettings += "<Deploy2003>false</Deploy2003>
        <CollectImmediately>false</CollectImmediately>
        <DisableMomAlert>false</DisableMomAlert>
        <GenerateMomAlert>false</GenerateMomAlert>    
        <LocalDPOption>InstallFromDP</LocalDPOption>
        <RemoteDPOption>DownloadAndInstall</RemoteDPOption>"
        if ($DownloadFromLocalDP) {
            $DepTempSettings += "<UseRemoteDP>true</UseRemoteDP>"
        } else {
            $DepTempSettings += "<UseRemoteDP>false</UseRemoteDP>"
        }
        if ($DownloadFromUnprotectedDP) {
            $DepTempSettings += "<UseUnprotectedDP>true</UseUnprotectedDP>"
        } else {
            $DepTempSettings += "<UseUnprotectedDP>false</UseUnprotectedDP>"
        } 
        $DepTempSettings += "</TemplateDescription>"
        
        
        $templateClass = [WMICLASS]"\\$($SccmServer.Machine)\$($SccmServer.Namespace):SMS_Template"
        $newSUMTemplate = $templateClass.createInstance()
        
        $newSUMTemplate.Name = $Name
        if ($Description -ne "") { $newSUMTemplate.Description = $Description }
        $newSUMTemplate.Data = $DepTempSettings
        $newSUMTemplate.Type = 0
        $newSUMTemplate.Put()
        Write-Verbose "SUM Template created with name $Name"
    }
        
}

Function Remove-SCCMAdvertisement {
    <#
    .SYNOPSIS
        Remove an Advertisement
    .EXAMPLE
        Remove an advertisement named "test adv"
        $adv = Get-SCCMAdvertisement -SccmServer $sccm -Filter "AdvertisementName='test adv'"
        Remove-SCCMAdvertisement -SccmServer $sccm -AdvertisementID $adv.AdvertisementID
    #>
    [CmdletBinding()]
    PARAM (
        [Parameter(Mandatory=$true, HelpMessage="SCCM Server")][Alias("Server","SmsServer")][System.Object] $SccmServer,
        [Parameter(Mandatory=$true, HelpMessage="Advertisement ID", ValueFromPipeline=$true)][String] $AdvertisementID
    )
 
    PROCESS {
        $advObj = Get-SCCMAdvertisement -SccmServer $SccmServer -Filter "AdvertisementID='$AdvertisementID'"
        if ($advObj -eq $null) {
            $Host.UI.WriteErrorLine("No Advertisement found with the ID $AdvertisementID")
            return
        }
        Write-Verbose "Advertisement found. Name= $($advObj.AdvertisementName)"
        
        # Delete Advertisement
        $advObj.Delete()
        Write-Verbose "Advertisement deleted."
    }
}

Function Remove-SCCMCollection {
    <#
    .SYNOPSIS
        Remove a Collection
    .EXAMPLE
        Remove a collection named "test" (this collection doesn't include sub collections otherwise it will not be deleted)
        $col = Get-SCCMCollection -SccmServer $sccm -Filter "Name='test'"
        Remove-SCCMCollection -SccmServer $sccm -CollectionID $col.CollectionID
    .EXAMPLE
        Remove a collection named "test" and all its sub collections
        $col = Get-SCCMCollection -SccmServer $sccm -Filter "Name='test'"
        Remove-SCCMCollection -SccmServer $sccm -CollectionID $col.CollectionID -Force
    #>
    [CmdletBinding()]
    PARAM (
        [Parameter(Mandatory=$true, HelpMessage="SCCM Server")][Alias("Server","SmsServer")][System.Object] $SccmServer,
        [Parameter(Mandatory=$true, HelpMessage="Collection ID", ValueFromPipeline=$true)][String] $CollectionID,
        [Parameter(Mandatory=$false, HelpMessage="Force deletion", ValueFromPipeline=$true)][Switch] $Force
    )
 
    PROCESS {
        $collObj = Get-SCCMCollection -SccmServer $SccmServer -Filter "CollectionID='$CollectionID'"
        if ($collObj -eq $null) {
            $Host.UI.WriteErrorLine("No Collection found with the ID $CollectionID")
            return
        }
        
        # Check if there are subcollections
        $subCollObj = Get-SCCMSubCollections -SccmServer $SccmServer -CollectionID $CollectionID
        if ($subCollObj -ne $null) {
            if (!$Force) {
                Write-Host "Sub-Collections found! Delete them first:"
                foreach ($elt in $subCollObj) {Write-Host "- $($elt.subCollectionID) "}
                return
            }
            else {
                Write-Host "-Force ON and Sub-Collections found! Also deleted!"
                foreach ($elt in $subCollObj) {
                    Remove-SCCMCollection -SccmServer $SccmServer -CollectionID $elt.subCollectionID -Force
                }
            }
        }
        
        # Check if there are members
        $memberObj = Get-SCCMCollectionMembers -SccmServer $SccmServer -CollectionID $CollectionID
        if ($memberObj -ne $null) {
            if (!$Force) {
                Write-Host "Members found! Delete them first:"
                foreach ($elt in $memberObj) {Write-Host "- $($elt.Name) "}
                return
            }
            else {
                Write-Host "-Force ON and Resources found! Also deleted!"
            }
        }
        
        # Check if the Collection is advertised
        $advObj = Get-SCCMAdvertisement -SccmServer $SccmServer -Filter "CollectionID='$CollectionID'"
        if ($advObj -ne $null) {
            if (!$Force) {
                Write-Host "Advertisements found! Delete them first:"
                foreach ($elt in $advObj) {Write-Host "- $($elt.AdvertisementName)"}
                return
            }
            else {
                Write-Host "-Force ON and Advertisements found! Also deleted!"
                foreach ($elt in $advObj) {
                    Write-Host "Advertisement $($elt.AdvertisementName) was found and deleted from the Collection ID $CollectionID"
                    $elt.Delete()
                }
            }
        }
        else {
            Write-Verbose "No advertisement found for the Collection ID $CollectionID"
        }
        
        # Delete collection
        $collObj.Delete()
        Write-Verbose "Collection $($collObj.Name) (ID $CollectionID) deleted."
    }
}

Function Remove-SCCMCollectionRule {
    <#
    .SYNOPSIS
        Remove a Collection Rule
    .EXAMPLE
        Remove a collection rule named "test rule" assigned to collection "test"
        $col = Get-SCCMCollection -SccmServer $sccm -Filter "Name='test'"
        Remove-SCCMCollectionRule -SccmServer $sccm -CollectionID $col.CollectionID -RuleName "test rule"
    #>
    [CmdletBinding()]
    PARAM (
        [Parameter(Mandatory=$true, HelpMessage="SCCM Server")][Alias("Server","SmsServer")][System.Object] $SccmServer,
        [Parameter(Mandatory=$true, HelpMessage="Collection ID", ValueFromPipeline=$true)][String] $CollectionID,
        [Parameter(Mandatory=$true, HelpMessage="Rule name", ValueFromPipeline=$true)][String] $RuleName
    )
 
    PROCESS {
        Write-Verbose "Collecting rules for $CollectionID..."
        $col = [wmi]"$($SccmServer.SccmProvider.NamespacePath):SMS_Collection.CollectionID='$($CollectionID)'"
        
        if ($col.CollectionRules -eq $null) {
            $Host.UI.WriteErrorLine("No Collection Rule found for the Collection ID $CollectionID")
            return
        }
        
        $found = $false
        foreach ($elt in $col.CollectionRules) {
            if (($elt.RuleName).ToUpper() -eq $RuleName.ToUpper()) {
                $found = $true
                $col.DeleteMembershipRule($elt)
                Write-Verbose "Rule $RuleName deleted of the Collection ID $CollectionID"
            }
        }
        
        if ($found -eq $false) {
            Write-Verbose "No Rule found with the name $RuleName in the Collection ID $CollectionID"
        }
    }
}

Function Remove-SCCMDriverPackage {
    <#
    .SYNOPSIS
        Remove a Driver Package
    .EXAMPLE
        Remove a driver package named "HP ILO"
        $drv = Get-SCCMDriverPackage -SccmServer $sccm -Filter "Name='HP ILO'"
        Remove-SCCMDriverPackage -SccmServer $sccm -DriverPackageID $drv.PackageID
    #>
    [CmdletBinding()]
    PARAM (
        [Parameter(Mandatory=$true, HelpMessage="SCCM Server")][Alias("Server","SmsServer")][System.Object] $SccmServer,
        [Parameter(Mandatory=$true, HelpMessage="Driver Package ID", ValueFromPipeline=$true)][String] $DriverPackageID
    )
 
    PROCESS {
         # Get Package Object
        $pkObj = Get-SCCMDriverPackage -sccmServer $SccmServer -Filter "PackageID='$DriverPackageID'"
        if ($pkObj -eq $null) {
            $Host.UI.WriteErrorLine("No Driver Package found with the ID $DriverPackageID")
            return
        }
        Write-Verbose "Driver Package found. Name= $($pkObj.Name)"
        
        # Delete Boot Image Package
        $pkObj.Delete()
        Write-Verbose "Driver Package deleted"
    }
}

Function Remove-SCCMFolder {
    <#
    .SYNOPSIS
        Remove a Folder
        It NEVER delete folder which contains other folders or items
        
        To get the Item Type detected during the deletion, use Get-SCCMFolderNode cmdlet to get the associated Name (Item Type = NodeID)
    .EXAMPLE
        Remove a folder named "test folder" under the node "Advertisements"
        $folderNode = Get-SCCMFolderNode -NodeName "Advertisements"
        $folder = Get-SCCMFolder -SccmServer $sccm -Filter "Name='test folder'" -FolderNodeID $folderNode
        Remove-SCCMFolder -SccmServer $sccm -FolderID $folder.ContainerNodeID
    #>
    [CmdletBinding()]
    PARAM (
        [Parameter(Mandatory=$true, HelpMessage="SCCM Server")][Alias("Server","SmsServer")][System.Object] $SccmServer,
        [Parameter(Mandatory=$true, HelpMessage="Folder ID", ValueFromPipeline=$true)][String] $FolderID
    )
 
    PROCESS {
        $folderObj = Get-SCCMFolder -SccmServer $SccmServer -Filter "ContainerNodeID='$FolderID'" | Select-Object -First 1
        if ($folderObj -eq $null) {
            $Host.UI.WriteErrorLine("No folder found with the ID $FolderID")
            return
        }
        
        $check = $false
        # Check if there are sub folders
        $subfolderObj = Get-SCCMFolder -SccmServer $SccmServer -Filter "ParentContainerNodeID='$FolderID'"
        if ($subfolderObj -ne $null) {$check = $true}
        
        $itemObj = Get-SCCMObject -SccmServer $SccmServer -Class "SMS_ObjectContainerItem" -Filter "ContainerNodeID='$FolderID'"
        if ($itemObj -ne $null) {$check = $true}
        
        if ($check) {
            Write-Host "Sub Folders AND/OR Items found! Delete them first:"
            foreach ($elt in $subfolderObj) {if ($elt -ne $null) {Write-Host "Folder: $($elt.Name) (ID $($elt.ContainerNodeID))"}}
            foreach ($elt in $itemObj) {if ($elt -ne $null) {Write-Host "Item: $($elt.InstanceKey) (Item Type: $($elt.ObjectType))"}}
        }
        else {
            # Delete folder
            $folderObj.Delete()
            Write-Verbose "Folder $($folderObj.Name) (ID $FolderID) deleted."
        }
    }
}

Function Remove-SCCMPackage {
    <#
    .SYNOPSIS
        Remove a Package
    .EXAMPLE
        Remove a package named "7Zip"
        $pkg = Get-SCCMPackage -SccmServer $sccm -Filter "Name='7Zip'"
        Remove-SCCMPackage -SccmServer $sccm -PackageID $pkg.PackageID
    #>
    [CmdletBinding()]
    PARAM (
        [Parameter(Mandatory=$true, HelpMessage="SCCM Server")][Alias("Server","SmsServer")][System.Object] $SccmServer,
        [Parameter(Mandatory=$true, HelpMessage="Package ID", ValueFromPipeline=$true)][String] $PackageID
    )
 
    PROCESS {
         # Get Package Object
        $pkObj = Get-SCCMPackage -sccmServer $SccmServer -Filter "PackageID='$PackageID'"
        if ($pkObj -eq $null) {
            $Host.UI.WriteErrorLine("No Package found with the ID $PackageID")
            return
        }
        Write-Verbose "Package found. Name= $($pkObj.Name)"
        
        # Check if the Package is advertised
        $advObj = Get-SCCMAdvertisement -SccmServer $SccmServer -Filter "PackageID='$PackageID'"
        if ($advObj -ne $null) {
            $advObj.Delete()
            Write-Host "An advertisement was found and deleted for this Package"
        }
        else {
            Write-Verbose "No advertisement found for this Package"
        }
        
        # Delete Package
        $pkObj.Delete()
        Write-Verbose "Package deleted"
    }
}

Function Remove-SCCMBootImagePackage {
    <#
    .SYNOPSIS
        Remove a Boot Image Package
    .EXAMPLE
        Remove a boot image package named "Windows 7 Ent SP1 x64"
        $pkg = Get-SCCMBootImagePackage -SccmServer $sccm -Filter "Name='Windows 7 Ent SP1 x64'"
        Remove-SCCMBootImagePackage -SccmServer $sccm -BootImagePackageID $pkg.PackageID
    #>
    [CmdletBinding()]
    PARAM (
        [Parameter(Mandatory=$true, HelpMessage="SCCM Server")][Alias("Server","SmsServer")][System.Object] $SccmServer,
        [Parameter(Mandatory=$true, HelpMessage="Boot Image Package ID", ValueFromPipeline=$true)][String] $BootImagePackageID
    )
 
    PROCESS {
         # Get Package Object
        $pkObj = Get-SCCMBootImagePackage -sccmServer $SccmServer -Filter "PackageID='$BootImagePackageID'"
        if ($pkObj -eq $null) {
            $Host.UI.WriteErrorLine("No Boot Image Package found with the ID $BootImagePackageID")
            return
        }
        Write-Verbose "Boot Image Package found. Name= $($pkObj.Name)"
        
        # Delete Boot Image Package
        $pkObj.Delete()
        Write-Verbose "Boot Image Package deleted"
    }
}

Function Remove-SCCMComputer {
    <#
    .SYNOPSIS
        Remove a Computer
    .EXAMPLE
        Remove a computer named "CLI-WIN7-01"
        $res = Get-SCCMComputer -SccmServer $sccm -NetbiosName "CLI-WIN7-01"
        Remove-SCCMComputer -SccmServer $sccm -ResourceID $res.ResourceID
    .EXAMPLE
        Remove all obsolete computers
        Remove-SCCMComputer -SccmServer $sccm -Obsolete
    #>
    [CmdletBinding()]
    PARAM (
        [Parameter(Mandatory=$true, HelpMessage="SCCM Server")][Alias("Server","SmsServer")][System.Object] $SccmServer,
        [Parameter(Mandatory=$false, HelpMessage="Resource ID", ValueFromPipeline=$true)][String] $ResourceID = "",
        [Switch] $Obsolete
    )
 
    PROCESS {
        if ($Obsolete) {
            # Delete all obsolete resources
            $resObj = Get-SCCMObject -sccmServer $SccmServer -class "SMS_R_System" -Filter "Obsolete=1"
            if ($resObj -eq $null) {
                Write-Host "No obsolete resource found"
            }
            else {
                $cpt = 1
                foreach ($elt in $resObj) {
                    Write-Verbose "Resource $($elt.NetbiosName) deleted"
                    $elt.Delete()
                    $cpt += 1
                }
                Write-Host "$cpt resources deleted"
            }
            
        }
        else {
            # Get Resource Object
            if ($ResourceID -eq "") {
                $Host.UI.WriteErrorLine("Type a Resource ID")
                return
            }
            
            $resObj = Get-SCCMComputer -sccmServer $SccmServer -ResourceID $ResourceID
            if ($resObj -eq $null) {
                $Host.UI.WriteErrorLine("No Resource found with the ID $ResourceID")
                return
            }
            Write-Verbose "Resource found. Name= $($resObj.NetbiosName)"
            
            # Delete Resource
            $resObj.Delete()
            Write-Verbose "Resource deleted"
        }
    }
}

Function Remove-SCCMReport {
   <#
    .SYNOPSIS
        Remove a Report
    .EXAMPLE
        Remove-SCCMReport -SccmServer $sccm -ReportID "456"
    #>
    [CmdletBinding()]
    PARAM (
        [Parameter(Mandatory=$true, HelpMessage="SCCM Server")][Alias("Server","SmsServer")][System.Object] $SccmServer,
        [Parameter(Mandatory=$true, HelpMessage="Report ID", ValueFromPipeline=$true)][String] $ReportID
    )
 
    PROCESS {
        $repObj = Get-SCCMReport -SccmServer $SccmServer -Filter "ReportID='$ReportID'"
        if ($repObj -eq $null) {
            $Host.UI.WriteErrorLine("No Report found with the ID $ReportID")
            return
        }
        Write-Verbose "Report found. Name= $($repObj.Name)"
        
        # Delete Advertisement
        $repObj.Delete()
        Write-Verbose "Report deleted."
    }
}

Function Remove-SCCMSUMDeploymentTemplate {
   <#
    .SYNOPSIS
        Remove a Software Updates Deployment Template
    .EXAMPLE
        Remove-SCCMSUMDeploymentTemplate -SccmServer $sccm -Name "test template"
    #>
    [CmdletBinding()]
    PARAM (
        [Parameter(Mandatory=$true, HelpMessage="SCCM Server")][Alias("Server","SmsServer")][System.Object] $SccmServer,
        [Parameter(Mandatory=$true, HelpMessage="SUM Template Name", ValueFromPipeline=$true)][String] $Name
    )
 
    PROCESS {
        $tplObj = Get-SCCMSUMDeploymentTemplate -SccmServer $SccmServer -Filter "Name='$Name'"
        if ($tplObj -eq $null) {
            $Host.UI.WriteErrorLine("No SUM Template found with the name $Name")
            return
        }
        Write-Verbose "SUM Template found. Name= $($tplObj.Name)"
        
        # Delete SUM Template
        $tplObj.Delete()
        Write-Verbose "SUM Template deleted."
    }
}

Function Remove-SCCMTaskSequence {
   <#
    .SYNOPSIS
        Remove a Task Sequence
    .EXAMPLE
        Remove-SCCMTaskSequence -SccmServer $sccm -TaskSequenceID "xxxxxxxx"
    #>
    [CmdletBinding()]
    PARAM (
        [Parameter(Mandatory=$true, HelpMessage="SCCM Server")][Alias("Server","SmsServer")][System.Object] $SccmServer,
        [Parameter(Mandatory=$true, HelpMessage="Task Sequence ID", ValueFromPipeline=$true)][String] $TaskSequenceID
    )
 
    PROCESS {
         # Get Task Sequence Object
        $tsObj = Get-SCCMTaskSequence -sccmServer $SccmServer -Filter "PackageID='$TaskSequenceID'"
        if ($tsObj -eq $null) {
            $Host.UI.WriteErrorLine("No Task Sequence found with the ID $TaskSequenceID")
            return
        }
        Write-Verbose "Task Sequence found. Name= $($tsObj.Name)"
        
        # Check if the TS is advertised
        $advObj = Get-SCCMAdvertisement -SccmServer $SccmServer -Filter "PackageID='$TaskSequenceID'"
        if ($advObj -ne $null) {
            foreach ($elt in $advObj) {
                Write-Host "Advertisement $($elt.AdvertisementName) was found and deleted from this Task Sequence"
                $elt.Delete()
            }
        }
        else {
            Write-Verbose "No advertisement found for this Task Sequence"
        }
        
        # Delete Task Sequence
        $tsObj.Delete()
        Write-Verbose "Task Sequence deleted"
    }
}

Function Clear-SCCMLastPXEAdvertisement {
   <#
    .SYNOPSIS
        Clear last PXE Advertisement of a specific resource or all resources of a collection
    .EXAMPLE
        Clear PXE Advertisement of all resources of the collection "test"
        $col = Get-SCCMCollection -SccmServer $sccm -Filter "Name='test'"
        Clear-SCCMLastPXEAdvertisement -SccmServer $sccm -CollectionID $col.CollectionID
    .EXAMPLE
        Clear PXE Advertisement of the computer "CLI-WIN7-01"
        Clear-SCCMLastPXEAdvertisement -SccmServer $sccm -ResourceName "CLI-WIN7
    #>
    [CmdletBinding()]
    PARAM (
        [Parameter(Mandatory=$true, HelpMessage="SCCM Server")][Alias("Server","SmsServer")][System.Object] $SccmServer,
        [Parameter(Mandatory=$false, HelpMessage="Collection ID", ValueFromPipeline=$true)][String] $CollectionID = "",
        [Parameter(Mandatory=$false, HelpMessage="Resource Name", ValueFromPipeline=$true)][String] $ResourceName = ""
    )
 
    PROCESS {
        # Get Collection Object
        if ($CollectionID -eq "" -and $ResourceName -eq "") {
            $Host.UI.WriteErrorLine("At least one criteria...")
            return
        }
        
        if ($CollectionID -ne "") {
            $collObj = Get-SCCMCollection -SccmServer $SccmServer -Filter "CollectionID='$CollectionID'"
            if ($collObj -eq $null) {
                $Host.UI.WriteErrorLine("No Collection found with the ID $CollectionID")
                return
            }            
            $collObj.ClearLastNBSAdvForCollection()
            Write-Verbose "Last PXE Advertisements deleted for the collection ID $CollectionID"
        }
        
        elseif ($ResourceName -ne "") {
            $compObj = Get-SCCMComputer -sccmServer $SccmServer -NetbiosName $ResourceName
            if ($compObj -eq $null) {
                $Host.UI.WriteErrorLine("No resource found with the name $ResourceName")
                return
            }
            $collectionClass = [WMICLASS]"\\$($SccmServer.Machine)\$($SccmServer.Namespace):SMS_Collection"
            $collectionClass.ClearLastNBSAdvForMachines($compObj.ResourceID)
            Write-Verbose "Last PXE Advertisement deleted for the resource $ResourceName"
        }
    }
}

# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
# Add/Update FVE | (c) Jeremy Young
Function Get-SCCMCollectionVariables {
<#
.SYNOPSIS
	Retrieves collection variables and their values from the SCCM site server WMI repository; if no CollectionID is passed in it will collect variables from all collections
#>
    [CmdletBinding()]
	PARAM (
        [Parameter(Mandatory=$true, HelpMessage="SCCM Server")][Alias("Server","SmsServer")][System.Object] $SccmServer,    
		[Parameter(Mandatory=$false,HelpMessage="Enter a CollectionID")][string]$CollectionID = ""
	)
    
    PROCESS {
        #setup a hash tables to hold the variables we find for each collection
        $Collections=@{}
    	
        #Get the variables for a single collection
    	if ($CollectionID -ne "") {
            #setup and object to hold the results
            $CollectionVariables=@{}
            
            # Retrieve the collection settings for the collectionID
            $CollectionSettings = Get-SCCMObject -sccmServer $SccmServer -class "SMS_CollectionSettings" -Filter "CollectionID = '$CollectionID'"

    		#process the results
            if ($CollectionSettings) {
                #collection variables is a lazy property so obtain a direct reference to the object using the __path found from the query
                $CollectionSettings=[wmi]"$($CollectionSettings.__PATH)"
            
                foreach ($CollVar in $CollectionSettings.CollectionVariables) {
                    $CollectionVariables.Add($CollVar.Name,$CollVar.Value)       
                }
    			
    			#add it to the results table
    			$Collections.Add($CollectionID,$CollectionVariables)            
            }
    		else {Write-Host "Collection [$CollectionID] contains no variables."}		
         }
    	 #No CollectionID passed in; get all collection variables
         else {        
            # Retrieve an the collection settings for all collections with settings
            $CollectionSettings = Get-SCCMObject -sccmServer $SccmServer -class "SMS_CollectionSettings"

    		#process the results
            foreach ($Coll in $CollectionSettings) {            
                #collection variables is a lazy property so obtain a direct reference to the object using the __path found from the query
                $Coll=[wmi]"$($Coll.__PATH)"
                
                #check that it has variables
                if ($Coll.CollectionVariables.Count -gt 0) {
                    #declare a hash table to hold the vars name/value
                    $CollectionVariables=@{}
                    
                    foreach ($CollVar in $Coll.CollectionVariables) {
                        #add each var to a hash table
                        $CollectionVariables.Add($CollVar.Name,$CollVar.Value)       
                    }
                    
                    #add the hash table to the other hash table keying on collectionID
                    $Collections.Add($Coll.CollectionID,$CollectionVariables)            
                }
            }
        }
        return $Collections
    }
}

Function New-SCCMCollectionVariable {
<#
.SYNOPSIS
	Creates a collection variable and assigns a value to it for the CollectionID passed in.
#>
    [CmdletBinding()]
    PARAM (
        [Parameter(Mandatory=$true, HelpMessage="SCCM Server")][Alias("Server","SmsServer")][System.Object] $SccmServer,
		[Parameter(Mandatory=$true,HelpMessage="Enter the new Variable Name")]	[string]$VariableName,
		[Parameter(Mandatory=$true,HelpMessage="Enter the new Variable Value")][string]$VariableValue,
		[Parameter(Mandatory=$true,HelpMessage="Enter the CollectionID")][string]$CollectionID
	)
    
    PROCESS {
        # Retrieve an the collection settings for the collectionID
        $CollectionSettings = Get-SCCMObject -sccmServer $SccmServer -class "SMS_CollectionSettings" -Filter "CollectionID = '$CollectionID'"

    	#check if collection settings exists for this collection
        if (!$CollectionSettings) {
            #if not then create the collection settings object
            $arguments = @{CollectionID=$CollectionID}
            $CollectionSettings = Set-WmiInstance -class "SMS_CollectionSettings" -arguments $arguments -computername $SccmServer.Machine -namespace $SccmServer.Namespace
        }

        #check that the collection settings object exists now
        if ($CollectionSettings) {
            #collection variables is a lazy property so obtain a direct reference to the object using the __path found from the query
            $refCollectionSettings=[wmi]"$($CollectionSettings.__PATH)"
            
            #create a collection variable instance and populate it
            $wmiClassVariable = [WMICLASS]("\\" + $SccmServer.Machine + "\" + $SccmServer.Namespace + ":SMS_CollectionVariable")
            
            #get an array to hold the vars
            $Vars = New-Object System.Collections.ArrayList
            
    		#create a new variable object and assign the passed in value
            $NewVar=$wmiClassVariable.Createinstance()
            $NewVar.Name = $VariableName
            $NewVar.Value = $VariableValue
                                  
            #update the array of variables in the object with any existing vars and check if the new var name exists
            if ($refCollectionSettings.CollectionVariables.Count -gt 0) {
                foreach ($Var in $refCollectionSettings.CollectionVariables) {
                    #if the name matches the new var then skip it and we will update the new value later
                    if ($Var.Name -ne $NewVar.Name) {
                        $Vars.Add($Var)
                    }
                }
            }
            
            #add the new var
            $Vars.Add($NewVar)
            
    		#assign the new collection variables array
            $CollectionSettings.CollectionVariables = $Vars
            
            #save the object to WMI
            $CollectionSettings.Put()
            Write-Verbose "Collection Variabled added"
        }
        else {
           $Host.UI.WriteErrorLine("Error creating the collection settings for $CollectionID")
        }
    }
}

Function Remove-SCCMCollectionVariable {
<#
.SYNOPSIS
	Removes the variable from the CollectionID passed in
#>
    [CmdletBinding()]
    PARAM (
        [Parameter(Mandatory=$true, HelpMessage="SCCM Server")][Alias("Server","SmsServer")][System.Object] $SccmServer,
		[Parameter(Mandatory=$true,HelpMessage="Enter the Variable Name to Remove")][string]$VariableName,
		[Parameter(Mandatory=$true,HelpMessage="Enter the CollectionID")][string]$CollectionID
	)

    PROCESS {
        # Retrieve an the collection settings for the collectionID
        $CollectionSettings = Get-SCCMObject -sccmServer $SccmServer -class "SMS_CollectionSettings" -Filter "CollectionID = '$CollectionID'"

        #check that the collection settings object exists
        if ($CollectionSettings) {
            #collection variables is a lazy property so obtain a direct reference to the object using the __path found from the query
            $refCollectionSettings=[wmi]"$($CollectionSettings.__PATH)"
            
    		#check if the variable to remove exists
    		if ($refCollectionSettings.CollectionVariables | Where-Object {$_.Name -eq $VariableName}) {
    			#get an array to hold the vars
    	        $Vars = New-Object System.Collections.ArrayList
    	        
    	        #update the array of variables in the object with any existing vars
    	        if ($refCollectionSettings.CollectionVariables.Count -gt 0) {
    	            foreach ($Var in $refCollectionSettings.CollectionVariables) {
    	                #if the name matches then skip it
    	                if ($Var.Name -ne $VariableName) {
    	                    $Vars.Add($Var)
    	                }
    	            }
    	        }
    	        $CollectionSettings.CollectionVariables = $Vars
    	        
    	        #save the new object
    	        $CollectionSettings.Put()
                Write-Verbose "Collection Variable removed"
    		}
    		else {Write-Host "[$CollectionID] does not contain variable [$VariableName]"}
        }
        else {
            Write-Verbose "[$CollectionID] contains no variables; nothing to remove"
        }
    }
}

Function Clear-SCCMCollectionVariables {
<#
.SYNOPSIS
	Removes all collection variables from the CollectionID passed in
#>
    [CmdletBinding()]
    PARAM (
        [Parameter(Mandatory=$true, HelpMessage="SCCM Server")][Alias("Server","SmsServer")][System.Object] $SccmServer,
		[Parameter(Mandatory=$true,HelpMessage="Enter the CollectionID")][string]$CollectionID
	)
    
    PROCESS {
        # Retrieve an the collection settings for the collectionID
        $CollectionSettings = Get-SCCMObject -sccmServer $SccmServer -class "SMS_CollectionSettings" -Filter "CollectionID = '$CollectionID'"

        #check that the collection settings object exists
        if ($CollectionSettings) {
            #get an array to hold the vars
            $BlankVars = New-Object System.Collections.ArrayList
            
            #replace the variables array with this blank one
            $CollectionSettings.CollectionVariables = $BlankVars
            
            #save the new object
            $CollectionSettings.Put()
            Write-Verbose "Collection Variables cleared"
        }
        else {
            Write-Verbose "$CollectionID contains no variables"
        }
    }
}

Function Get-SCCMCollectionVariablePrecedence {
<#
.SYNOPSIS
	Returns the variable precedence on the CollectionID passed in.
#>
    [CmdletBinding()]
    PARAM (
        [Parameter(Mandatory=$true, HelpMessage="SCCM Server")][Alias("Server","SmsServer")][System.Object] $SccmServer,
		[Parameter(Mandatory=$true,HelpMessage="Enter the CollectionID")][string]$CollectionID
	)
    
    PROCESS {
        # Retrieve an the collection settings for the collectionID
        $CollectionSettings = Get-SCCMObject -sccmServer $SccmServer -class "SMS_CollectionSettings" -Filter "CollectionID = '$CollectionID'"
        
    	if ($CollectionSettings) {
        	Write-Host "Collection [$CollectionID] variable precedence is set to [$($CollectionSettings.CollectionVariablePrecedence)]"
    	}
    	else {Write-Verbose "[$CollectionID] has no collection settings."}
    }
}

Function Set-SCCMCollectionVariablePrecedence {
<#
.SYNOPSIS
	Sets the variable precedence on the CollectionID passed in.
#>
    [CmdletBinding()]
    PARAM (
        [Parameter(Mandatory=$true, HelpMessage="SCCM Server")][Alias("Server","SmsServer")][System.Object] $SccmServer,
		[Parameter(Mandatory=$true,HelpMessage="Enter the Collection Variable Precedence")][int]$VariablePrecedence, 
		[Parameter(Mandatory=$true,HelpMessage="Enter the CollectionID")][string]$CollectionID
	)
    
    PROCESS {
        # Retrieve an the collection settings for the collectionID
        $CollectionSettings = Get-SCCMObject -sccmServer $SccmServer -class "SMS_CollectionSettings" -Filter "CollectionID = '$CollectionID'"
        
        #update the int and put the object back
    	if ($CollectionSettings) {
    	    $CollectionSettings.CollectionVariablePrecedence = $VariablePrecedence
    	    $out=$CollectionSettings.Put()
    		#get the new variable precedence value
    		return Get-SCCMCollectionVariablePrecedence -sccmServer $SccmServer -CollectionID $CollectionID
    	}
    	else {Write-Host "[$CollectionID] has no collection settings."}
    }
}
# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
# Add FVE | (c) Stephane Van Gulick
########################################################################### 
# 
# NAME: New-SccmAppVPackage 
# 
# AUTHOR:  stephane van gulick 
# 
# COMMENT: New-SccmAppVpackage - www.PowerShellDistrict.com 
# 
# VERSION HISTORY: 
# 1.0 08/08/2012 - Final release 
# 
########################################################################### 
  
Function New-SCCMAppVPackage { 
 <# 
.SYNOPSIS 
    Function to create an App-V package in SCCM 2007 
  
.DESCRIPTION 
    Creates a AppvPackage in Sccm 2007 environement  

.PARAMETER SccmServer 
    Specify the Sccm connection variable (Initialized before through the Connect-SccmServer command, from the SCCM-Commands module.) 
    
.PARAMETER AppName 
    The application name 
  
.PARAMETER smsShare 
    Specify the "Share destination" (The stagging folder) where the AppVpackage will be copied to. 
  
.PARAMETER ApplicationNameSourceFolder 
    Specify the source folder of the AppV original package. (This folder must contain the .SprJ file,.sft and the .OSD files) 
  
.PARAMETER Manufacturer 
    The application manufacturer name.

.PARAMETER Language 
    Language of the application 
  
.PARAMETER Whatif 
    Permits to launch this script in "draft" mode. This means it will only show the results without really making generating the files. 
  
.PARAMETER Verbose 
    Allow to run the script in verbose mode for debbuging purposes. 
  
.EXAMPLE 
    New-SccmAppVPackage -SCCMServer $con -ApplicationNameSourceFolder "\\MyDomain\DP01_it\Applications$\Mozilla_Firefox_3.6.3_FR\V01" -AppName "Firefox" -Language "FR" -Manufacturer "Mozilla" -Description "Created by Stéphane van Gulick for www.PowershellDistrict.com" -smsShare "\\MyDomain\DP01_it\Applications$\__AppV_Staging__" 
  
    -Will create an AppVPAckage with the following details : 
        -The folder containing all the source files : 
            "\\MyDomain\DP01_it\Applications$\Mozilla_Firefox_3.6.3_FR\V01" 
        -ApplicationName 
            "FireFox" 
        -Language 
            "French" (FR) 
        -Manufacturer 
            "Mozilla" 
        -Description 
            "Created by Stéphane van Gulick for www.PowershellDistrict.com"  
        -AppV stagging folder  
            "\\MyDomain\DP01_it\Applications$\__AppV_Staging__" 
  
.NOTES 
    -Author: Stephane van Gulick 
    -Email : svangulick@gmail.com 
     www.powershellDistrict.com 
    -LastModifiedDate: 08/08/2012 
    -Version: 1.0 
  
.LINK 
  
http://www.powershellDistrict.com 
  
#>
  
    [CmdletBinding(SupportsShouldProcess=$true)] 
    PARAM (
        [Parameter(Mandatory=$true, HelpMessage="SCCM Server name where the application will be created on.")][System.Object] $SCCMServer, #SMS server name where the package will be created 
        [Parameter(Mandatory=$true, HelpMessage="Application Name")][String] $AppName, #ApplicationName 
        [Parameter(Mandatory=$false, HelpMessage="Manufucturer of the application")][String] $Manufacturer, #The manufacturer of the application 
        [Parameter(Mandatory=$true, HelpMessage="The Stagging folder where the app-v packages will be copied to for extra treatement.")][String] $SmsShare,#App-V Stagging folder 
        [Parameter(Mandatory=$true, HelpMessage="Source folder of the application of the original App-V package.")][String] $ApplicationNameSourceFolder, #Source Folder of the appvPackage 
        [Parameter(Mandatory=$false, HelpMessage="Description of the application")][String] $Description, 
        [Parameter(Mandatory=$false, HelpMessage="Language of the App-V Package.")][String] $Language #The language that the package will have. 
  
        #[Parameter(Mandatory=$false, HelpMessage="SCCM site where the application needs to be created on.")]$site, #SMS site name (trigram) 
    ) 
  
    BEGIN { 
        Write-Verbose "Starting App-V integration process"
    } 
    PROCESS { 
        #Region Variables 
        $ApplicationName = $Manufacturer + "_" + $AppName
        $ApplicationFolder = Join-Path -Path $smsShare -ChildPath $ApplicationName
        #EndRegion 
  
        #Region AppVStaging 
  
        #Creating the appVStaging folder 
        try { 
            $Destination = "$smsShare\$ApplicationName\"
            New-Item  "$smsShare\$ApplicationName\" -Type Directory -Force | Out-Null -ErrorAction Stop 
        } 
        catch { 
            Write-Host "Error :" $_ "Could not create the AppVstagging folder $($Destination)"
        } 
  
        Write-Verbose "App-V Destination Stagging folder will be : $($destination)"
  
        #AppShare = Location of the AppVSource files 
  
        if (Test-Path $ApplicationNameSourceFolder) { 
            Write-Verbose "Copying content of $($ApplicationNameSourceFolder) to $($destination)"
            Copy-Item $ApplicationNameSourceFolder\* -Destination $Destination -Recurse -Force
            Write-Verbose "Copy sucesfull of $($ApplicationNameSourceFolder) to $($destination)"
        } 
        else { 
            Write-Host "Couldn't copy $($ApplicationNameSourceFolder) to $($destination). Quiting" -ForegroundColor "red"
            exit 
        } 
  
        #EndRegion 
  
        #Region XmlManifest 
        Write-Verbose "----XML Manifest section----"
        #Getting the XML Manifest 
        #Eventually change *xml to manifest.xml 
        try { 
            Write-Verbose "Checking for the Manifest.xml file"
            $Manfst = Get-ChildItem "$smsShare\$ApplicationName\*manifest.xml" -Name
        } 
        catch{ 
            Write-Host "Impossible to locate the Manifest.xml file in $smsShare\$ApplicationName\ . Quiting"
            exit 
        } 
  
        #Importing Xml manifest 
        Write-Verbose "Importing $($smsShare)\$($ApplicationName)\$($Manfst)"
        [xml]$Manifest = Get-Content "$smsShare\$ApplicationName\$Manfst"
  
        #Getting AppVPackage information 
        $Name = $Manifest.Package.Name 
        $GUID = $Manifest.Package.GUID 
        $Version = $Manifest.Package.VersionGuid 
        $Name = $Manifest.Package.Name 
  
        #Generating the commandLine 
        Write-Verbose "Generating the command line"
        $Commandline = "PkgGUID=" + "$GUID" + ":VersionGUID=" + "$Version"
  
        #Create the extended data variable. 
        Write-Verbose "Creating extended data"
        $exData = [Text.Encoding]::UTF8.GetBytes($Version) 
        $exDataSize = $exData.getupperbound(0) + 1 
  
        #EndRegion 
  
        #Region OSD 
        #Getting OSD 
        Write-Verbose "----OSD section----"
        Write-Verbose "Working on the OSD settings. Searching for OSD file in $($applicationFolder)"
        $childs = Get-ChildItem $ApplicationFolder
        foreach ($file in $childs) { 
            if ($file.extension -eq ".osd") { 
                #Importing OSD data (XML format) 
                Write-Verbose "OSD file found at $($file.fullname)"
                Write-Verbose "importing $($file.fullname) and extracting App-V package information."
                [xml]$OSD = Get-Content $file.fullname 
  
                #Getting OSD information from OSD file 
                $PkgGUID = $OSD.Softpkg.GUID 
                $PkgName = $OSD.Softpkg.Name 
                $PkgVers = $OSD.Softpkg.Version   
            } 
        } 
  
        #EndREgion 
  
        #Region AppVPackage 
        Write-Verbose "----App-V PAckage section----"
        #Creating a hastable with all the required arguments for the creation of the AppvPackage 
        $argumentsPackage = @{Name = "$Name"; 
            Manufacturer = $Manufacturer; 
            Description = $Description; 
            ExtendedData = $exData; 
            ExtendedDataSize = $exDataSize; 
            Version = $PkgVers; 
            Language = $language; 
            PackageType = 7; 
            PkgFlags = 104857600; 
            PkgSourceFlag = 2; 
            PkgSourcePath = "$smsShare\$ApplicationName\"
        } 
        #Creating the Package through WMI 
  
        try { 
            Write-Verbose "Creating the Appv Package"
            $SetPkg = Set-WmiInstance -ComputerName $SCCMServer.machine -class SMS_Package -Arguments $argumentsPackage -Namespace $SCCMServer.Namespace 
            Write-Verbose "$($setpkg) has been created successfully"
        } 
        catch { 
            Write-Host "$_ Errorduring the creating of the package App-V. Quiting" -ForegroundColor Red 
            exit 
        } 
        #Getting application where Application Name = $ApplicationName (It will not work if error above) 
        $Package = Get-WmiObject -ComputerName $SCCMServer.Machine -Namespace $SCCMServer.Namespace -Query "Select * from SMS_Package WHERE Name = '$Name'"
  
        #Getting PackageID 
        $PackageID = $Package.PackageID 
  
        #EndRegion 
  
        #Region SFT+SPRJ 
        Write-Verbose "----SFT and SPRJ section----"
        #Renaming SFT 
        Write-Verbose "Renaming sft to $($PackageID).sft"
  
        foreach ($file in (Get-ChildItem $smsShare\$ApplicationName\)) { 
            if ($file.extension -eq "sft") { 
                Rename-Item "$smsShare\$ApplicationName\*.sft" "$PackageID.sft"
            } 
        } 
  
        #Deleting .SPRJ 
        Write-Verbose "Deleting the sprj file"
        Remove-Item "$smsShare\$ApplicationName\*.sprj" -Force
  
        #EndRegion 
  
        #Region ProgramCreation 
  
        Write-Verbose "----Program Section----"
  
        #Creating arguments for Program creation 
        $argumentsProgram = @{ 
            PackageID = $Package.PackageID; 
            ProgramFlags = "135307273"; 
            ProgramName = "[Virtual application]"; 
            CommandLine = "$Commandline"
        } 
        #Creating the program (WMI) 
        try { 
            Write-Verbose "Creating the Program for the Appv Package"
            $SetPrg = Set-WmiInstance -ComputerName $SCCMServer.Machine -Class SMS_Program -Arguments $argumentsProgram -Namespace $SCCMServer.Namespace 
            Write-Verbose "$SetPrg created sucessfully"
        } 
        catch { 
            Write-Host "$_ error while creating the AppV Program. Quiting" -ForegroundColor Red 
            exit 
        } 
        #EndRegion 
  
        #Region SFTRename 
        $i = 0 
        foreach ($f in $childs) { 
            if($f.extension -eq ".sft") { 
                Write-Verbose "Renaming $f.fullname to $($pkguid.sft)"
                Rename-Item -Path $f.fullname -NewName "$PkgGUID.sft" 
            } 
        } 
  
        #EndRegion       
  
        #Region Icons 
  
        Write-Verbose "----Icons section----"
        if ($OSD.Softpkg.MGMT_Shortcutlist.Shortcut.count -like "") { 
            $RawIcon = $OSD.Softpkg.MGMT_Shortcutlist.Shortcut.Icon 
        }  
        else { 
            $RawIcon = $OSD.Softpkg.MGMT_Shortcutlist.Shortcut[0].Icon 
        } 
  
        $RawIcon = $RawIcon -replace "/", "\" 
        $Icon = $RawIcon -replace "%SFT_MIME_SOURCE%", $ApplicationFolder 
  
        #Reading icon properties  
        $Obj = New-Object -ComObject ADODB.Stream 
        $Obj.Open() 
        $Obj.Type = 1 
        $Obj.LoadFromFile("$Icon") 
        $IconData = $Obj.Read() 
        $IconSize = $IconData.getupperbound(0) + 1 
  
        #EndRegion 
  
        #Region AppVInstanceCreation  
        Write-Verbose "----VirtualApp instance creation----" 
        $argumentsApps = @{ 
            GUID = "$PkgGUID"; 
            IconSize = $IconSize; 
            Icon = $IconData; 
            PackageID = $Package.PackageID; 
            Name = "$PkgName"; 
            Version = "$PkgVers" 
        } 
  
        $VApp = Set-WmiInstance -Computername $SCCMServer.machine -class SMS_VirtualApp -arguments $argumentsApps -namespace $SCCMServer.namespace 
        #EndRegion 
  
        Write-Verbose "End of App-V package creation process" 
    }

    END { 
        #Returning object 
        return $VApp
    } 
}
# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
# EOF