# SCCM 2007 cmdlets

## Description

This PowerShell module is used to perform actions on a **SCCM 2007** server.

## How to use it

Save the file as SCCM-Commands.psm1
Enter this command in a PowerShell prompt from a SCCM 2007 server:
PS:>Import-Module SCCM-Commands
PS:>Get-SCCMCommands

## Cmdlets available

Cmdlet | Description | Parameters | Status
------ | ----------- | ---------- | ------
Add-SCCMCollectionRule | Add a Rule (Direct or WQL Query) to a collection | SccmServer<br/>CollectionID<br/>RuleName<br/>ResourceName<br/>QueryExpression<br/>LimitToCollectionID | Native
Add-SCCMDistributionPoint | Add a Distribution Point |SccmServer<br/>DPPackageID<br/>DPName<br/>DPsSiteCode<br/>DPGroupName<br/>AllDPs | Native
Connect-SCCMServer | Connect to one SCCM server | HostName<br/>SiteCode<br/>Credential | Native
Get-SCCMAdvertisement | Get Advertisement | SccmServer<br/>Filter | Native
Get-SCCMBootImagePackage | Get Boot Image Package | SccmServer<br/>Filter | Native
Get-SCCMCollection | Get Collection | SccmServer<br/>Filter | Native
Get-SCCMCollectionMembers | Get Collection Members | SccmServer<br/>CollectionID |Native
Get-SCCMCollectionRules | Get Collection Rules | SccmServer<br/>CollectionID | Native
Get-SCCMCommands | Display all SCCM cmdlets available | | Native
Get-SCCMDriver | Get Driver | SccmServer<br/>Filter | Native
Get-SCCMDriverPackage | Get Driver Package | SccmServer<br/>Filter | Native
Get-SCCMImagePackage | Get Image Package | SccmServer<br/>Filter | Native
Get-SCCMInboxes | Get Inboxes | SccmServer<br/>minCount | Native
Get-SCCMIsR2 | Get if R2 is installed | SccmServer | Native
Get-SCCMObject | Get an SCCM Object based on WMI classes | SccmServer<br/>Class<br/>Filter | Native
Get-SCCMOperatingSystemInstallPackage | Get Operating System Install Package | SccmServer<br/>Filter | Native
Get-SCCMPackage | Get Package | SccmServer<br/>Filter | Native
Get-SCCMParentCollection | Get Parent Collection of a Collection | SccmServer<br/>CollectionID | Native
Get-SCCMSite | Get SCCM Site Information | SccmServer<br/>Filter | Native
Get-SCCMSiteDefinition | Get SCCM Site Definition | SccmServer | Native
Get-SCCMSiteDefinitionProps | Get SCCM Site Definition Properties | SccmServer | Native
Get-SCCMSubCollections | Get sub Collections of a collection | SccmServer<br/>CollectionID | Native
Get-SCCMUser | Get SCCM User | SccmServer<br/>ResourceID<br/>UniqueUserName<br/>WindowsNTDomain<br/>UserName | Native
New-SCCMProgram | Create a new Program | SccmServer<br/>PrgName<br/>PrgPackageID<br/>PrgComment<br/>PrgCommandLine<br/>PrgMaxRunTime<br/>PrgSpaceReq<br/>PrgWorkDir<br/>PrgFlags | Native
Update-SCCMDriverPkgSourcePath | Update Driver Package Source Path | SccmServer<br/>CurrentPath<br/>NewPath | Native
Update-SCCMDriverSourcePath | Update Driver Source Path | SccmServer<br/>CurrentPath<br/>NewPath | Native
Update-SCCMPackageSourcePath | Update Package Source Path | SccmServer<br/>CurrentPath<br/>NewPath | Native
Clear-SCCMLastPXEAdvertisement | Clear Last PXE Advertisement | SccmServer<br/>CollectionID<br/>ResourceName | New
Copy-SCCMTaskSequence | Copy Task Sequence | SccmServer<br/>TaskSequenceID<br/>NewName<br/>FolderID<br/>Description<br/>CustomText<br/>Duration | New
Export-SCCMTaskSequence | Export Task Sequence | SccmServer<br/>TaskSequenceID<br/>Path | New
Get-SCCMDCMAssignment | Get Desired Configuration Management | SccmServer<br/>CollectionID | New
Get-SCCMFolder | Get Folder | SccmServer<br/>Filter<br/>FolderNodeID<br/>ParentFolderID | New
Get-SCCMFolderNode | Get folder Node (like Packages, Advertisements, Task Sequences, …) | NodeName | New
Get-SCCMIsR3 | Get if R3 is installed || New
Get-SCCMReport | Get Report | SccmServer<br/>Filter | New
Get-SCCMSUMDeploymentTemplate | Get Software Updates Deployment Template | SccmServer<br/>Filter | New
Get-SCCMSUMUpdatesInfo | Get Software Updates Information | SccmServer<br/>ArticleID<br/>Severity<br/>Downloaded<br/>Deployed | New
Import-SCCMTaskSequence | Import Task Sequence | SccmServer<br/>Name<br/>Path<br/>FolderID<br/>Description<br/>CustomText<br/>Duration | New
New-SCCMFolder | Create a new folder | FolderName<br/>FolderNodeID<br/>ParentFolderID | New
New-SCCMSUMDeploymentTemplate | Create a new Software Updates Deployment Template | SccmServer<br/>Name<br/>Description<br/>CollectionID<br/>Duration<br/>DurationUnit<br/>IncludeSubCollection<br/>AllowNotification<br/>ScheduleUTC<br/>RestartServers<br/>RestartWorkstations<br/>RestartOutsideMaintenance<br/>DownloadFromLocalDP<br/>DownloadFromUnprotectedDP | New
Remove-SCCMAdvertisement | Remove Advertisement | SccmServer<br/>AdvertisementID | New
Remove-SCCMBootImagePackage | Remove Boot Image Package | SccmServer<br/>BootImagePackageID | New
Remove-SCCMCollection | Remove Collection | SccmServer<br/>CollectionID<br/>Force | New
Remove-SCCMCollectionRule | Remove Collection Rule | SccmServer<br/>CollectionID<br/>RuleName | New
Remove-SCCMComputer | Remove Computer | SccmServer<br/>ResourceID<br/>Obsolete | New
Remove-SCCMDriverPackage | Remove Driver Package | SccmServer<br/>DriverPackageID | New
Remove-SCCMFolder | Remove Folder | SccmServer<br/>FolderID | New
Remove-SCCMPackage | Remove Package | SccmServer<br/>PackageID | New
Remove-SCCMReport | Remove Report | SccmServer<br/>ReportID | New
Remove-SCCMSUMDeploymentTemplate | Remove Software Updates Deployment Template | SccmServer<br/>Name | New
Remove-SCCMTaskSequence | Remove Task Sequence | SccmServer<br/>TaskSequenceID | New
Add-SCCMDirUserCollectionRule | Add a User Rule to a Collection | SccmServer<br/>CollectionID<br/>UserName | Update
Clear-SCCMCollectionVariables | Removes all collection variables from the CollectionID passed in parameter | SccmServer<br/>CollectionID | Update
Get-SCCMCollectionVariablePrecedence | Returns the variable precedence on the CollectionID passed in parameter | SccmServer<br/>CollectionID | Update
Get-SCCMCollectionVariables | Retrieves collection variables and their values from the SCCM site server WMI repository; if no CollectionID is passed in it will collect variables from all collections | SccmServer<br/>CollectionID | Update
Get-SCCMComputer | Get Computer | SccmServer<br/>ResourceID<br/>NetbiosName<br/>Obsolete | Update
Get-SCCMTaskSequence | Get Task Sequence | SccmServer<br/>Filter | Update
New-SCCMAdvertisement | Create a new Program or Task Sequence Advertisement | SccmServer<br/>AdvertisementName<br/>CollectionID<br/>PackageID<br/>ProgramName<br/>FolderID<br/>Priority<br/>RerunBehavior<br/>StartTime<br/>EndTime<br/>MandatoryTime<br/>Download<br/>IncludeSubCollection<br/>EnableWOL<br/>IgnoreMaintenance<br/>AllowRestart<br/>TSUseRemoteDP<br/>TSUseUnprotectedDP<br/>TSShowProgressBar | Update
New-SCCMCollection | Create a new Collection | SccmServer<br/>Name<br/>Comment<br/>DynamicAddResources<br/>RefreshMinutes<br/>RefreshHours<br/>RefreshDays<br/>ParentCollectionID | Update
New-SCCMPackage | Create a new Package | SccmServer<br/>Name<br/>Version<br/>Manufacturer<br/>Language<br/>Description<br/>PkgSourcePath<br/>PkgShareName<br/>FolderID | Update
New-SCCMAppVPackage | Creates an App-V Package | SccmServer<br/>AppName<br/>smsShare<br/>ApplicationNameSourceFolder<br/>Manufacturer<br/>Language | Update
New-SCCMCollectionVariable | Creates a collection variable and assigns a value to it for the CollectionID passed in parameter | SccmServer<br/>VariableName<br/>VariableValue<br/>CollectionID | Update
Remove-SCCMCollectionVariable | Removes the variable from the CollectionID passed in parameter | SccmServer<br/>VariableName<br/>CollectionID | Update
Set-SCCMCollectionVariablePrecedence | Sets the variable precedence on the CollectionID passed in parameter | SccmServer<br/>VariablePrecedence<br/>CollectionID | Update

## Notes

Thanks to [Michael Niehaus](http://blogs.technet.com/mniehaus/), [Rikard Ronnkvist](http://www.snowland.se/sccm-posh/) and Stefan Ringler for their scripts basis.