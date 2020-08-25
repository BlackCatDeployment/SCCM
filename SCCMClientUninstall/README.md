# Description
This script uninstalls SCCM Client from a list of devices.
It performs a ccmsetup /uninstall + files and registry keys removal for a total cleanup.

# How to use it
## Edit the list file (List.txt by default)
Add all devices where the SCCM Client has to be removed.

## Run the script
Run the *_Launcher.cmd* as administrator.
Fill user credentials that is administrator of listed devices.

## Log files
- Deploy.log

Summary of the execution

- DeployStates_<yyyyMMddHHmmss>.csv

CSV file summarize uninstallation status of the list of devices

Exit codes:

0  : Success

1  : SCCM Client not installed

2  : Cannot run the uninstallation program

6  : SCCM Client install failed! Check the log on the computer

7  : SCCM Client installed successfully but the computer needs a restart

9  : SCCM Client install failed! Prerequisite evaluation failure

10 : SCCM Client install failed! Setup manifest hash validation failure

53 : Device unreachable on SMB port

65 : Credentials used cannot access to the device

 
 - CCM_uninstall.log
 
Under C:\Windows\Temp of each listed device
Summary of the uninstallation script
