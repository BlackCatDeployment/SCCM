# Description
This script is used to automatically perform following actions on Software Updates that are moved in a specific folder:
- Remove them from Software Update Groups
- Set a custom severity

This script must be run on a machine containing SCCM console.

I suggest you to create a scheduled task to automatically run the script every 6 hours.

# How to use it
## Edit the XML file (settings.xml by default)
- *folder* node

Set the folder name used for updates exclusion under "All Software Updates" node 

- *customseverity* node

Set the custom severity to apply to all software updates located in the *folder*

## Run the script
ManageExcludeUpdates.ps1 -File "*XML_settings_file*"

