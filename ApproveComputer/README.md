# Description
This script is used to automatically approve computers and send a mail HTML report.

This script must be run on a machine containing SCCM console.

I suggest you to create a scheduled task to automatically run the script every hour.

# How to use it
## Edit the XML file (settings.xml by default)
- *collections* node

It's possible to add several collections.
For each, set a *name*

- *mail* node

Set the SMTP *server* FQDN

Set the sender (*from*) address

Set the recipient (*to*) address(es), by separing email addresses with "," if needed

Set the carbon copy (*cc*) address(es), by separing email addresses with "," if needed

Set the blind carbon copy (*bcc*) address(es), by separing email addresses with "," if needed


## Run the script
ApproveComputer.ps1 -File "*XML_settings_file*"

## Remarks
Reports are saved in a Reports folder under the script root path.
If no computer needs to be approved, no report and mail are sent.
