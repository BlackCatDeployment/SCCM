# Description
This script is used to send by email a Distribution Points health state HTML report.

This script must be run on a machine containing SCCM console.

I suggest you to create a scheduled task to automatically run the script every day.

# How to use it
## Edit the XML file (settings.xml by default)

- *mail* node

Set the SMTP *server* FQDN

Set the sender (*from*) address

Set the recipient (*to*) address(es), by separing email addresses with "," if needed

Set the carbon copy (*cc*) address(es), by separing email addresses with "," if needed

Set the blind carbon copy (*bcc*) address(es), by separing email addresses with "," if needed


## Run the script
DPStatus.ps1

## Remarks
Reports are saved in a Reports folder under the script root path.

