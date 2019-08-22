# Description
This script is used to generate a report of ADR executions and send a mail HTML report.

This script must be run on a machine containing SCCM console.

I suggest you to create a scheduled task to automatically run the script every hour.

# How to use it
## Edit the XML file (settings.xml by default)
- *cmpath* node

SCCMPRIMARY = Primary SCCM Server

SITECODE = trigram of the SCCM Site Code (ex: PP1)

- *mail* node

Set the SMTP *server* FQDN

Set the sender (*from*) address

Set the recipient (*to*) address(es), by separing email addresses with "," if needed

Set the carbon copy (*cc*) address(es), by separing email addresses with "," if needed

Set the blind carbon copy (*bcc*) address(es), by separing email addresses with "," if needed


## Run the script
CheckADRExecution.ps1 -File "*XML_settings_file*"

## Remarks
Reports are saved in a Reports folder under the script root path.

If no ADR was found, no report and mail are sent.
