# Description
This script is used to send a mail HTML report of a specific ADR with following information:
- Approved updates by the ADR
- Deployment schedules set for the ADR

This script must be run on a machine containing SCCM console.

I suggest you to create a scheduled task to automatically send the report each month.

# How to use it
## Edit the XML file (settings.xml by default)
- *adrlist* node

It's possible to add several ADRs.
For each, set a *title* and the ADR *name*
It will send a mail for each ADR.

- *mail* node

Set the SMTP *server* FQDN

Set the sender (*from*) address

Set the recipient (*to*) address(es), by separing email addresses with "," if needed

Set the carbon copy (*cc*) address(es), by separing email addresses with "," if needed

Set the blind carbon copy (*bcc*) address(es), by separing email addresses with "," if needed


## Run the script
ADRReport.ps1 -File "*XML_settings_file*"

## Remarks
Reports are saved in a Reports folder under the script root path.
If a report already exists, the script skip the corresponding ADR.
