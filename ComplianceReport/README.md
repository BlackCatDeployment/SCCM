# Description
This script is used to automatically send a mail HTML report containing all collection members created in the corresponding folder.

This script must be run on a machine containing SCCM console.

I suggest you to create a scheduled task to automatically run the script every week.

# How to use it
## Edit the XML file (settings.xml by default)
- *report* node

Set the *collectionfolder* path

Set the *title* of the report

- *mail* node

Set the SMTP *server* FQDN

Set the sender (*from*) address

Set the recipient (*to*) address(es), by separing email addresses with "," if needed

Set the carbon copy (*cc*) address(es), by separing email addresses with "," if needed

Set the blind carbon copy (*bcc*) address(es), by separing email addresses with "," if needed


## Run the script
ComplianceReport.ps1 -File "*XML_settings_file*"

## Remarks
Reports are saved in a Reports folder under the script root path.
