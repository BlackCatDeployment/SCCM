# ManageCollections Script

## Description

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
- One or more administrative users

## How to use it

Enter this command in a PowerShell prompt from a ConfigMgr Primary Server:

.\ManageCollections.ps1 -File <*CSV_File*>

CSV File content:

CSV file columns **must** be delimited by "**;**"

Implement | CollectionName | CollectionType | CollectionLimit | CollectionFolder | CollectionComment | RefreshSchedule | User | RuleType | RuleName | RuleQuery
--------- | -------------- | -------------- | --------------- | ---------------- | ----------------- | --------------- | ---- | -------- | -------- | ---------

- **Implement**
  - Set **A** for creating the collection
    - If the collection already exists, a warning is displayed
  - Set **D** for removing the collection. Before removal, it checks:
    - Collection references
    - Collection Membership Rules dependences
    - Collection Administrative User(s) permissions
  - Set **R** for replacing the collection
    - Replace = Removal (D) + Creation (A)
  - Set **N** for doing nothing

- **CollectionName**
  - Name of the collection to create

- **CollectionType**
  - Set **User** for creating a User collection
  - Set **Device** for creating a Device collection

- **CollectionLimit**
  - Name of the limiting collection (default: All Systems)

- **CollectionFolder**
  - Name of the folder where to create the collection
  - It creates the folder and subfolders in the User or Device collections section
  - If no folder was set, the collection will be created in the root User or Device collection section

- **CollectionComment**
  - Description of the collection

- **RefreshSchedule**
  - Set the schedule for the update collection Membership Rule
  - 1st character:
    - Set **D** for day
    - Set **M** for minute
    - Set **H** for hour
  - 2nd and + characters:
    - Set the delay
  - Example: **D7** for 7 days
  - If a wrong value was set, 7 days is defined by default
  - If no value was set, incremental updates is defined by default

- **User**
  - Grant Administrative User(s) to the collection
  - Separate users by a **,**
  - No value is allowed
  - Example: DOMAIN\GS-Users

- **RuleType**
  - Add Membership Rule type(s)
    - Set **Query** for creating a Query Membership Rule (WQL query is set in "RuleQuery" column)
    - Set **Direct** for creating a Direct Membership Rule (Computer is set in "RuleQuery" column)
    - Set **Include** for creating an Include collection Membership Rule (Include Collection is set in "RuleQuery" column)
    - Set **Exclude** for creating an Exclude collection Membership Rule (Exclude Collection is set in "RuleQuery" column)
  - It's possible to create several Membership Rules for the collection by separating them by a **||** (double pipes)
  - Example: Query||Direct||Include

- **RuleName**
  - Name of Membership Rule(s)
  - If no name was set, it uses the collection name
  - If several "RuleType" was defined, separate Rule Names by a **||** (as "RuleType" column)
  - Example: Rule1||Rule2||Rule3

- **RuleQuery**
  - Query of rule(s)
    - If **RuleType = Query** then set a WQL query
    - If **RuleType = Direct** then set computer name(s), separated by a **,**
    - If **RuleType = Include** then set collection(s) to include, separated by a **,**
    - If **RuleType = Exclude** then set collection(s) to exclude, separated by a **,**
  - If several RuleType were defined, separate "RuleQuery" by a **||** (as RuleType column)
  - Example: select * from SMS_R_System where SMS_R_System.ClientType = 3||SRVTEST01,SRVTEST02||Servers - All Collection

## Logging

The script logs everything in **ManageCollections.log** in the script path.
It displays at the end of its execution the number of Success, Warnings and Errors that occured.

## Notes

This script has been tested on these platforms:

- ConfigMgr 2012 R2 SP1 (v5.0.8239.1000) under Windows Server 2008 R2 SP1 (PowerShell 3.0)
  - Operational collections like Windows 10 Support State or Windows 10 Branch detection are not working.
  - Use the CSV file "CreateOperationalCollections.csv-For2012"
- ConfigMgr CB 1702 and above under Windows Server 2012 R2 and above (PowerShell 5.1)
  - Use the CSV file "CreateOperationalCollections.csv-ForCB"

It uses the ConfigurationManager PoSh module.

I added Operational Collections created by Benoit Lecours in the CSV File **[CreateOperationalCollections-ForCB.csv](https://github.com/BlackCatDeployment/SCCM/blob/master/ManageCollections/CreateOperationalCollections-ForCB.csv)**

Thanks to [Marius / Hican](https://gallery.technet.microsoft.com/scriptcenter/SCCM-2012-Management-b36e7aeb) and [Benoit Lecours](https://gallery.technet.microsoft.com/Set-of-Operational-SCCM-19fa8178) for their scripts basis.
