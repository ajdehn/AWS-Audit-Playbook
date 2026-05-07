## Test Description
RDS backups are retained for at least 14 days.
- **NOTE:** Number of days should be updated to reflect the client's retention period.

## Example Risk
A database administrator (DBA) accidentally deletes 10,000 records from your production database. It's been two days, and your most important enterprise customer has already cancelled while your engineering team is scrambling to get your data back.

## Test Procedures
1. For each in-scope region, obtained a list of RDS instances by calling the [describe_db_instances()](https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/rds/client/describe_db_instances.html) boto3 command.
2. For each in-scope region, saved the list of RDS instances: [/evidence_library/rds/region_name/db_instances.json](/evidence_library/rds/us-east-1/db_instances.json).
3. For each RDS instance, inspected the `BackupRetentionPeriod` setting to determine if it was set to is **greater than or equal to** the number of days required by the organization's backup retention policy.
    * If you want to change the default retention period, please update the 'rds_backup_retention_days' in the 'test_config' section of the config.json file.
    * If the database does not meet the requirement, check if there is a valid reason (ex. RDS instance does not host production data).    

## Other Resources
- [Example Workpaper](/evidence_library/aws_audit_report.pdf)
