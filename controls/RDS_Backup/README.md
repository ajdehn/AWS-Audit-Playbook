## Control Description
RDS backups are retained for at least 14 days.
- **NOTE:** Number of days should be updated to reflect the client's retention period.

## Evidence Required
* [db_instances.json](./us_east_1_db_instances.json) provides information about all RDS instances in a specific region.
    * This evidence is gathered by calling the [describe_db_instances()](https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/rds/client/describe_db_instances.html) command in Boto3 for each in-scope region.

## Testing Details
1. Find the "BackupRetentionPeriod" field for each database. This value represents the number of days backups are retained before being automatically deleted.
2. Confirm the "BackupRetentionPeriod" is **greater than or equal to** the number of days required by the organization's backup retention policy. If the database does not meet the requirement, check if there is a valid reason (ex. RDS instance does not host production data).

## Support
- Please email us at info@auditops.io if you have any questions.

## Other Resources
- [Example Workpaper](https://docs.google.com/spreadsheets/d/1bGfbXUTSzVCSGCWn7UtG6QN4wWeEKdrubygcCuDDjbI/edit?gid=1525441158)
