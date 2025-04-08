## Control Description
RDS backups are retained for at least 14 days.

## Evidence Collection Steps
1. For each in-scope region, call the [describe_db_instances()](https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/rds/client/describe_db_instances.html) command. See [describe_db_instances.json](./describe_db_instances.json) for example evidence.

## Testing Details
1. Find the "BackupRetentionPeriod" field for each database. This value represents the number of days backups are retained for in that RDS instance.
2. Confirm the retention period is **at least** the number of days required by the organization's backup retention policy. If the database does not meet the requirement, check if there is a valid reason (ex. RDS instance does not host production data).

## Support
- Please email us at info@auditops.io if you have any questions.

## Other Resources
- [Example Workpaper](https://docs.google.com/spreadsheets/d/1bGfbXUTSzVCSGCWn7UtG6QN4wWeEKdrubygcCuDDjbI/edit?gid=1525441158)
