## aws-rds-003 (RDS backups)

### Test Overview

- **Test Description:** RDS backups are retained for at least 14 days. **NOTE:** Number of days should be updated to reflect the client's retention period.
- **Risk Level:** Low
- **Risk Scenario:** A database administrator (DBA) accidentally deletes 10,000 records from your production database. It's been two days, and your most important enterprise customer has already cancelled while your engineering team is scrambling to get your data back.

### Test Procedures

1. Perform the following for each in-scope region:
    - Obtain a list of RDS instances by calling the [describe_db_instances()](https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/rds/client/describe_db_instances.html) Boto3 method.
    - Save the list of RDS instances: [rds/[region_name]/db_instances.json](../../../evidence_library/aws/audit_evidence/rds/us-east-1/db_instances.json).
    - Save the list of RDS instances: [rds/[region_name]/db_instances.json](../../../evidence_library/aws/audit_evidence/rds/us-east-1/db_instances.json).    
    - For each RDS instance, inspect the `BackupRetentionPeriod` property to determine if it was set to is **greater than or equal to** the number of days required by the organization's backup retention policy.

**NOTE:** By default, the AuditOps Python library requires 14 days of backups to be retained. To customize the backup retetntion settings, update the corresponding values in `AWSConfig`.

```
aws_config.rds_backup_retention_days = 30
```

### Remediation Guidance

1. Open the [Amazon RDS Console](https://console.aws.amazon.com/rds/).
2. Select the appropriate AWS region.
3. Navigate to **Databases** and select the RDS instance with insufficient backup retention.
4. Select **Modify**.
5. Locate the **Backup** section.
6. Update the **Backup retention period** to meet or exceed the organization's backup retention requirements.
7. Review the remaining configuration changes and select **Continue**.
8. Choose whether to apply the changes immediately or during the next maintenance window, as appropriate.
9. Verify that the updated backup retention period meets the organization's requirements.
10. Repeat for each RDS instance that does not meet the required backup retention period.