## aws-rds-005 (RDS deletion protection)

### Test Overview

- **Test Description:** RDS instances have deletion protection enabled at the cluster or instance level.
- **Risk Level:** Low
- **Risk Scenario:** A DevOps intern accidentally deletes your RDS instance. In seconds, all your application data (including your backups) are gone!

### Test Procedures

1. Perform the following for each in-scope region:
    - Obtain a list of RDS instances by calling the [describe_db_instances()](https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/rds/client/describe_db_instances.html) Boto3 method.
    - Save the list of RDS instances: [rds/[region_name]/db_instances.json](../../../evidence_library/aws/audit_evidence/rds/us-east-1/db_instances.json).
    - Obtain a list of RDS DB clusters by calling the [describe_db_clusters()](https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/rds/client/describe_db_clusters.html) Boto3 method.
    - Save the list of RDS DB Clusters: [rds/[region_name]/db_clusters.json](../../../evidence_library/aws/audit_evidence/rds/us-east-1/db_clusters.json).
    - For each RDS instance, inspect the `DeletionProtection` property to determine whether it is set to `true` at the instance or cluster level.

### Remediation Guidance

1. Open the [Amazon RDS Console](https://console.aws.amazon.com/rds/).
2. Select the appropriate AWS region.
3. Navigate to **Databases** and select the RDS instance or DB cluster with deletion protection disabled.
4. Select **Modify**.
5. Locate the **Deletion protection** section.
6. Enable **Deletion protection**.
7. Review the remaining configuration changes and select **Continue**.
8. Choose whether to apply the changes immediately or during the next maintenance window, as appropriate.
9. Verify that deletion protection is enabled.
10. Repeat for each RDS instance or DB cluster that does not have deletion protection enabled.