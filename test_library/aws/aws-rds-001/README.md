## aws-rds-001 (RDS encryption)

### Test Overview

- **Test Description:** RDS instances in the AWS account are encrypted.
- **Risk Level:** Medium
- **Risk Scenario:** An RDS instance storing sensitive data is configured without encryption at rest. The database is later exposed due to a misconfiguration, and is immediately readable by malicious actors.

### Test Procedures

1. Perform the following for each in-scope region:
    - Obtain a list of RDS instances by calling the [describe_db_instances()](https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/rds/client/describe_db_instances.html) Boto3 method.
    - Save the list of RDS instances: [rds/[region_name]/db_instances.json](../../../evidence_library/aws/audit_evidence/rds/us-east-1/db_instances.json).
    - For each RDS instance, inspect the `StorageEncrypted` property to determine whether it is set to `true`.

**### Remediation Guidance**

**#### Prerequisites:**
Before making changes, coordinate with the database owner or the individual responsible for managing the RDS instance. Plan for any required downtime and application connection updates.

**#### Remediation Procedure:**
1. Open the [Amazon RDS Console](https://console.aws.amazon.com/rds/).
2. Select the appropriate AWS region.
3. Navigate to **Databases** and select the unencrypted RDS instance.
4. Create a snapshot of the RDS instance.
5. Navigate to **Snapshots**, select the newly created snapshot, and select **Copy snapshot**.
6. Enable encryption and select the appropriate AWS KMS key when copying the snapshot.
7. Restore the encrypted snapshot as a new RDS DB instance.
8. Coordinate with the database owner to update application connections and migrate workloads to the new encrypted instance.
9. Verify that the new DB instance has encryption enabled.
10. Once the migration is complete and the original instance is no longer needed, securely decommission it according to your organization's retention and change management requirements.