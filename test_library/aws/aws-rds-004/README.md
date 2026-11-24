## aws-rds-004 (RDS automatic minor upgrades)

### Test Overview

- **Test Description:** RDS instances have automatic minor version upgrades enabled.
- **Risk Level:** Low
- **Risk Scenario:** An RDS instance is configured without automatic minor version upgrades, causing it to miss important security patches. Because it was left unpatched, the database is compromised and sensitive data is stolen by malicious actors.

### Test Procedures

1. Perform the following for each in-scope region:
    - Obtain a list of RDS instances by calling the [describe_db_instances()](https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/rds/client/describe_db_instances.html) Boto3 method.
    - Save the list of RDS instances: [rds/[region_name]/db_instances.json](../../../evidence_library/aws/audit_evidence/rds/us-east-1/db_instances.json).
    - For each RDS instance, inspect the `AutoMinorVersionUpgrade` setting to determine if it was set to `true`.

### Remediation Guidance

1. Open the [Amazon RDS Console](https://console.aws.amazon.com/rds/).
2. Select the appropriate AWS region.
3. Navigate to **Databases** and select the RDS instance with automatic minor version upgrades disabled.
4. Select **Modify**.
5. Locate the **Maintenance** section.
6. Enable **Auto minor version upgrade**.
7. Review the remaining configuration changes and select **Continue**.
8. Choose whether to apply the changes immediately or during the next maintenance window, as appropriate.
9. Verify that automatic minor version upgrades are enabled.
10. Repeat for each RDS instance that does not have automatic minor version upgrades enabled.