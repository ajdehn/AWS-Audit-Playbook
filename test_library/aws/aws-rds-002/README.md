## aws-rds-002 (RDS public accessibility)

### Test Overview

- **Test Description:** RDS instances are configured to block public access.
- **Risk Level:** High
- **Risk Scenario:** An attacker discovers that an RDS database is publicly accessible from the internet and attempts to gain unauthorized access through brute-force attacks or exploitation of database vulnerabilities, potentially resulting in unauthorized access to sensitive data.

### Test Procedures

1. Perform the following for each in-scope region:
    - Obtain a list of RDS instances by calling the [describe_db_instances()](https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/rds/client/describe_db_instances.html) Boto3 method.
    - Save the list of RDS instances: [rds/[region_name]/db_instances.json](../../../evidence_library/aws/audit_evidence/rds/us-east-1/db_instances.json).
    - For each RDS instance, inspect the `PubliclyAccessible` property to determine whether it is set to `false`.

### Remediation Guidance

#### Prerequisites:

Before making changes, coordinate with the database owner or the individual responsible for managing the RDS instance to identify application connectivity requirements and potential dependencies.

#### Remediation Procedure:

1. Open the [Amazon RDS Console](https://console.aws.amazon.com/rds/).
2. Select the appropriate AWS region.
3. Navigate to **Databases** and select the publicly accessible RDS instance.
4. Select **Modify**.
5. Locate the **Connectivity** section and disable **Public access**.
6. Review the remaining configuration changes and select **Continue**.
7. Choose whether to apply the changes immediately or during the next maintenance window, as appropriate.
8. Verify that the RDS instance is no longer publicly accessible.
9. Confirm that applications and authorized users can still connect to the database through the appropriate private network configuration.