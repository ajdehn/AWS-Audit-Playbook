## aws-rds-006 (RDS instance tagging)

### Test Overview

- **Test Description:** RDS instances in the AWS account have tags applied.
- **Risk Level:** Informational
- **Risk Scenario:** A production RDS instance is created without proper tagging. Due to the lack of tagging, a permissions policy grants developers administrative access. Because of this mistake, you can no longer rely on Segregation of Duties controls.

### Test Procedures

1. Perform the following for each in-scope region:
   - Obtain a list of RDS instances by calling the [describe_db_instances()](https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/rds/client/describe_db_instances.html) Boto3 method.
   - Save the list of RDS instances: [rds/[region_name]/db_instances.json](../../../evidence_library/aws/audit_evidence/rds/us-east-1/db_instances.json).
   - For each RDS instance, inspect the `TagList` to determine whether the required tags exist and contain non-empty values.

**NOTE:** By default, the AuditOps Python library requires the tags `Owner`, `Description`, and `Classification`. To change the default required tags, update the `AWSConfig` values.

### Remediation Guidance

1. Open the [Amazon RDS Console](https://console.aws.amazon.com/rds/).
2. Select the appropriate AWS region.
3. Navigate to **Databases** and select the RDS instance missing the required tags.
4. In the **Tags** section, select **Manage tags** (or **Edit tags**, depending on the console view).
5. Add the required tags and their corresponding non-empty values:
   - `Owner`: The individual or team responsible for the RDS instance.
   - `Description`: A brief description of the RDS instance and its purpose.
   - `Classification`: The data classification level of the information stored in the RDS instance.
6. Save the changes.
7. Verify that the required tags are present and contain non-empty values.
8. Repeat for each RDS instance missing the required tags.