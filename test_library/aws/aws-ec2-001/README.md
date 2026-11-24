## aws-ec2-001 (EC2 instance tagging)

### Test Overview

- **Test Description:** EC2 instances must have required tags applied, and tag values must not be empty.
- **Risk Level:** Informational
- **Risk Scenario:** EC2 instances without appropriate tags are more difficult to identify, manage, and monitor. This can increase administrative overhead and delay incident response.

### Test Procedures
1. Perform the following for each in-scope region:
    - Obtain a list of EC2 instances by calling the [describe_instances()](https://docs.aws.amazon.com/boto3/latest/reference/services/ec2/client/describe_instances.html) Boto3 method.
   - Save the list of EC2 instances: [ec2/[region]/instances.json](../../../evidence_library/aws/audit_evidence/ec2/us-east-1/instances.json)
   - For each EC2 instance, inspect the `Tags` property to determine whether the required tags exist and contain non-empty values.

**NOTE:** By default, the AuditOps Python library requires the tags `Owner`, `Description`, and `Classification`. To change the default required tags, update the `AWSConfig` values.

### Remediation Guidance

1. Open the [AWS EC2 Console](https://console.aws.amazon.com/ec2/).
2. Select the appropriate AWS region.
3. Navigate to **Instances** and select the EC2 instance.
4. Select **Actions > Instance settings > Manage tags**.
5. Add the required tags with appropriate, non-empty values.
6. Save the changes.
7. Repeat for each instance.