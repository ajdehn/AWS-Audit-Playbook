## aws-ec2-002 (EC2 security group tagging)

### Test Overview

- **Test Description:** EC2 security groups have required tags applied and tag values are not empty.
- **Risk Level:** Informational
- **Risk Scenario:** EC2 security groups lack required ownership and documentation tags, making it difficult to identify responsible parties, understand the purpose of firewall rules, and maintain effective security oversight.

### Test Procedures

1. Perform the following for each in-scope region:
    - Obtain a list of EC2 security groups by calling the [describe_security_groups()](https://docs.aws.amazon.com/boto3/latest/reference/services/ec2/client/describe_security_groups.html) Boto3 method.
    - Save the list of EC2 security groups: [ec2/[region]/security_groups.json](../../../evidence_library/aws/audit_evidence/ec2/us-east-1/security_groups.json).
    - For each EC2 security group, inspect the `Tags` property to determine whether the required tags exist and contain non-empty values.

**NOTE:** By default, the AuditOps Python library requires the tags `Owner`, `Description`, `ReviewedBy`, and `LastReviewedDate`. To change the default required tags, update the `AWSConfig` values.

### Remediation Guidance**

1. Open the [AWS EC2 Console](https://console.aws.amazon.com/ec2/).
2. Select the appropriate AWS region.
3. Navigate to **Network & Security > Security Groups**.
4. Select the security group you want to update.
5. Open the **Tags** tab and select **Manage tags**.
6. Add the required tags with appropriate, non-empty values.
7. Save the changes.
8. Repeat for each security group.