## aws-ebs-001 (EBS default encryption)

### Test Overview

- **Test Description:** EBS default encryption is enabled in each in-scope region.
- **Risk Level:** Medium
- **Risk Scenario:** EBS default encryption is not enabled in one or more AWS regions, allowing newly created volumes to be provisioned without encryption. If these volumes or their associated snapshots are accessed by unauthorized parties, sensitive data may be exposed.

### Test Procedures

1. Perform the following steps for each in-scope region:
    - Obtain the EBS default encryption settings by calling the [get_ebs_encryption_by_default()](https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/ec2/client/get_ebs_encryption_by_default.html) Boto3 method.
    - Save the EBS default encryption settings: [ec2/[region]/ebs_encryption_by_default.json](../../../evidence_library/aws/audit_evidence/ec2/us-east-1/ebs_encryption_by_default.json).
    - Inspect the EBS default encryption settings to determine whether the `EbsEncryptionByDefault` property is set to `true`.

### Remediation Guidance

1. Open the [AWS EC2 Console](https://console.aws.amazon.com/ec2/).
2. Navigate to **Account attributes** > **Data protection and security**.
3. Select **Manage** under **EBS encryption**.
4. Enable **Always encrypt new EBS volumes** for each in-scope region.
5. Save the configuration.