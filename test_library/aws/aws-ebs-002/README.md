## aws-ebs-002 (EBS volume encryption)

### Test Overview

- Test Description: EBS volumes are encrypted at rest.
- Risk Level: Medium
- Risk Scenario: An EBS volume is created without encryption and contains sensitive data. The volume is later accessed through a snapshot, backup process, or underlying infrastructure issue, resulting in loss of unencrypted data.

### Test Procedures

1. Perform the following for each in-scope region:
    - Obtain a list of EBS volumes by calling the [describe_volumes()](https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/ec2/client/describe_volumes.html) Boto3 method.
    - Save the list of EBS volumes: [ec2/[region]/volumes.json](../../../evidence_library/aws/audit_evidence/ec2/us-east-1/volumes.json).
    - For each EBS volume, inspect the `Encrypted` property to determine whether it is set to `true`.

### Remediation Guidance

#### Warning:
Encrypting existing EBS volumes requires creating replacement volumes from encrypted snapshots. This process may require instance downtime and changes to application configurations or storage mappings. Before proceeding, verify that you have current backups, understand the dependencies of each volume, and have a tested migration and rollback plan. Do not delete the original volumes until the replacement volumes have been verified and confirmed to be functioning correctly.

#### Remediation Procedure:
1. Open the [AWS EC2 Console](https://console.aws.amazon.com/ec2/).
2. Navigate to **Elastic Block Store** > **Volumes**.
3. Identify any unencrypted EBS volumes.
4. Create an encrypted snapshot of each unencrypted volume and use the snapshot to create a replacement encrypted volume.
5. Update any associated EC2 instances to use the replacement volumes, following an appropriate maintenance procedure.
6. Navigate to **Account attributes** > **Data protection and security** and enable **EBS encryption by default** for each in-scope region to ensure newly created volumes are encrypted automatically.