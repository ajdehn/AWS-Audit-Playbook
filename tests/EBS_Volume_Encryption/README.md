## Control Description
EBS volumes are encrypted.

## Example Risk
An EBS volume is created without encryption and contains sensitive data. The volume is later accessed through a snapshot, backup process, or underlying infrastructure issue, resulting in loss of unencrypted data.

## Test Procedures
1. For each in-scope region, obtained a list of EBS volumes by calling the [describe_volumes()](https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/ec2/client/describe_volumes.html) boto3 command.
2. For each in-scope region, saved the list of EBS volumes: [ec2/[region]/volumes.json](/evidence_library/ec2/us-east-1/volumes.json).
3. For each EBS volume, inspected the `Encrypted` attribute to determine it is set to `true`.

## Other Resources
- [Example Workpaper](/evidence_library/aws_audit_report.pdf)