## Control Description
RDS instances in the AWS account are encrypted.

## Example Risk
An RDS instance storing sensitive data is configured without encryption at rest. The database is later exposed due to a misconfiguration, and is immediately readable by malicious actors.

## Test Procedures
1. For each in-scope region, obtained a list of RDS instances by calling the [describe_db_instances()](https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/rds/client/describe_db_instances.html) boto3 command.
2. For each in-scope region, saved the list of RDS instances: [/evidence_library/RDS/region_name/db_instances.json](/evidence_library/RDS/us-east-1/db_instances.json).
3. For each RDS instance, inspected the `StorageEncrypted` setting to determine if it was set to `true`.

## Other Resources
- [Example Workpaper](/evidence_library/aws_audit_report.pdf)