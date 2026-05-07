## Test Description
RDS instances have automatic minor version upgrades enabled.

## Example Risk
An RDS instance is configured without automatic minor version upgrades, causing it to miss important security patches. Because it was left unpatched, the database is compromised and sensitive data is stolen by malicious actors.

## Test Procedures
1. For each in-scope region, obtained a list of RDS instances by calling the [describe_db_instances()](https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/rds/client/describe_db_instances.html) boto3 command.
2. For each in-scope region, saved the list of RDS instances: [/evidence_library/rds/region_name/db_instances.json](/evidence_library/rds/us-east-1/db_instances.json).
3. For each RDS instance, inspected the `AutoMinorVersionUpgrade` setting to determine if it was set to `true`.

## Other Resources
- [Example Workpaper](/evidence_library/aws_audit_report.pdf)