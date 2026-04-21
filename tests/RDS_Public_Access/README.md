## Control Description
RDS instances are configured to block public access.

## Example Risk
Foreign adversaries discover that your RDS database is accessible from the internet and begin a brute-force attack in an attempt to gain access to your valuable data.

## Test Procedures
1. For each in-scope region, obtained a list of RDS instances by calling the [describe_db_instances()](https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/rds/client/describe_db_instances.html) boto3 command.
2. For each in-scope region, saved the list of RDS instances: [/evidence_library/rds/region_name/db_instances.json](/evidence_library/rds/us-east-1/db_instances.json).
3. For each RDS instance, inspected the `PubliclyAccessible` setting to determine if it was set to `false`.

## Other Resources
- [Example Workpaper](/evidence_library/aws_audit_report.pdf)