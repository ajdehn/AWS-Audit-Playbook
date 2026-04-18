## Control Description
RDS instances have deletion protection enabled at the cluster or instance level.

## Example Risk
A DevOps intern accidentally deletes your RDS instance. In seconds, all your application data (including your backups) are gone!

## Test Procedures
1. For each in-scope region, obtained a list of RDS instances and clusters by calling the [describe_db_instances()](https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/rds/client/describe_db_instances.html) and [describe_db_clusters()](https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/rds/client/describe_db_instances.html) boto3 commands.
2. For each in-scope region, saved the list of RDS instances: [/evidence_library/RDS/region_name/db_instances.json](/evidence_library/RDS/us-east-1/db_instances.json) and DB clusers: [/evidence_library/RDS/region_name/db_instances.json](/evidence_library/RDS/us-east-1/db_instances.json).
3. For each RDS instance, inspected the `DeletionProtection` setting to determine if it was set to `true` at the instance or cluster level.

## Other Resources
- [Example Workpaper](/evidence_library/aws_audit_report.pdf)