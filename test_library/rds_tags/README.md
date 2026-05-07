## Test Description
RDS instances in the AWS account have tags applied.

## Example Risk
A production RDS instance is created without proper tagging. Due to the lack of tagging, a permissions policy grants developers administrative access. Because of this mistake, you can no longer rely on Segragration of Duties controls.

## Test Procedures
1. For each in-scope region, obtained a list of RDS instances by calling the [describe_db_instances()](https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/rds/client/describe_db_instances.html) boto3 command.
2. For each in-scope region, saved the list of RDS instances: [/evidence_library/rds/region_name/db_instances.json](/evidence_library/rds/us-east-1/db_instances.json).
3. For each RDS instance, reviewed the `TagList` to determine if the required tags exist and contain non-empty values.
  * By default, the playbook requires the following tags: "Owner", "Description", "Classification".
  * If you want to change the default required tags, please add them under 'rds_required_tags' in the 'test_config' section of the config.json file.

## Other Resources
- [Example Workpaper](/evidence_library/aws_audit_report.pdf)