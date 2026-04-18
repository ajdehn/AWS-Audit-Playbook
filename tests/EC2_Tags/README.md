## Control Description
EC2 instances have appropriate tags applied.

## Example Risk
An EC2 instance is created without proper tagging, and over time it becomes unclear who owns it or what application it supports. When an incident or cost issue arises, teams are unable to quickly identify the responsible owner, resulting in delayed response and increased operational risk.

## Test Procedures
1. For each in-scope region, obtained a list of EC2 instances by calling the [describe_instances()](https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/ec2/client/describe_instances.html) boto3 command.  
2. For each in-scope AWS region, saved the list of EC2 instances: [EC2/[region]/instances.json](/evidence_library/EC2/us-east-1/instances.json).
3. For each EC2 instance, reviewed the `Tags` to determine if the required tags exist and contain non-empty values.
  * By default, the playbook requires the following tags: "Owner", "Description", "Classification".
  * If you want to change the default required tags, please add them under 'ec2_required_tags' in the 'test_config' section of the config.json file.

## Other Resources
- [Example Workpaper](/evidence_library/aws_audit_report.pdf)