## Test Description
EC2 security groups have required tags applied and tag values are not empty.

## Example Risk
Your AWS account has overly permissive firewall rules that are exposed to the internet. This is exploited by a malicious actor who extracts sensitive data from your AWS resources.

## Test Procedures
1. For each in-scope region, obtained a list of EC2 security groups by calling the [describe_security_groups()](https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/ec2/client/describe_security_groups.html) boto3 command.  
2. For each in-scope region, saved the list of security groups: [ec2/[region]/security_groups.json](/evidence_library/ec2/us-east-1/security_groups.json).
3. For each security group, reviewed the `Tags` to determine if the required tags exist and contain non-empty values.
  * By default, the playbook requires the following tags: "Owner", "Description", "ReviewedBy", "LastReviewedDate".
  * If you want to change the default required tags, please add them under 'ec2_sg_required_tags' in the 'test_config' section of the config.json file.

## Other Resources
- [Example Workpaper](/evidence_library/aws_audit_report.pdf)