## Control Description
EC2 security groups have the proper tags applied, and have been reviewed in the last year.

## Example Risk
Your AWS account has overly permissive firewall rules that are exposed to the internet. This is exploited by a malicious actor who extracts sensitive data from your AWS resources.

## Required Evidence
* [securityGroups.json](/evidence_library/EC2/regions/us-east-1/allSecurityGroups.json) provides a list of all EC2 security groups along with tags attached to each security group.
  * This evidence is gathered by calling the [describe_security_groups()](https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/ec2/client/describe_security_groups.html) command in Boto 3. 

## Testing Details
1. Internal Audit independently obtained a listing of all security groups using the boto3 describe_security_groups() command.
2. IA reviewed the 'Tags' settings for each security group to determine if it has the required tags as shown below.

## Other Resources
- [Example Workpaper](https://docs.google.com/spreadsheets/d/1bGfbXUTSzVCSGCWn7UtG6QN4wWeEKdrubygcCuDDjbI/edit?gid=323546867#gid=323546867)