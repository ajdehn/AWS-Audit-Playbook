## Control Description
Security group rules open to the internet are appropriately restricted.

## Required Evidence
* [securityGroups.json](/evidence_library/EC2/regions/us-east-1/allSecurityGroups.json) provides a list of all EC2 security groups.
  * This evidence is gathered by calling the [describe_security_groups()](https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/ec2/client/describe_security_groups.html) command in Boto 3. 

## Testing Details
1. Internal Audit independently obtained a listing of all security groups using the boto3 describe_security_groups() command.
2. Internal Audit obtained and inspected the IpRanges for security groups open to the public (0.0.0.0 or ::/0).
3. The security group settings were reviewed for appropriateness as shown in the table below. If a security group was pre-approved by management to allow public IpRanges, then Internal Audit performed an inquiry with management and commented on the rationale in Column J.


## Other Resources
- [Example Workpaper](https://docs.google.com/spreadsheets/d/1bGfbXUTSzVCSGCWn7UtG6QN4wWeEKdrubygcCuDDjbI/edit?gid=311996735#gid=311996735)