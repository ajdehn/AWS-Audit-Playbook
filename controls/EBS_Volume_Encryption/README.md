## Control Description
EBS volumes are encrypted.

## Required Evidence
* [ebsVolumes.json](/evidence_library/EC2/us-east-1/volumes.json) provides a list of all EBS volumes within each in-scope region.
  * This evidence is gathered by calling the [describe_volumes()](https://boto3.amazonaws.com/v1/documentation/api/1.35.9/reference/services/ec2/client/describe_volumes.html) command in Boto 3. 

## Testing Details
1. For each in-scope region, review the [ebsVolumes.json](/evidence_library/EC2/us-east-1/volumes.json) file and confirm the "Encryption" is enabled for each volume.


## Other Resources
- [Example Workpaper](/evidence_library/aws_audit_report.pdf)
