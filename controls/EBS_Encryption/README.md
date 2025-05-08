## Control Description
EBS volumes are encrypted.

## Required Evidence
* [ebsVolumes.json](./regions/us-east-1/ebsVolumes.json) provides a list of all EBS volumes.
  * This evidence is gathered by calling the [describe_volumes()](https://boto3.amazonaws.com/v1/documentation/api/1.35.9/reference/services/ec2/client/describe_volumes.html) command in Boto 3. 

## Testing Details
1. For each in-scope region, review the [ebsVolumes.json](./regions/us-east-1/ebsVolumes.json) file and confirm the "Encryption" is enabled for each volume.


## Other Resources
- [Example Workpaper](https://docs.google.com/spreadsheets/d/1bGfbXUTSzVCSGCWn7UtG6QN4wWeEKdrubygcCuDDjbI/edit?gid=1449904500)