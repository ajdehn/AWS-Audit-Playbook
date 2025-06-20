## Control Description
EC2 instances have appropriate tags applied.

## Required Evidence
* [allInstances.json](/evidence_library/EC2/us-east-1/allInstances.json) provides information for all EC2 instances in a specific region.
  * This evidence is gathered by calling the [describe_instances()](https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/ec2/client/describe_instances.html) command in Boto 3. 

## Testing Details
1. Review the listing of all EC2 instances in each region in the [allInstances.json](/evidence_library/EC2/us-east-1/allInstances.json) file.
2. For each EC2 instance, review the 'Tags' settings. Confirm all required tags are applied on each bucket as described in the organization's Data Classification Policy. Usually this policy requires assets to have an "Owner", "Description", and "Classification".

## Other Resources
- [Example Workpaper](https://docs.google.com/spreadsheets/d/1bGfbXUTSzVCSGCWn7UtG6QN4wWeEKdrubygcCuDDjbI/edit?gid=1896997060)