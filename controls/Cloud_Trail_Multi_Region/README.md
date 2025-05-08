## Control Description
At least one multi-region CloudTrail is enabled with log-file validation.

## Required Evidence
* [all_trails.json](./all_trails.json) provides a list of all trails in the AWS account.
  * This evidence is gathered by calling the [describe_trails()](https://boto3.amazonaws.com/v1/documentation/api/1.26.93/reference/services/cloudtrail/client/describe_trails.html) command in Boto 3. 

## Testing Details
1. Internal Audit obtained the multi-region settings of each trail by using the boto3 the describe_trails() command.
2. The multi-region & log file validation settings were reviewed for appropriateness as shown in Column C below.

## Other Resources
- [Example Workpaper](https://docs.google.com/spreadsheets/d/1bGfbXUTSzVCSGCWn7UtG6QN4wWeEKdrubygcCuDDjbI/edit?gid=1065714791)
