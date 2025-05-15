## Control Description
RDS instances in the AWS account have tags applied.

## Required Evidence
* [db_instances.json](./us_east_1_db_instances.json) provides information about all RDS instances in a specific region.
    * This evidence is gathered by calling the [describe_db_instances()](https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/rds/client/describe_db_instances.html) command in Boto3 for each in-scope region.

## Testing Details
1. Review the listing of all RDS instances in each region in the [db_instances.json](./us_east_1_db_instances.json) file.
2. For each RDS instance, review the 'TagList' settings. Confirm all required tags are applied on each bucket as described in the organization's Data Classification Policy. Usually this policy requires assets to have an "Owner", "Description", and "Classification".

## Other Resources
- [Example Workpaper](https://docs.google.com/spreadsheets/d/1bGfbXUTSzVCSGCWn7UtG6QN4wWeEKdrubygcCuDDjbI/edit?gid=144111786)