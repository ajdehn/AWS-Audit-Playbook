## Control Description
RDS instances in the AWS account are encrypted.

## Example Risk
A rogue AWS employee steals hardware from the data center hosting your company's sensitive information. The data from the hard drive is sold on the dark web and your organization is now facing reputational damage, fines, reputational damage, and loss of revenue.

## Evidence Required
* [db_instances.json](/evidence_library/RDS/regions/us_east_1_db_instances.json) provides information about all RDS instances in a specific region.
    * This evidence is gathered by calling the [describe_db_instances()](https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/rds/client/describe_db_instances.html) command in Boto3 for each in-scope region.

## Testing Details
1. Confirm the "StorageEncrypted" field is **true** for each database within each region.

## Other Resources
- [Example Workpaper](https://docs.google.com/spreadsheets/d/1bGfbXUTSzVCSGCWn7UtG6QN4wWeEKdrubygcCuDDjbI/edit?gid=164074275)
