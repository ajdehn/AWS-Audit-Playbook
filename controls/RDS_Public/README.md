## Control Description
RDS instances are configured to block public access.

## Example Risk
Foreign adversaries discover that your RDS database is accessible to the internet and begin a brute-force attack in an attempt to guess your database credentials.

## Evidence Required
* [db_instances.json](/evidence_library/RDS/regions/us_east_1_db_instances.json) provides information about all RDS instances in a specific region.
    * This evidence is gathered by calling the [describe_db_instances()](https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/rds/client/describe_db_instances.html) command in Boto3 for each in-scope region.

## Testing Details
1. Confirm the "PubliclyAccessible" setting for each in-scope database is set to false.

## Other Resources
- [Example Workpaper](https://docs.google.com/spreadsheets/d/1bGfbXUTSzVCSGCWn7UtG6QN4wWeEKdrubygcCuDDjbI/edit?gid=1178605592)
