## Control Description
S3 buckets are configured to block public access.

## Evidence Collection Steps
1. Call [list_buckets()](https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/s3/client/list_buckets.html) in Boto3. See [all_s3_buckets.json](./all_s3_buckets.json) for example evidence.
2. For each S3 bucket, run the the [get_public_access_block()](https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/s3/client/get_public_access_block.html) in Boto3. See ???

## Support
- Please email us at info@auditops.io if you have any questions.

## Other Resources
- [Example Workpaper](https://docs.google.com/spreadsheets/d/1bGfbXUTSzVCSGCWn7UtG6QN4wWeEKdrubygcCuDDjbI/edit?gid=427799283)
