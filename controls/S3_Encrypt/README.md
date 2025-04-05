## Control Description
S3 buckets are encrypted at rest.

## Evidence Collection Steps
1. Call [list_buckets()](https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/s3/client/list_buckets.html) in Boto3. See [all_s3_buckets.json](./all_s3_buckets.json) for example evidence.
2. For each S3 bucket, run the the [get_bucket_encryption()](https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/s3/client/get_bucket_encryption.html) in Boto3. See [encryption_settings.json](./buckets/itauditguy/encryption_settings.json) for example evidence.

## Support
- Please email us at info@auditops.io if you have any questions.

## Other Resources
- [Example Workpaper](https://docs.google.com/spreadsheets/d/1bGfbXUTSzVCSGCWn7UtG6QN4wWeEKdrubygcCuDDjbI/edit?gid=1801900379)
