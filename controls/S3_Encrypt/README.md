## Control Description
S3 buckets are encrypted at rest.

## Evidence Collection Steps
1. Call [list_buckets()](https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/s3/client/list_buckets.html) in Boto3. See [all_s3_buckets.json](./all_s3_buckets.json) for example evidence.
2. For each S3 bucket, run the the [get_bucket_encryption()](https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/s3/client/get_bucket_encryption.html) in Boto3. See [encryption_settings.json](./buckets/itauditguy/encryption_settings.json) for example evidence.

## Sales Pitch
- If you would like a free AWS Internal Audit, please email us at info@auditops.io.

## Other Resources
- [Video: How to audit IAM passwords](https://www.loom.com/share/89e2dacf90f14afe8803fa05439caccc?sid=beecc028-26ee-410d-aa61-cd4c2b26efa3)
- [Video: How to update IAM password settings](https://www.youtube.com/watch?v=Ma5jxRO1nUQ)
- [Example Workpaper](https://docs.google.com/spreadsheets/d/1bGfbXUTSzVCSGCWn7UtG6QN4wWeEKdrubygcCuDDjbI/edit?gid=290595007)
