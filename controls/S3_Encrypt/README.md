## Control Description
S3 buckets are encrypted at rest.

## Required Evidence
* [all_s3_buckets.json](./all_s3_buckets.json) provides a list of all S3 buckets.
  * This evidence is gathered by calling the [list_buckets()](https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/s3/client/list_buckets.html) in Boto3.
* [encryption_settings.json](./buckets/itauditguy/encryption_settings.json) provides the encryption settings for an individual S3 bucket.
  * This evidence is gathered by calling the [get_bucket_encryption()](https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/s3/client/get_bucket_encryption.html) for each S3 bucket.

## Testing Details
1. Review the full listing of all S3 buckets in the [all_s3_buckets.json](./all_s3_buckets.json) file.
2. For each S3 bucket, review the [encryption_settings.json](./buckets/itauditguy/encryption_settings.json) file.
3. Confirm the "SSEAlgorithm" is "AES256" or "AWS:KMS" to confirm that encryption is enabled. If the bucket does not meet the requirement, check if there is a valid reason (ex. S3 Bucket contains only public-facing data and thus does not require encryption).

## Support
- Please email us at info@auditops.io if you have any questions.

## Other Resources
- [Example Workpaper](https://docs.google.com/spreadsheets/d/1bGfbXUTSzVCSGCWn7UtG6QN4wWeEKdrubygcCuDDjbI/edit?gid=1801900379)
