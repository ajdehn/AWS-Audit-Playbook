## Control Description
S3 buckets are configured to block public access.

## Required Evidence
* [all_s3_buckets.json](./all_s3_buckets.json) provides a list of all S3 buckets.
  * This evidence is gathered by calling the [list_buckets()](https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/s3/client/list_buckets.html) command in Boto3.
* [public_access_settings.json](./buckets/itauditguy/public_access_settings.json) provides the public access settings for an individual S3 bucket.
  * This evidence is gathered by calling the [get_public_access_block()](https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/s3/client/get_public_access_block.html) command for each S3 bucket.

## Testing Details
1. Review the full listing of all S3 buckets in the [all_s3_buckets.json](evidence_library/S3/all_s3_buckets.json) file.
2. For each S3 bucket, review the [public_access_settings.json](evidence_library/S3/buckets/itauditguy/public_access_settings.json) file.
3. Confirm the "BlockPublicAcls", "IgnorePublicAcls", "BlockPublicPolicy", and "RestrictPublicBuckets" are all set to true. If the bucket does not meet the requirements, check if there is a valid reason (ex. S3 Bucket is intended for public consumption and thus does not require block public access to be true).

## Other Resources
- [Example Workpaper](https://docs.google.com/spreadsheets/d/1bGfbXUTSzVCSGCWn7UtG6QN4wWeEKdrubygcCuDDjbI/edit?gid=427799283)
