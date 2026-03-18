## Control Description
S3 buckets are configured to encrypt data in-transit.

## Required Evidence
* [all_s3_buckets.json](/evidence_library/S3/all_s3_buckets.json) provides a list of all S3 buckets.
  * This evidence is gathered by calling the [list_buckets()](https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/s3/client/list_buckets.html) command in Boto3.
* [bucket_policy.json](/evidence_library/S3/buckets/itauditguy/bucket_policy.json) provides the bucket policy which controls access to the S3 bucket.
  * This evidence is gathered by calling the [get_bucket_policy()](https://docs.aws.amazon.com/boto3/latest/reference/services/s3/client/get_bucket_policy.html) command for each S3 bucket.

## Testing Details
1. Review the full listing of all S3 buckets in the [all_s3_buckets.json](/evidence_library/S3/all_s3_buckets.json) file.
2. For each S3 bucket, review the [bucket_policy.json](/evidence_library/S3/buckets/itauditguy/bucket_policy.json) file.
3. Confirm there is a rule that blocks traffic if "SecureTransport" is not enforced.

## Other Resources
- [Example Workpaper](https://docs.google.com/spreadsheets/d/1bGfbXUTSzVCSGCWn7UtG6QN4wWeEKdrubygcCuDDjbI/edit?gid=427799283)
