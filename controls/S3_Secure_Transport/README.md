## Control Description
S3 buckets are configured to encrypt data in-transit.

## Test Procedures
1. Obtained a list of S3 buckets by calling the [list_buckets()](https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/s3/client/list_buckets.html) boto3 command.,
2. Saved the list of S3 buckets in the audit evidence folder. See [S3/buckets.json](/evidence_library/S3/buckets.json).
3. Obtained the bucket policy for each bucket by calling the [get_bucket_policy()](https://docs.aws.amazon.com/boto3/latest/reference/services/s3/client/get_bucket_policy.html) boto3 command.,
4. Saved the bucket policy for each S3 bucket. See [S3/buckets/[bucket_name]/bucket_policy.json](/evidence_library/S3/buckets/itauditguy/bucket_policy.json).
5. Inspected each bucket policy to confirm a statement exists that denies requests when aws:SecureTransport is false.

## Other Resources
- [Example Workpaper](/evidence_library/aws_audit_report.pdf)
