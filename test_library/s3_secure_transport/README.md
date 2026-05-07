## Test Description
S3 buckets are configured to deny unencrypted data in-transit.

## Example Risk
An engineer accidentally uses HTTP when uploading sensitive documents to an S3 bucket. They are working from a coffee shop, and the traffic is intercepted giving the attacker a list of your customer's bank account numbers.

## Test Procedures
1. Obtained a list of S3 buckets by calling the [list_buckets()](https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/s3/client/list_buckets.html) boto3 command.
2. Saved the list of buckets: [s3/buckets.json](/evidence_library/s3/buckets.json).  
3. For each bucket, obtained the bucket policy by calling the [get_bucket_policy()](https://docs.aws.amazon.com/boto3/latest/reference/services/s3/client/get_bucket_policy.html) boto3 command.
4. For each bucket, saved the bucket policy: [s3/buckets/[bucket_name]/bucket_policy.json](/evidence_library/s3/buckets/itauditguy/bucket_policy.json).
5. For each bucket, inspected the bucket policy to determine if a statement exists that denies requests when `aws:SecureTransport` is false.

## Other Resources
- [Example Workpaper](/evidence_library/aws_audit_report.pdf)