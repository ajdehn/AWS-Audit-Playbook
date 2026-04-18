## Control Description
S3 buckets are encrypted at rest.

## Example Risk
One of your S3 buckets was created before AWS turned on encryption by default. Everyone assumes all buckets are encrypted until you undergo a regulatory audit and face a $50,000 fine for failing to encrypt sensitive data.

## Test Procedures
1. Obtained a list of S3 buckets by calling the [list_buckets()](https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/s3/client/list_buckets.html) boto3 command.  
2. Saved the list of buckets: [S3/buckets.json](/evidence_library/S3/buckets.json).  
3. For each S3 bucket, obtained the encryption settings by calling the [get_bucket_encryption()](https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/s3/client/get_bucket_encryption.html) boto3 command.  
4. For each S3 bucket, saved the encryption settings: [S3/buckets/[bucket_name]/encryption_settings.json](/evidence_library/S3/buckets/itauditguy/encryption_settings.json).  
5. For each S3 bucket, inspected the encryption settings to verify that the "SSEAlgorithm" is set to "AES256" or "aws:kms", and determined whether encryption at rest is properly enabled.

## Other Resources
- [Example Workpaper](/evidence_library/aws_audit_report.pdf)