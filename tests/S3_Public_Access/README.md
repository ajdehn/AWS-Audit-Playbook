## Control Description
S3 buckets are configured to block public access.

## Example Risk
An engineer accidentally leaves an S3 bucket publicly accessible, and the bucket name gets picked up by a search engine. Strangers are now scanning your bucket daily, waiting for another misconfiguration to steal sensitive data.

## Test Procedures
1. Obtained a list of S3 buckets by calling the [list_buckets()](https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/s3/client/list_buckets.html) boto3 command.  
2. Saved the list of buckets: [S3/buckets.json](/evidence_library/S3/buckets.json).  
3. For each S3 bucket, obtained the public access block configuration by calling the [get_public_access_block()](https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/s3/client/get_public_access_block.html) boto3 command.  
4. For each S3 bucket, saved the public access settings: [S3/buckets/[bucket_name]/public_access_settings.json](/evidence_library/S3/buckets/itauditguy/public_access_settings.json).  
5. For each S3 bucket, inspected the public access settings to verify that "BlockPublicAcls", "IgnorePublicAcls", "BlockPublicPolicy", and "RestrictPublicBuckets" are set to true.
  * If the bucket does not meet the requirements, check if there is a valid reason (ex. S3 Bucket is intended for public consumption and thus does not require block public access to be true).
  
## Other Resources
- [Example Workpaper](/evidence_library/aws_audit_report.pdf)