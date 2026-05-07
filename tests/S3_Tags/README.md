## Test Description
S3 buckets in the AWS account have appropriate tags applied.

## Example Risk
Your lead DevOps engineer wins the lottery and walks away with $100 million dollars. You never hear from them again, and your team is unable to maintain your AWS account.

## Test Procedures
1. Obtained a list of S3 buckets by calling the [list_buckets()](https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/s3/client/list_buckets.html) boto3 command.
2. Saved the list of buckets: [s3/buckets.json](/evidence_library/s3/buckets.json).
3. For each bucket, obtained its tags by calling the [get_bucket_tagging()](https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/s3/client/get_bucket_tagging.html) boto3 command.
4. For each bucket, saved the attached tags: [s3/[bucket_name]/tags.json)](/evidence_library/s3/buckets/itauditguy/bucket_tags.json).
5. For each bucket, inspected the tags to determine if the required tags exist and contain non-empty values.
  * By default, the playbook requires the following tags: "Owner", "Description", "Classification".
  * If you want to change the default required tags, please add them under 's3_required_tags' in the 'test_config' section of the config.json file.

## Other Resources
- [Example Workpaper](/evidence_library/aws_audit_report.pdf)
- [VIDEO TUTORIAL: How to Audit S3 Bucket Tags](https://youtu.be/7av0BotJaQE)
