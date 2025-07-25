## Control Description
S3 buckets in the AWS account have appropriate tags applied.

## Required Evidence
* [all_s3_buckets.json](/evidence_library/S3/all_s3_buckets.json) provides a list of all S3 buckets.
  * This evidence is gathered by calling the [list_buckets()](https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/s3/client/list_buckets.html) command in Boto3.
* [bucket_tags.json](/evidence_library/S3/buckets/itauditguy/bucket_tags.json) provides the tags for an individual S3 bucket.
  * This evidence is gathered by calling the [get_bucket_tagging()](https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/s3control/client/get_bucket_tagging.html) command in Boto3.

## Testing Details
1. Review the full listing of all S3 buckets in the [all_s3_buckets.json](/evidence_library/S3/all_s3_buckets.json) file.
2. For each S3 bucket, review the [bucket_tags.json](/evidence_library/S3/buckets/itauditguy/bucket_tags.json) file.
3. Confirm all required tags are applied on each bucket as described in the organization's Data Classification Policy. Usually this policy requires assets to have an "Owner", "Description", and "Classification".

## Other Resources
- [Example Workpaper](https://docs.google.com/spreadsheets/d/1bGfbXUTSzVCSGCWn7UtG6QN4wWeEKdrubygcCuDDjbI/edit?gid=1021258140)
- [VIDEO TUTORIAL: How to Audit S3 Bucket Tags](https://youtu.be/7av0BotJaQE)
