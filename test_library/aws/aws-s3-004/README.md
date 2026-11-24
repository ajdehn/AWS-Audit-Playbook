## aws-s3-004 (S3 bucket tagging)

### Test Overview

- **Test Description:** S3 buckets in the AWS account have appropriate tags applied.
- **Risk Level:** Informational
- **Risk Scenario:** Your lead DevOps engineer wins the lottery and walks away with $100 million dollars. You never hear from them again, and your team is unable to determine who owns or maintains critical S3 buckets. Suddenly, a simple maintenance task turns into an organizational scavenger hunt.

### Test Procedures

1. Obtain a list of S3 buckets by calling the [list_buckets()](https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/s3/client/list_buckets.html) Boto3 method.
2. Save the list of buckets: [s3/buckets.json](../../../evidence_library/aws/audit_evidence/s3/buckets.json).
3. Perform the following for each S3 bucket:
    - Obtain the bucket's tags by calling the [get_bucket_tagging()](https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/s3/client/get_bucket_tagging.html) Boto3 method.
    - Save the attached tags: [s3/[bucket_name]/tags.json](../../../evidence_library/aws/audit_evidence/s3/buckets/itauditguy/bucket_tags.json).
    - Inspect the tags to determine whether the required tags exist and contain non-empty values.

**NOTE:** By default, the AuditOps Python library requires the tags `Owner`, `Description`, and `Classification`. To change the default required tags, update the `AWSConfig` values.

### Remediation Guidance

1. Open the [Amazon S3 Console](https://console.aws.amazon.com/s3/).
2. Select **General purpose buckets** and choose the bucket missing the required tags.
3. Navigate to the **Properties** tab.
4. Locate the **Tags** section and select **Edit**.
5. Add the required tags and their corresponding non-empty values:
   - `Owner`: The individual or team responsible for maintaining the S3 bucket.
   - `Description`: A brief description of the bucket and its intended purpose.
   - `Classification`: The data classification level of the information stored in the bucket.
6. Select **Save changes**.
7. Verify that the required tags are present and contain non-empty values.
8. Repeat for each S3 bucket missing the required tags.

### Other Resources
- [VIDEO TUTORIAL: How to Audit S3 Bucket Tags](https://youtu.be/7av0BotJaQE)