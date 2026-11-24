## aws-s3-001 (S3 bucket encryption)

### Test Overview

- **Test Description:** S3 buckets are encrypted at rest.
- **Risk Level:** Medium
- **Risk Scenario:** One of your S3 buckets was created before AWS turned on encryption by default. Everyone assumes all buckets are encrypted until you undergo a regulatory audit and face a $50,000 fine for failing to encrypt sensitive data.

### Test Procedures

1. Obtain a list of S3 buckets by calling the [list_buckets()](https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/s3/client/list_buckets.html) Boto3 method.
2. Save the list of S3 buckets: [s3/buckets.json](../../../evidence_library/aws/audit_evidence/s3/buckets.json).
3. Perform the following for each S3 bucket:
    - Obtain the bucket's encryption settings by calling the [get_bucket_encryption()](https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/s3/client/get_bucket_encryption.html) Boto3 method.
    - Save the bucket's encryption settings: [s3/buckets/[bucket_name]/encryption_settings.json](../../../evidence_library/aws/audit_evidence/s3/buckets/itauditguy/encryption_settings.json).
    - Inspect the bucket's encryption settings to determine whether the `SSEAlgorithm` is set to `AES256` or `aws:kms`.

### Remediation Guidance

1. Open the [Amazon S3 Console](https://console.aws.amazon.com/s3/).
2. Select **General purpose buckets** and choose the bucket without default encryption enabled.
3. Navigate to the **Properties** tab.
4. Locate the **Default encryption** section and select **Edit**.
5. Under **Encryption type**, select **Server-side encryption with Amazon S3 managed keys (SSE-S3)** or **Server-side encryption with AWS Key Management Service keys (SSE-KMS)**, as appropriate.
6. If using SSE-KMS, select the appropriate AWS KMS key and verify that the necessary permissions are configured.
7. Select **Save changes**.
8. Verify that default encryption is enabled and the encryption algorithm is set to `AES256` or `aws:kms`.
9. Repeat for each S3 bucket without default encryption enabled.