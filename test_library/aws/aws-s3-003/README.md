## aws-s3-003 (S3 bucket secure transport)

### Test Overview

- **Test Description:** S3 buckets are configured to deny unencrypted data in-transit.

- **Risk Level:** Medium
- **Risk Scenario:** An engineer accidentally uploads sensitive customer documents to an S3 bucket over an unencrypted HTTP connection while working from a coffee shop. An attacker on the same network intercepts the traffic and walks away with a copy of your customers' bank account information.

### Test Procedures

1. Obtain a list of S3 buckets by calling the [list_buckets()](https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/s3/client/list_buckets.html) Boto3 method.
2. Save the list of S3 buckets: [s3/buckets.json](../../../evidence_library/aws/audit_evidence/s3/buckets.json).
3. Perform the following for each S3 bucket:
   - Obtain the bucket policy by calling the [get_bucket_policy()](https://docs.aws.amazon.com/boto3/latest/reference/services/s3/client/get_bucket_policy.html) Boto3 method.
   - Save the bucket policy: [s3/buckets/[bucket_name]/policy.json](../../../evidence_library/aws/audit_evidence/s3/buckets/itauditguy/policy.json).
   - Inspect the bucket policy to determine whether a statement exists that denies requests when `aws:SecureTransport` is `false`.

### Remediation Guidance

1. Open the [Amazon S3 Console](https://console.aws.amazon.com/s3/).
2. Select **General purpose buckets** and choose the affected bucket.
3. Navigate to the **Permissions** tab.
4. Locate the **Bucket policy** section and select **Edit**.
5. Add the following statement to the existing bucket policy, replacing `YOUR-BUCKET-NAME` with the actual bucket name:

```json
{
    "Sid": "DenyInsecureTransport",
    "Effect": "Deny",
    "Principal": "*",
    "Action": "s3:*",
    "Resource": [
        "arn:aws:s3:::YOUR-BUCKET-NAME",
        "arn:aws:s3:::YOUR-BUCKET-NAME/*"
    ],
    "Condition": {
        "Bool": {
            "aws:SecureTransport": "false"
        }
    }
}
```

6. Select **Save changes**.
7. Verify that the bucket policy denies requests when `aws:SecureTransport` is `false`.
8. Repeat for each affected S3 bucket.