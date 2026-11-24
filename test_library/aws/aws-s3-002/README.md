## aws-s3-002 (S3 bucket public access)

### Test Overview

- **Test Description:** S3 buckets are configured to block public access.
- **Risk Level:** High
- **Risk Scenario:** An engineer accidentally leaves an S3 bucket publicly accessible. An attacker discovers the bucket, downloads sensitive customer data, and sells it on the dark web. The security team finds out when customers start asking why their personal information is for sale.

### Test Procedures

1. Obtain a list of S3 buckets by calling the [list_buckets()](https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/s3/client/list_buckets.html) Boto3 method.
2. Save the list of S3 buckets: [s3/buckets.json](../../../evidence_library/aws/audit_evidence/s3/buckets.json).
3. Perform the following for each S3 bucket:
   - Obtain the bucket's public access block configuration by calling the [get_public_access_block()](https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/s3/client/get_public_access_block.html) Boto3 method.
   - Save the bucket's public access block configuration: [s3/buckets/[bucket_name]/public_access_settings.json](../../../evidence_library/aws/audit_evidence/s3/buckets/itauditguy/public_access_settings.json).
   - Inspect the bucket's public access block configuration to determine whether `BlockPublicAcls`, `IgnorePublicAcls`, `BlockPublicPolicy`, and `RestrictPublicBuckets` are set to `true`.

**Note:** If a bucket does not meet the requirements, check if there is a valid reason (ex. S3 Bucket is intended for public consumption and thus does not require block public access to be true).

### Remediation Guidance

1. Open the [Amazon S3 Console](https://console.aws.amazon.com/s3/).
2. Select **General purpose buckets** and choose the bucket without all four Block Public Access settings enabled.
3. Navigate to the **Permissions** tab.
4. Locate the **Block public access (bucket settings)** section and select **Edit**.
5. Enable **Block all public access**.
6. Select **Save changes**.
7. Confirm the changes when prompted.
8. Verify that all four settings are enabled:
   - **Block public access to buckets and objects granted through new access control lists (ACLs)**.
   - **Block public access to buckets and objects granted through any access control lists (ACLs)**.
   - **Block public access to buckets and objects granted through new public bucket or access point policies**.
   - **Block public and cross-account access to buckets and objects through any public bucket or access point policies**.
9. Repeat for each S3 bucket that does not have all four Block Public Access settings enabled.