## aws-iam-004 (iam access key age)

### Test Overview

- **Test Description:** IAM access keys are rotated at least every 90 days.
- **Risk Level:** High
- **Risk Scenario:** Your organization created an IAM access key for a legacy data & analytics tool. This access key is compromised and allows attackers to extract data from your AWS account.

### Test Procedures

1. Obtain a list of IAM users by calling the [list_users()](https://docs.aws.amazon.com/boto3/latest/reference/services/iam/client/list_users.html) Boto3 method.  
2. Save the list of IAM users: [iam/users.json](../../../evidence_library/aws/audit_evidence/iam/users.json).
3. Perform the following for each IAM user:
    - Obtain a list of access keys associated with the IAM user by calling the [list_access_keys()](https://docs.aws.amazon.com/boto3/latest/reference/services/iam/client/list_access_keys.html) Boto3 method.
    - Save the list of access keys: [iam/users/user_name/access_keys.json](../../../evidence_library/aws/audit_evidence/iam/users/itauditguy/access_keys.json).
    - For each IAM user's access keys, inspect the `AccessKeyMetadata` property to identify active access keys. If the access key is inactive, exclude it from testing.
    - For each active access key, inspect the CreateDate property to determine its age. If the active access key is more than 90 days old, note an exception.

**NOTE:** By default, the AuditOps Python library sets the maximum age for an IAM access key to **90 days**. To customize this value, please update the `iam_access_key_max_age` property in the AWSConfig file with your desired values. See example below:
```
aws_config.iam_access_key_max_age = 30
```

### Remediation Guidance

#### Warning:
Before deactivating any access keys, verify whether they are being used by any applications, scripts, integrations, or automation. Deactivating an access key will immediately prevent it from being used to authenticate to AWS and may disrupt dependent services.

We recommend deactivating the access key first and allowing an appropriate monitoring period to identify any unexpected impact before permanently deleting it.

#### Prerequisites:
Contact the IAM user or the individual responsible for managing the account to coordinate access key rotation.

#### Remediation Procedure:
1. Open the [AWS IAM Console](https://console.aws.amazon.com/iam/).
2. Navigate to **Users** and select the IAM user with the outdated access key.
3. Select the **Security credentials** tab.
4. Locate the **Access keys** section and identify the active access key that exceeds 90 days.
5. Before making changes, review AWS CloudTrail activity and other available logs to identify applications, scripts, integrations, or automation that may be using the access key.
6. Create a replacement access key and securely provide it to the responsible individual.
7. Update dependent applications, scripts, integrations, and automation to use the replacement access key.
8. Once the replacement key is confirmed to be working, deactivate the outdated access key.
9. Monitor dependent applications and AWS activity for an appropriate cooling-off period to identify any unexpected disruptions.
10. Once you have confirmed that the outdated access key is no longer needed, permanently delete it.
11. Repeat for each IAM user with an active access key older than 90 days.