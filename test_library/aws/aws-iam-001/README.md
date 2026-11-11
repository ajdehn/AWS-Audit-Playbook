## aws-iam-001 (Root Access Key)

### Test Overview
- **Test Description:** The AWS root account does not have any active access keys.
- **Risk Level:** High
- **Risk Scenario:** An attacker discovers an exposed AWS root account access key and uses it to gain unauthorized access to the organization's AWS environment, potentially resulting in data exposure, resource destruction, or service disruption.

### Test Procedure
1. Call the [get_account_summary()](https://docs.aws.amazon.com/boto3/latest/reference/services/iam/client/get_account_summary.html) boto3 command.  
2. Save the API response: [iam/account_summary.json](../../../evidence_library/aws/audit_evidence/iam/account_summary.json).  
3. Inspect the evidence (iam/account_summary.json) to determine whether the `AccountAccessKeysPresent` property is set to `0`.

### Remediation Guidance

#### Prerequisites:
In order to remediate this finding, you will need to login to the AWS Root Account.

#### Warning:
Before deactivating any access keys, verify whether they are being used by any applications, scripts, integrations, or automation. Deactivating an access key will immediately prevent it from being used to authenticate to AWS and may disrupt dependent services.

We recommend deactivating the access key first and allowing an appropriate monitoring period to identify any unexpected impact before permanently deleting it.
 
#### Remediation Procedure:
1. [Open the AWS Management Console](https://console.aws.amazon.com/) and sign in using the AWS root account credentials.
2. Navigate to **Security credentials**.
3. Locate the **Access keys** section and identify any active access keys.
4. Before making changes, review AWS CloudTrail activity and other available logs to determine whether the access keys are being used by applications, scripts, or integrations.
5. For any keys that are still active, select **Deactivate**.
6. Monitor dependent applications and AWS activity for an appropriate cooling-off period to identify any unexpected disruptions.
7. Once you have confirmed that the access key is no longer needed, permanently delete it.
8. Verify that no active root access keys remain.
