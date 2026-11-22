## aws-iam-002 (root account MFA)

### Test Overview
- **Test Description:** The AWS root account has MFA enabled.
- **Risk Level:** High
- **Risk Scenario:** The AWS root account is compromised because it is not protected by MFA. The attacker changes the password, locks all employees out of AWS, and encrypts all sensitive data.

### Test Procedures

1. Obtain the AWS account summary by calling the [get_account_summary()](https://docs.aws.amazon.com/boto3/latest/reference/services/iam/client/get_account_summary.html) Boto3 method.
2. Save the AWS account summary: [iam/account_summary.json](../../../evidence_library/aws/audit_evidence/iam/account_summary.json).  
3. Inspect the AWS Account Summary to determine whether the `AccountPasswordPresent` property is set to `1`. If a password is not present, this monitoring test is passing. No further testing is required.
4. If a root account password is present, inspect the AWS Account Summary to determine whether the `AccountMFAEnabled` property is set to `1`.

### Remediation Guidance

#### Prerequisites:
In order to remediate this finding, you will need to log in using the AWS root account credentials.

#### Remediation Procedure:
1. Open the [AWS Management Console](https://console.aws.amazon.com/) and sign in using the AWS root account credentials.
2. Navigate to **Security credentials**.
3. Locate the **Multi-factor authentication (MFA)** section.
4. Select **Assign MFA device**.
5. Follow the instructions to configure an MFA device for the root account.
6. Verify that the MFA device is successfully registered and that MFA is enabled for the root account.