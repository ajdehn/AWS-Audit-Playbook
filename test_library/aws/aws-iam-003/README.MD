## aws-iam-003 (iam user MFA)

### Test Overview

- **Test Description:** IAM users with an active password must have MFA enabled.
- **Risk Level:** High
- **Risk Scenario:** An IAM user’s credentials are compromised through phishing or password reuse. Because MFA is not enabled, the attacker is able to authenticate directly into the AWS console and gain access to sensitive resources, resulting in unauthorized data exposure and potential account compromise.

### Test Procedures

1. Obtain a list of IAM users by calling the [list_users()](https://docs.aws.amazon.com/boto3/latest/reference/services/iam/client/list_users.html) Boto3 method.  
2. Save the list of IAM users: [iam/users.json](../../../evidence_library/aws/audit_evidence/iam/users.json).  
3. Perform the following for each IAM user:
    - Obtain the login profile information by calling the [get_login_profile()](https://docs.aws.amazon.com/boto3/latest/reference/services/iam/client/get_login_profile.html) Boto3 method.
    - Save the login profile: [iam/users/user_name/login_profile.json](../../../evidence_library/aws/audit_evidence/iam/users/itauditguy/login_profile.json).
    - If no login profile exists, the IAM user does not have console access and no further testing is required.
4. Perform the following for each IAM user with a login profile:
    - Obtain a list the MFA devices attached to the IAM user by calling the [list_mfa_devices()](https://docs.aws.amazon.com/boto3/latest/reference/services/iam/client/list_mfa_devices.html) Boto3 method.
    - Save the list of MFA devices attached to the IAM user: [iam/users/user_name/mfa_devices.json](../../../evidence_library/aws/audit_evidence/iam/users/itauditguy/mfa_devices.json).
5. For each IAM user with a login profile, inspect the list of MFA devices to determine whether at least one MFA device is registered.
    - [Example: Passing IAM User](../../../evidence_library/aws/audit_evidence/iam/users/itauditguy/mfa_devices.json)
    - [Example: Failing IAM User](../../../evidence_library/aws/audit_evidence/iam/users/maverick/mfa_devices.json)

### Remediation Guidance
Send the instructions below to **each** individual responsible for an IAM user without MFA:
1. Open the [AWS IAM Console](https://console.aws.amazon.com/iam/).
2. Navigate to **Users** and select the IAM user with the missing MFA device.
3. Select the **Security credentials** tab.
4. Locate the **Multi-factor authentication (MFA)** section.
5. Select **Assign MFA device**.
6. Coordinate with the IAM user to complete the MFA registration process.
7. Verify that the MFA device is successfully registered.