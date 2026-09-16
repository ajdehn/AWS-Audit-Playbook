## Test Description
IAM users with an active password must have MFA enabled.

## Example Risk
An IAM user’s credentials are compromised through phishing or password reuse. Because MFA is not enabled, the attacker is able to authenticate directly into the AWS console and gain access to sensitive resources, resulting in unauthorized data exposure and potential account compromise.

## Test Procedures
1. Obtained a list of IAM users in the AWS account by calling the [list_users()](https://docs.aws.amazon.com/boto3/latest/reference/services/iam/client/list_users.html) boto3 command.  
2. Saved the list of IAM users: [iam/users.json](/evidence_library/iam/users.json).  
3. For each IAM user, obtained the login profile information by calling the [get_login_profile()](https://docs.aws.amazon.com/boto3/latest/reference/services/iam/client/get_login_profile.html) boto3 command.
4. For each IAM user, saved the login profile: [iam/users/user_name/login_profile.json](/evidence_library/iam/users/itauditguy/login_profile.json).
    1. If no login profile exists, the user does not have console access and no further testing is required for this control. Note: Access keys should still be evaluated for this IAM user.
5. For each IAM user with a login profile, obtained the MFA device information by calling the [list_mfa_devices()](https://docs.aws.amazon.com/boto3/latest/reference/services/iam/client/list_mfa_devices.html) boto3 command.  
6. For each IAM user with a login profile, saved the MFA device information: [iam/users/user_name/mfa_devices.json](/evidence_library/iam/users/itauditguy/mfa_devices.json).
7. For each IAM user with a login profile, inspected `mfa_devices.json` to determine if at least one MFA device is registered.  
   1. [Example: Passing IAM User](/evidence_library/iam/users/itauditguy/mfa_devices.json)  
   2. [Example: Failing IAM User](/evidence_library/iam/users/maverick/mfa_devices.json)  

## Other Resources
- [Example Workpaper](/evidence_library/aws_audit_report.pdf)