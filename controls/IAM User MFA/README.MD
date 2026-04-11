## Control Description
IAM users with an active password must have MFA enabled.

## Example Risk
A DevOps engineering falls prey to a phishing email and the malicous actor obtains the engineer's Facebook password in plaintext. After realizing the engineer is a System Admin at a major bank, the attacker does extensive intelligence gathering and is able to login to the bank's AWS account because the engineer re-used their password. After gaining access, the malicious actor steals sensitive data, and is demanding a $10,000,000 ransom in exchange for not releasing it to the dark web.

## Required Evidence
* [users.json](/evidence_library/IAM/users.json) list of all IAM users in AWS account.
  * This evidence is gathered by calling the [list_users()](https://docs.aws.amazon.com/boto3/latest/reference/services/iam/client/list_users.html) command in Boto3.
* For each user, you will need the following:
  * [login_profile.json](/evidence_library/IAM/itauditguy/login_profile.json) obtained by calling the [get_login_profile()](https://docs.aws.amazon.com/boto3/latest/reference/services/iam/client/get_login_profile.html) command in Boto3.
  * [mfa_devices.json](/evidence_library/IAM/itauditguy/mfa_devices.json) obtained by calling the [list_mfa_devices()](https://docs.aws.amazon.com/boto3/latest/reference/services/iam/client/list_mfa_devices.html) command in Boto3.

## Testing Details
1. For each IAM user in the [users.json](/evidence_library/IAM/users.json), check if user has a login profile. If the [login_profile](/evidence_library/IAM/audit-user/login_profile.json) is null, the user doesn't have a console login and no further testing is required for this control. NOTE: You should still consider IAM access keys to check if they have programmatic access outside of the AWS console.
2. For each IAM user with a [login_profile](/evidence_library/IAM/itauditguy/login_profile.json), check if they have at least one item in MFADevices in the mfa_devices.json.
  * [Example: Passing IAM User](/evidence_library/IAM/itauditguy/mfa_devices.json)
  * [Example: Failing IAM User](/evidence_library/IAM/maverick/mfa_devices.json)

## Other Resources
- [Example Workpaper](/evidence_library/aws_audit_report.pdf)
