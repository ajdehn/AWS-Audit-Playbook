## aws-iam-005 (iam password policy)

### Test Overview

- **Test Description:** AWS passwords must comply with the organization's password complexity requirements.
- **Risk Level:** Medium
- **Risk Scenario:** An engineer sets their IAM user's password as "Fall2026!". Their IAM user account is compromised and the attacker is threatening to release your company's sensitive data unless you pay a $500,000 ransom.

### Test Procedures

1. Obtain the AWS password policy by calling the [get_account_password_policy()](https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/iam/client/get_account_password_policy.html) Boto3 method.
2. Save the AWS password policy: [iam/password_policy.json](../../../evidence_library/aws/audit_evidence/iam/password_policy.json).
    - If no password policy is configured, note an exception. No further testing is required.
3. Inspect the AWS account password policy to determine whether it complies with the following requirements:
   - `MinimumPasswordLength` is greater than or equal to 14.
   - `RequireSymbols`, `RequireNumbers`, `RequireUppercaseCharacters`, and `RequireLowercaseCharacters` are set to `true`.
   - `PasswordReusePrevention` is greater than or equal to 24.
   - If password expiration is configured, verify that `MaxPasswordAge` does not exceed the organization's configured maximum.

**NOTE:** By default, the AuditOps Python library requires a minimum password length of 14 characters, uppercase and lowercase letters, numbers, symbols, and prevention of password reuse for the previous 24 passwords.

Password expiration is disabled by default (`iam_max_password_age = 0`). This follows current NIST password guidance, which discourages routine password changes unless there is evidence of compromise or another indication that a change is necessary. Organizations may configure a maximum password age if required by their internal policies or compliance obligations.

To customize the default password requirements, update the corresponding values in `AWSConfig`.

```
aws_config.iam_minimum_password_length = 20
aws_config.iam_require_uppercase: bool = True
aws_config.iam_require_lowercase: bool = True
aws_config.iam_require_numbers: bool = True
aws_config.iam_require_symbols: bool = True
aws_config.iam_max_password_age: int = 365
aws_config.iam_password_reuse_prevention: int = 24
```

### Other Resources
- [Video: How to update IAM password settings](https://www.youtube.com/watch?v=Ma5jxRO1nUQ)

### Remediation Guidance

1. Open the [AWS IAM Console](https://console.aws.amazon.com/iam/).
2. Navigate to **Account settings**.
3. Locate the **Password policy** section and select **Edit**.
4. Update the password policy settings to meet the organization's requirements. See AuditOps default settings below (customized through AWSConfig):
   - Set the minimum password length to at least 14 characters.
   - Require uppercase and lowercase letters.
   - Require numbers and symbols.
   - Prevent the reuse of at least the last 24 passwords.
5. Save the changes.
6. Verify that the updated password policy meets the organization's requirements.