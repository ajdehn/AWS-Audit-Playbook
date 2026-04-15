## Control Description
AWS passwords must comply with the organization's password complexity requirements.

## Example Risk
An engineer sets their IAM user's password as "Spring2026!". Their account is compromised and the attacker is threatening to release your company's sensitive data unless you pay a $500,000 ransom.

## Test Procedures
1. Obtained the AWS account password policy by calling the [get_account_password_policy()](https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/iam/client/get_account_password_policy.html) boto3 command. These settings are applicable to all IAM users in the account.
2. Saved the AWS account password policy as [IAM/password_policy.json](/evidence_library/IAM/password_policy.json).
3. Reviewed the `password_policy.json` file to determine whether the password policy settings meet organizational requirements, including:  
    * "MinimumPasswordLength" >= minimum length required in the password policy.
    * Password complexity requirements ("RequireSymbols", "RequireNumbers", "RequireUppercaseCharacters", and "RequireLowercaseCharacters") comply with the password policy.
    * If required, "MaxPasswordAge" is <= the number of days defined in the password policy & "ExpirePasswords" is set to true.
    * If required, "PasswordReusePrevention" is >= the number of passwords remembered in the password policy.

**Note:** If you want to change the default password configuration checks, please update the config file with your desired values. See example below:
```
"iam_password_min_length": 20,
"iam_password_min_complexity_types": 4,
"iam_password_require_expiration": false,
"iam_password_max_password_age": null,
"iam_password_password_history": 24,
"iam_key_max_age": 90
```

## Other Resources
- [Example Workpaper](/evidence_library/aws_audit_report.pdf)
- [Video: How to update IAM password settings](https://www.youtube.com/watch?v=Ma5jxRO1nUQ)