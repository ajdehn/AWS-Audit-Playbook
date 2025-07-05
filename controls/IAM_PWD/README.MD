## Control Description
AWS passwords must comply with the organization's password complexity requirements.

## Required Evidence
* [password_policy.json](/evidence_library/IAM/password_policy.json) describes the password requirements for the AWS account. These settings are applicable to all IAM users in the account.
  * This evidence is gathered by calling the [get_account_password_policy()](https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/iam/client/get_account_password_policy.html) command in Boto3.

## Testing Details
1. Review the [password_policy.json](/evidence_library/IAM/password_policy.json) file and confirm the following:
    * "MinimumPasswordLength" >= minimum length required in the password policy.
    * Settings for "RequireSymbols", "RequireNumbers", "RequireUppercaseCharacters", and "RequireLowercaseCharacters" comply with the password policy.
    * If required, confirm "MaxPasswordAge" is <= the number of days defined in the password policy & "ExpirePasswords" is set to true.
    * If required, confirm "PasswordReusePrevention" is >= the number of passwords remembered in the password policy.

## Other Resources
- [Video: How to update IAM password settings](https://www.youtube.com/watch?v=Ma5jxRO1nUQ)
- [Example Workpaper](https://docs.google.com/spreadsheets/d/1bGfbXUTSzVCSGCWn7UtG6QN4wWeEKdrubygcCuDDjbI/edit?gid=290595007)
