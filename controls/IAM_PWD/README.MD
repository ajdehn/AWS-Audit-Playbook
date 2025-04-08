## Control Description
IAM passwords must comply with the organizations password complexity requirements.

## Evidence Collection Steps
1. Call [get_account_password_policy()](https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/iam/client/get_account_password_policy.html) in Boto3. See [password_policy.json](./password_policy.json) for example evidence.

## Testing Details
1. Open the [password_policy.json](./password_policy.json) file and confirm the following:
    * "MinimumPasswordLength" >= Organization's minimum length defined in the password policy.
    * Settings for "RequireSymbols", "RequireNumbers", "RequireUppercaseCharacters", and "RequireLowercaseCharacters" comply with the password policy.
    * If in-scope, confirm "ExpirePasswords" is true & "MaxPasswordAge" is <= the number of days defined in the password policy.
    * If in-scope, confirm "PasswordReusePrevention" is >= the number of passwords remembered in the password policy.

## Support
- Please email us at info@auditops.io if you have any questions.

## Other Resources
- [Video: How to audit IAM passwords](https://www.loom.com/share/89e2dacf90f14afe8803fa05439caccc?sid=beecc028-26ee-410d-aa61-cd4c2b26efa3)
- [Video: How to update IAM password settings](https://www.youtube.com/watch?v=Ma5jxRO1nUQ)
- [Example Workpaper](https://docs.google.com/spreadsheets/d/1bGfbXUTSzVCSGCWn7UtG6QN4wWeEKdrubygcCuDDjbI/edit?gid=290595007)
