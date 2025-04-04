## Control Description
IAM passwords must comply with the organizations password complexity requirements.

## Evidence Collection Steps
1. Collect the client's Password Policy document. Once collected, you will need to compare the documented minimum length, maximum password age, and other complexity requirements to the JSON file below.
2. Call [get_account_password_policy()](https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/iam/client/get_account_password_policy.html) in Boto3. See [password_policy.json](./password_policy.json) for example evidence.

## Sales Pitch
- If you would like a free AWS Internal Audit, please email us at info@auditops.io.

## Other Resources
- [Video: How to audit IAM passwords](https://docs.google.com/spreadsheets/d/1bGfbXUTSzVCSGCWn7UtG6QN4wWeEKdrubygcCuDDjbI/edit?gid=290595007)
- [Video: How to update IAM password settings](https://docs.google.com/spreadsheets/d/1bGfbXUTSzVCSGCWn7UtG6QN4wWeEKdrubygcCuDDjbI/edit?gid=290595007)
- [Example Workpaper](https://docs.google.com/spreadsheets/d/1bGfbXUTSzVCSGCWn7UtG6QN4wWeEKdrubygcCuDDjbI/edit?gid=290595007)

