## Control Description
All users with an active password must have MFA enabled.

## Evidence Collection Steps
1. Call [generate_credentials_report()](https://boto3.amazonaws.com/v1/documentation/api/1.26.89/reference/services/iam/client/generate_credential_report.html) command in Boto3.
2. Call [get_credentials_report()](https://boto3.amazonaws.com/v1/documentation/api/1.26.89/reference/services/iam/client/get_credential_report.html) command in Boto3. See [credentials_report.csv](./credentials_report.csv) as an example.

## Testing Details
1. Open the [credentials_report.csv](./credentials_report.csv) and confirm that all users with an active password also have MFA enabled.

## Support
- Please email us at info@auditops.io if you have any questions.

## Other Resources
- [Example Workpaper](https://docs.google.com/spreadsheets/d/1bGfbXUTSzVCSGCWn7UtG6QN4wWeEKdrubygcCuDDjbI/edit?gid=1190435560)
