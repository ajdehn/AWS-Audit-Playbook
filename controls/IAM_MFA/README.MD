## Control Description
All users with an active password must have MFA enabled.

## Evidence Collection Steps
1. Call [generate_credentials_report()](https://boto3.amazonaws.com/v1/documentation/api/1.26.89/reference/services/iam/client/generate_credential_report.html) command in Boto3.
2. Call [get_credentials_report()](https://boto3.amazonaws.com/v1/documentation/api/1.26.89/reference/services/iam/client/get_credential_report.html) command in Boto3.

## Support
- Please email us at info@auditops.io if you have any questions.

## Other Resources
- Video: Remediation Guidance (coming soon)
