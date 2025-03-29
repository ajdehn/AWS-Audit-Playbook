## Control Description
All IAM users with an active password must have MFA enabled.

## Evidence Collection Steps
1. Call [list_users()](https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/iam/client/list_users.html) in Boto3 to get a full list of IAM users.
2. Call [list_mfa_devices()](https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/iam/client/list_users.html) in Boto3 to check if the IAM user has MFA enabled.


## Sales Pitch
- If you would like a free AWS Internal Audit, please email (info@auditops.io).

## Other Resources
- Video: Remediation Guidance (coming soon)