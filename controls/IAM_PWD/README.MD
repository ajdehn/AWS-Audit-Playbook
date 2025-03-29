## Control Description
IAM passwords must meet the following complexity requirements:
- At least 14 characters in length
- Require all character types (lowercase letter, upper case letter, number, special character)

## Evidence Collection Steps
1. Call [get_account_password_policy()](https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/iam/client/get_account_password_policy.html) in Boto3. See password_policy.json for example evidence.

## Sales Pitch
- If you would like a free AWS Internal Audit, please email us at info@auditops.io.

## Other Resources
- Video: Remediation Guidance (coming soon)