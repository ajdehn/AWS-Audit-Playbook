## Control Description
IAM access keys are less than 90 days old.

## Required Evidence
* [credentials_report.csv](/evidence_library/IAM/credentials_report.csv) lists all users in your account and the status of their various credentials, including access keys.
  * This evidence is gathered by calling the [generate_credentials_report()](https://boto3.amazonaws.com/v1/documentation/api/1.26.89/reference/services/iam/client/generate_credential_report.html) & [get_credentials_report()](https://boto3.amazonaws.com/v1/documentation/api/1.26.89/reference/services/iam/client/get_credential_report.html) commands in Boto3.

## Testing Details
1. Open the [credentials_report.csv](/evidence_library/IAM/credentials_report.csv) and confirm that no users have an access key over 90 days old.

## Other Resources
- [Example Workpaper](https://docs.google.com/spreadsheets/d/1bGfbXUTSzVCSGCWn7UtG6QN4wWeEKdrubygcCuDDjbI/edit?gid=1228234859)
