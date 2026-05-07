## Test Description
The AWS root account does not have any active access keys.

## Example Risk
The AWS root account access key is compromised after it's discovered in a .env file. The attacker changes the password, locks all employees out of AWS, and encrypts sensitive data.

## Test Procedures
1. Obtained the AWS account summary by calling the [get_account_summary()](https://docs.aws.amazon.com/boto3/latest/reference/services/iam/client/get_account_summary.html) boto3 command.  
2. Saved the account summary: [iam/account_summary.json](/evidence_library/iam/account_summary.json).  
3. Inspected the account summary to determine if `AccountAccessKeysPresent` is set to `0`.

## Other Resources
- [Example Workpaper](/evidence_library/aws_audit_report.pdf)