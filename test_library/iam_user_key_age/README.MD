## Test Description
IAM access keys are rotated at least every 90 days.

## Example Risk
Your organization created an IAM access key for a legacy data & analytics tool. This access key is compromised and allows attackers to extract data from your AWS account.

## Test Procedures
1. Obtained a list of IAM users in the AWS account by calling the [list_users()](https://docs.aws.amazon.com/boto3/latest/reference/services/iam/client/list_users.html) boto3 command.  
2. Saved the list of IAM users: [iam/users.json](/evidence_library/iam/users.json).  
3. For each IAM user, obtained access key metadata by calling the [list_access_keys()](https://docs.aws.amazon.com/boto3/latest/reference/services/iam/client/list_access_keys.html) boto3 command.  
4. For each IAM user, saved access key metadata: [iam/users/user_name/access_keys.json](/evidence_library/iam/users/itauditguy/access_keys.json).
5. For each IAM user, inspected the `AccessKeyMetadata` to identify all access keys and determine their status.  
6. For each access key with a status of `Active`, inspected the `CreateDate` to determine the age of the key and determined whether the key is less than or equal to 90 days old.  
   - If the access key is inactive, it is excluded from testing.  
   - If the access key exceeds 90 days, an it is marked as an exception.

**Note:** The default maximum age for IAM access keys is 90 days. To customize this value, update the `iam_key_max_age` setting in the `test_config` section of the `config.json` file.

## Other Resources
- [Example Workpaper](/evidence_library/aws_audit_report.pdf)