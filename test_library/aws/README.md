## AWS Test Library
| Test ID | Test Description | Risk Rating |
| ------------- | ------------- | ------------- |
| [aws-cloudtrail-001](/test_library/aws-cloudtrail-001) | At least one multi-region CloudTrail trail has logging enabled. | High |
| [aws-ebs-002](/test_library/aws-ebs-002) | EBS volumes are encrypted at rest. | Medium |
| [aws-ebs-003](/test_library/aws-ebs-003) | EBS volumes must have required tags applied and tag values must not be empty. | Informational |
| [aws-ec2-001](/test_library/aws-ec2-001) | EC2 instances must have required tags applied and tag values must not be empty. | Informational |
| [aws-ec2-002](/test_library/aws-ec2-002) | EC2 security groups have required tags applied and tag values are not empty. | Informational |
| [aws-guardduty-001](/test_library/aws-guardduty-001) | GuardDuty is enabled for all in-scope regions. | High |
| [aws-iam-001](/test_library/aws-iam-001) | Root account does not have any active access keys. | High |
| [aws-iam-002](/test_library/aws-iam-002) | Root account has MFA enabled. | High |
| [aws-iam-003](/test_library/aws-iam-003) | IAM users with an active console password have MFA enabled. | High |
| [aws-iam-004](/test_library/aws-iam-004) | Active IAM user access keys are rotated at least every 90 days. | High |
| [aws-iam-005](/test_library/aws-iam-005) | IAM passwords comply with the organization's password policy. | Medium |
| [aws-lambda-001](/test_library/aws-lambda-001) | Lambda functions must have required tags applied and tag values must not be empty. | Informational |
| [aws-rds-001](/test_library/aws-rds-001) | RDS instances are encrypted at rest. | Medium |
| [aws-rds-002](/test_library/aws-rds-002) | RDS instances are configured to block public access. | High |
| [aws-rds-003](/test_library/aws-rds-003) | RDS backups are retained for at least 14 days. | Low |
| [aws-rds-004](/test_library/aws-rds-004) | RDS instances have automatic minor version upgrades enabled. | Low |
| [aws-rds-005](/test_library/aws-rds-005) | RDS instances have deletion protection enabled at the cluster or instance level. | Medium |
| [aws-rds-006](/test_library/aws-rds-006) | RDS instances must have required tags applied and tag values must not be empty. | Informational |
| [aws-s3-001](/test_library/aws-s3-001) | S3 buckets are encrypted at rest. | Medium |
| [aws-s3-002](/test_library/aws-s3-002) | S3 buckets are configured to block public access. | Medium |
| [aws-s3-003](/test_library/aws-s3-003) | S3 buckets are configured to deny unencrypted data in-transit. | Informational |
| [aws-s3-004](/test_library/aws-s3-004) | S3 buckets must have required tags applied and tag values must not be empty. | Informational |
