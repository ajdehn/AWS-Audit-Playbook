## Author
The AWS Audit Playbook is written and maintained by [AJ Dehn](https://www.linkedin.com/in/ajdehn/) founder of [AuditOps.io](https://www.auditops.io/).

## Project Goals
1. Improve audit quality by standardizing AWS audit procedures, providing example evidence, and sharing sample audit reports.
2. **Eliminate** screenshots from the AWS audit process, and re-allocate that time towards risk-based discussions.
3. Raise cloud security standards as a result of these high-quality audits.

## Project Overview
- **Test Library**: Detailed explanation of audit tests for various AWS services. Each test includes an example risk, test procedures, and links to audit evidence.
- **[Evidence Library](./evidence_library/)**: Example audit evidence generated and saved from the [AuditOps Python Library](https://pypi.org/project/auditops/).
- **[AuditOps-SDK](https://pypi.org/project/auditops/)**: Open-source Python library that generates evidence, performs testing, and builds audit reports in ~25 lines of code.
- **[AWS Training Portal](https://training.itauditguy.com/)**: Gives **everyone** a chance to login to an AWS sandbox environment.

## Project Outputs:
   - [Audit Report (PDF)](./evidence_library/aws_audit_report.pdf)
   - [Audit Report (JSON)](./evidence_library/aws_audit_report.json)


## Test Library
| Test ID | Test Description | Risk Rating |
| ------------- | ------------- | ------------- |
| [aws-cloudtrail-001](aws-cloudtrail-001) | At least one multi-region CloudTrail trail has logging enabled. | High |
| [aws-ebs-001](aws-ebs-001) | EBS volumes must have default encryption enabled in each region. | Medium |
| [aws-ebs-002](aws-ebs-002) | EBS volumes are encrypted at rest. | Medium |
| [aws-ebs-003](aws-ebs-003) | EBS volumes must have required tags applied and tag values must not be empty. | Informational |
| [aws-ec2-001](aws-ec2-001) | EC2 instances must have required tags applied and tag values must not be empty. | Informational |
| [aws-ec2-002](aws-ec2-002) | EC2 security groups have required tags applied and tag values are not empty. | Informational |
| [aws-guardduty-001](aws-guardduty-001) | GuardDuty is enabled for all in-scope regions. | High |
| [aws-iam-001](aws-iam-001) | Root account does not have any active access keys. | High |
| [aws-iam-002](aws-iam-002) | Root account has MFA enabled. | High |
| [aws-iam-003](aws-iam-003) | IAM users with an active console password have MFA enabled. | High |
| [aws-iam-004](aws-iam-004) | Active IAM user access keys are rotated at least every 90 days. | High |
| [aws-iam-005](aws-iam-005) | IAM passwords comply with the organization's password policy. | Medium |
| [aws-lambda-001](aws-lambda-001) | Lambda functions must have required tags applied and tag values must not be empty. | Informational |
| [aws-rds-001](aws-rds-001) | RDS instances are encrypted at rest. | Medium |
| [aws-rds-002](aws-rds-002) | RDS instances are configured to block public access. | High |
| [aws-rds-003](aws-rds-003) | RDS backups are retained for at least 14 days. | Low |
| [aws-rds-004](aws-rds-004) | RDS instances have automatic minor version upgrades enabled. | Low |
| [aws-rds-005](aws-rds-005) | RDS instances have deletion protection enabled at the cluster or instance level. | Medium |
| [aws-rds-006](aws-rds-006) | RDS instances must have required tags applied and tag values must not be empty. | Informational |
| [aws-s3-001](aws-s3-001) | S3 buckets are encrypted at rest. | Medium |
| [aws-s3-002](aws-s3-002) | S3 buckets are configured to block public access. | Medium |
| [aws-s3-003](aws-s3-003) | S3 buckets are configured to deny unencrypted data in-transit. | Informational |
| [aws-s3-004](aws-s3-004) | S3 buckets must have required tags applied and tag values must not be empty. | Informational |
