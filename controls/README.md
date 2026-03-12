# Control Library
| Priority | Control Title | Control Description | Link to Documentation | Type |
| ------------- | ------------- | ------------- | ------------- |------------- |
| 1 | IAM MFA | All users with an active password must have MFA enabled. | [Link](/controls/IAM_MFA) | Automated |
| 2 | IAM Key Age | IAM access keys are rotated at least every 90 days. | [Link](/controls/IAM_Key_Age) | Automated |
| 3 | CloudTrail | At least one multi-region CloudTrail is enabled with log-file validation.| [Link](/controls/Cloud_Trail_Multi_Region) | Automated |
| 4.1 | S3 Block Public Access | S3 buckets are configured to block public access. | [Link](/controls/S3_Public) | Automated |
| 4.2 | RDS Block Public Access | RDS instances are configured to block public access. | [Link](/controls/RDS_Public) | Automated |
| 5 | RDS Backup Retention | RDS backups are retained for at least 14 days. | [Link](/controls/RDS_Backup) | Automated |
| 6.1 | User Access Review | Management conducts a user access review on at least a quarterly basis. | [Link](/controls/IAM_UAR) | Manual |
| 6.2 | EC2 Firewall Review | EC2 security groups have the proper tags applied, and have been reviewed in the last year. | [COMING SOON](/controls/EC2_SG_Tags) | Automated |
| 7.1 | GuardDuty Enabled | GuardDuty is enabled for in-scope regions. | [Link](/controls/GD_Enabled) | Automated |
| 7.1 | GuardDuty Alerts | GuardDuty is configured to send alerts to relevant personnel, for each in-scope region. | [Link](/controls/GD_Alerts) | Manual |
| 8 | Vulnerability Scans | Management conducts an infrastructure vulnerability scan on at least a quarterly basis. | [COMING SOON](/) | Manual |
| 9.1 | S3 Encryption | S3 buckets are encrypted at rest. | [Link](/controls/S3_Encrypt) | Automated |
| 9.2 | RDS Encryption | RDS instances in the AWS account are encrypted. | [Link](/controls/RDS_Encrypt) | Automated |
| 10.1 | RDS Tags | RDS instances have appropriate tags applied. | [Link](/controls/RDS_Tags) | Automated |
| 10.2 | S3 Tags | S3 buckets have appropriate tags applied. | [Link](/controls/S3_Tags) | Automated |
| 10.3 | EC2 Tags | EC2 instances have appropriate tags applied. | [Link](/controls/EC2_Tags) | Automated |
