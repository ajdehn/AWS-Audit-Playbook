# Test Library
| Priority | Example Control Description | Evidence Type | Test Documentation | ISO 27001 Mapping|
| ------------- | ------------- | ------------- | ------------- | ------------- |
| 1 | Multi-factor authentication is configured for all users of critical systems. | Automated | [aws-iam-002](aws-iam-002)<br>[aws-iam-003](aws-iam-003) |A.5.18, A.8.5|
| 2 | Infrastructure service account credentials are rotated at least once per year. | Automated | [aws-iam-001](aws-iam-001)<br>[aws-iam-004](aws-iam-004) |A.5.18, A.8.5|
| 3 | Audit logs are enabled to capture activity within the cloud infrastructure.| Automated | [aws-cloudtrail-001](aws-cloudtrail-001) |A.8.15|
| 4 | Cloud resources are configured to block public access. | Automated | [aws-s3-002](aws-s3-002)<br>[aws-rds-002](aws-rds-002) |A.8.9|
| 5 | Production database backups are taken daily, and are retained for at least 14 days. | Automated | [aws-rds-003](aws-rds-003) |A.8.13|
| 6.1 | Management conducts a user access review on at least a quarterly basis. | Manual | [IAM User Access Review](IAM_User_Access_Review) |A.5.18|
| 6.2 | Management conducts a firewall review on at least a quarterly basis. | Automated | [aws-ec2-002](aws-ec2-002) |A.8.20|
| 7 | The production environment is monitored for suspicious or anomalous activity. | Partially Automated | [aws-guardduty-001](aws-guardduty-001) |A.8.7|
| 8 | Management conducts an infrastructure vulnerability scan on at least a quarterly basis. | Manual | Coming Soon |A.8.8|
| 9.1 | Cloud resources are configured to encrypt data in-transit. | Automated | [aws-s3-003](aws-s3-003)|A.8.24|
| 9.2 | Cloud resources are encrypted at rest. | Automated | [aws-rds-001](aws-rds-001)<br>[aws-s3-001](aws-s3-001) |A.8.9, A.8.24|
| 10 | Cloud resources are tagged based on the requirements set in the asset management policy. | Automated | [aws-ec2-001](aws-ec2-001)<br>[aws-rds-006](aws-rds-006)<br>[aws-s3-004](aws-s3-004) |A.5.9, A.5.12|
