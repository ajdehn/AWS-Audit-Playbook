# Test Library
| Priority | Test Description | Evidence Type | Test Documentation | ISO 27001 Mapping|
| ------------- | ------------- | ------------- | ------------- | ------------- |
| 1 | Multi-factor authentication is configured for all users of critical systems. | Automated | [IAM Root MFA](IAM_Root_MFA)<br>[IAM User MFA](IAM_User_MFA) |A.5.18, A.8.5|
| 2 | Infrastructure service account credentials are rotated at least once per year. | Automated | [IAM Root Access Key](IAM_Root_Access_Key)<br>[IAM User Key Age](IAM_User_Key_Age) |A.5.18, A.8.5|
| 3 | Audit logs are enabled to capture activity within the cloud infrastructure.| Automated | [CloudTrail Multi Region](Cloud_Trail_Multi_Region) |A.8.15|
| 4 | Cloud resources are configured to block public access. | Automated | [S3_Public](S3_Public_Access)<br>[RDS_Public](RDS_Public_Access) |A.8.9|
| 5 | Production database backups are taken daily, and are retained for at least 14 days. | Automated | [RDS_Backup Retention](RDS_Backup_Retention) |A.8.13|
| 6.1 | Management conducts a user access review on at least a quarterly basis. | Manual | [IAM_User Access Review](IAM_User_Access_Review) |A.5.18|
| 6.2 | Management conducts a firewall review on at least a quarterly basis. | Automated | [EC2_Security Group Tags](EC2_Security_Group_Tags) |A.8.20|
| 7 | The production environment is monitored for suspicious or anomalous activity. Alerts are sent to the Security team for investigation, when necessary. | Partially Automated | [GuardDuty Enabled](GD_Enabled)<br>[GuardDuty_Alerts](GD_Alerts) |A.8.7|
| 8 | Management conducts an infrastructure vulnerability scan on at least a quarterly basis. | Manual | Coming Soon |A.8.8|
| 9.1 | Cloud resources are configured to encrypt data in-transit. | Automated | [S3_Secure_Transport](S3_Secure_Transport)|A.8.24|
| 9.2 | Cloud resources are encrypted at rest. | Automated | [RDS_Encryption](RDS_Encryption)<br>[S3_Encryption](S3_Encryption) |A.8.9, A.8.24|
| 10 | Cloud resources are tagged based on the requirements set in the asset management policy. | Automated | [EC2 Tags](EC2_Tags)<br>[RDS Tags](RDS_Tags)<br>[S3 Tags](S3_Tags) |A.5.9, A.5.12|
