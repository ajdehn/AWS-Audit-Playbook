# Control Library
| Priority | Control Description | Evidence Type | Control Documentation | ISO 27001 Mapping|
| ------------- | ------------- | ------------- | ------------- | ------------- |
| 1 | Multi-factor authentication is configured for all users of critical systems. | Automated | [IAM MFA](/controls/IAM_USER_MFA)<br> |A.5.18, A.8.5|
| 2 | Infrastructure service account credentials are rotated at least once per year. | Automated | [IAM Key Age](/controls/IAM_Key_Age) |A.5.18, A.8.5|
| 3 | Audit logs are enabled to capture activity within the cloud infrastructure.| Automated | [Cloud Trail Multi Region](/controls/Cloud_Trail_Multi_Region) |A.8.15|
| 4 | Cloud resources are configured to block public access. | Automated | [S3_Public](/controls/S3_Public)<br>[RDS_Public](/controls/RDS_Public) |A.8.9|
| 5 | Production database backups are taken daily, and are retained for at least 14 days. | Automated | [RDS_Backup](/controls/RDS_Backup) |A.8.13|
| 6.1 | Management conducts a user access review on at least a quarterly basis. | Manual | [IAM_UAR](/controls/IAM_UAR) |A.5.18|
| 6.2 | Management conducts a firewall review on at least a quarterly basis. | Automated | [EC2_SG_Tags](/controls/EC2_SG_Tags) |A.8.20|
| 7 | The production environment is monitored for suspicious or anomalous activity. Alerts are sent to the Security team for investigation, when necessary. | Partially Automated | [GD_Enabled](/controls/GD_Enabled)<br>[GD_Alerts](/controls/GD_Alerts) |A.8.7|
| 8 | Management conducts an infrastructure vulnerability scan on at least a quarterly basis. | Manual | Coming Soon |A.8.8|
| 9.1 | Cloud resources are configured to encrypt data in-transit. | Automated | [S3_Secure_Transport](/controls/S3_Secure_Transport)|A.8.24|
| 9.2 | Cloud resources are encrypted at rest. | Automated | [RDS_Encrypt](/controls/RDS_Encrypt)<br>[S3_Encrypt](/controls/S3_Encrypt) |A.8.9, A.8.24|
| 10 | Cloud resources are tagged based on the requirements set in the asset management policy. | Automated | [EC2 Tags](/controls/EC2_Tags)<br>[RDS Tags](/controls/RDS_Tags)<br>[S3 Tags](/controls/S3_Tags) |A.5.9, A.5.12|
