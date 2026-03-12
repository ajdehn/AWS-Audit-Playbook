# Control Library
| Priority | Control Description | Type | Control Documentation |
| ------------- | ------------- | ------------- |------------- |
| 1 | All users with an active password must have MFA enabled. | Automated | [IAM MFA](/controls/IAM_MFA)<br> |
| 2 | IAM access keys are rotated at least every 90 days. | Automated | [IAM Key Age](/controls/IAM_Key_Age) |
| 3 | At least one multi-region CloudTrail is enabled with log-file validation.| Automated | [Cloud Trail Multi Region](/controls/Cloud_Trail_Multi_Region) |
| 4 | Cloud assets are configured to block public access. | Automated | [S3_Public](/controls/S3_Public)<br>[RDS_Public](/controls/RDS_Public) |
| 5 | RDS backups are retained for at least 14 days. | Automated | [RDS_Backup](/controls/RDS_Backup) |
| 6.1 | Management conducts a user access review on at least a quarterly basis. | Manual | [IAM_UAR](/controls/IAM_UAR) |
| 6.2 | EC2 security groups have the proper tags applied, and have been reviewed in the last year. | Automated | [EC2_SG_Tags](/controls/EC2_SG_Tags) |
| 7 | GuardDuty is enabled and configured to send alerts to relevant personnel. | Partially Automated | [GD_Enabled](/controls/GD_Enabled)<br>[GD_Alerts](/controls/GD_Alerts) |
| 8 | Management conducts an infrastructure vulnerability scan on at least a quarterly basis. | Manual |COMING SOON |
| 9 | Cloud resources are encrypted at rest and in-transit. | Automated | [RDS_Encrypt](/controls/RDS_Encrypt)<br>[S3_Encrypt](/controls/S3_Encrypt) |
| 10 | Cloud resources are tagged based on the requirements set in the asset management policy. | Automated | [EC2 Tags](/controls/EC2_Tags)<br>[RDS Tags](/controls/RDS_Tags)<br>[S3 Tags](/controls/S3_Tags) |
