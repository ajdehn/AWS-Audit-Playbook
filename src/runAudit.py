from dotenv import load_dotenv
import controlTesting
from utils import confirm_delete_folder, save_json, load_config
from buildReport import generate_pdf_report
from evidenceClient import EvidenceClient

class Audit:
    """
    Initializes the audit instance with the provided attributes.
    """
    def __init__(self, evidence_folder="tmp/audit_evidence",
    config_file_path="config.json"):
        self.evidence_folder = evidence_folder                      # Name of the evidence_folder
        self.config = load_config(config_file_path)                 # Control and sample exclusions
        self.evidence_client = EvidenceClient(base_path=evidence_folder, debug=False)
        self.in_scope_regions = controlTesting.get_regions(self)
        self.aws_account_id = controlTesting.get_aws_account_id()

if __name__ == "__main__":
    # Load variables from .env file
    load_dotenv()
    audit = Audit()

    print("\nRunning the AWS Audit Playbook (maintained by AJ Dehn - AuditOps.io)\n")
    controls = []

    confirm_delete_folder(audit.evidence_folder)

    controls.append(controlTesting.test_root_mfa_enabled(audit, "IAM Root MFA"))
    controls.append(controlTesting.test_root_no_access_keys(audit, "IAM Root Access Key"))
    controls.append(controlTesting.test_iam_users_mfa(audit, "IAM User MFA"))
    controls.append(controlTesting.test_iam_access_key_age(audit, "IAM User Key Age"))
    controls.append(controlTesting.test_iam_password_policy(audit, "IAM Password"))
    # TODO: Add IAM tests (IAM User Stale Access Keys)

    controls.append(controlTesting.test_s3_encryption(audit, "S3 Encryption"))
    controls.append(controlTesting.test_s3_public_access(audit, "S3 Public Access"))
    controls.append(controlTesting.test_s3_tags(audit, "S3 Tags"))
    # TODO: Add S3 secure transport test
    # TODO: Add S3 object owner check

    controls.append(controlTesting.test_rds_backup_retention(audit, "RDS Backup Retention"))
    controls.append(controlTesting.test_rds_encryption(audit, "RDS Encryption"))
    controls.append(controlTesting.test_rds_public_access(audit, "RDS Public Access"))
    controls.append(controlTesting.test_rds_tags(audit, "RDS Tags"))
    # TODO: Add RDS_Auto_Upgrade
    # TODO: Add RDS_Deletion_Protection

    controls.append(controlTesting.test_ebs_volume_encryption(audit, "EBS Volume Encryption"))
    controls.append(controlTesting.test_ebs_tags(audit, "EBS Tags"))
    controls.append(controlTesting.test_ebs_default_encryption(audit, "EBS Encryption Default"))
    # TODO: Add EC2_Tags
    # TODO: Add EC2_SG_Tags
    # TODO: Add EC2 Public Ports (22, RDS, all ports, etc)

    # TODO: Add Lambda Tags

    controls.append(controlTesting.test_cloudtrail_global_logging(audit, "CloudTrail Multi-Region"))
    controls.append(controlTesting.test_cloudtrail_log_file_validation(audit, "CloudTrail Log File Validation"))
    controls.append(controlTesting.test_cloudtrail_s3_bucket_protection(audit, "CloudTrail S3 Bucket Protection"))
    controls.append(controlTesting.test_cloudtrail_logging_recent_stops(audit, "CloudTrail Logging Recent Stops"))

    # TODO: Add AWS Client Cache
    # TODO: Add GuardDuty Enabled for regions with resources.
    # TODO: Add GuardDuty findings resolved within a set time period.
    # TODO: Add GuardDuty findings sent to EventBridge every 15 minutes (default is 6 hours).
    # TODO: Add WAF enabled on relevant resources (Application Load Balancers, API Gateway, etc)
    # TODO: Add WAF Tags

    generate_pdf_report(audit, controls, "AWS", file_name="tmp/aws_audit_report.pdf")