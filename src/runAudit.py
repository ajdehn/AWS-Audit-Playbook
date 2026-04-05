import controlTesting
from utils import confirm_delete_folder, save_json, load_config, create_session, get_aws_account_id
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
        self.session = create_session()
        self.in_scope_regions = controlTesting.get_regions(self)        
        self.aws_account_id = get_aws_account_id(self)

if __name__ == "__main__":
    print("\nRunning the AWS Audit Playbook (maintained by AJ Dehn - AuditOps.io)\n")
    controls = []
    audit = Audit()
    confirm_delete_folder(audit.evidence_folder)

    control_definitions = [
        ("IAM Root MFA", controlTesting.test_root_mfa_enabled),
        ("IAM Root Access Key", controlTesting.test_root_no_access_keys),
        ("IAM User MFA", controlTesting.test_iam_users_mfa),
        ("IAM User Key Age", controlTesting.test_iam_access_key_age),
        ("IAM Password", controlTesting.test_iam_password_policy),
        ("S3 Encryption", controlTesting.test_s3_encryption),
        ("S3 Public Access", controlTesting.test_s3_public_access),
        ("S3 Tags", controlTesting.test_s3_tags),
        ("RDS Backup Retention", controlTesting.test_rds_backup_retention),
        ("RDS Encryption", controlTesting.test_rds_encryption),
        ("RDS Public Access", controlTesting.test_rds_public_access),
        ("RDS Automatic Upgrades", controlTesting.test_rds_auto_minor_version_upgrade),
        ("RDS Deletion Protection", controlTesting.test_rds_deletion_protection),
        ("RDS Tags", controlTesting.test_rds_tags),
        ("EBS Volume Encryption", controlTesting.test_ebs_volume_encryption),
        ("EBS Encryption Default", controlTesting.test_ebs_default_encryption),
        ("EBS Tags", controlTesting.test_ebs_tags),
        ("EC2 Tags", controlTesting.test_ec2_tags),
        ("EC2 Security Group Tags", controlTesting.test_ec2_security_group_tags),
        ("Lambda Tags", controlTesting.test_lambda_tags),
        ("CloudTrail Multi-Region", controlTesting.test_cloudtrail_global_logging),
        ("CloudTrail Log File Validation", controlTesting.test_cloudtrail_log_file_validation),
        ("CloudTrail S3 Bucket Protection", controlTesting.test_cloudtrail_s3_bucket_protection),
        ("CloudTrail Logging Recent Stops", controlTesting.test_cloudtrail_logging_recent_stops),
        ("Web Application Firewall Enabled", controlTesting.test_waf_enabled),
    ]

    controls = []
    for control_id, control_fn in control_definitions:
        controls.append(controlTesting.run_control_safely(audit, control_fn, control_id))

    # TODO: Add IAM tests (IAM User Stale Access Keys)    
    # TODO: Add S3 secure transport test
    # TODO: Add S3 object owner check    
    # TODO: Add EC2 Public Ports (22, RDS, all ports, etc)    
    # TODO: Add WAF Tags
    # TODO: Add GuardDuty Enabled for regions with resources.
    # TODO: Add GuardDuty findings resolved within a set time period.
    # TODO: Add GuardDuty findings sent to EventBridge every 15 minutes (default is 6 hours).

    generate_pdf_report(audit, controls, "AWS", file_name="tmp/aws_audit_report.pdf")