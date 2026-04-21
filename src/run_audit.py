import aws_tests
from datetime import datetime, timezone
from utils import confirm_delete_folder, load_config, create_session, get_aws_account_id
from build_report import generate_pdf_report
import json

class Audit:
    """
    Initializes the audit instance with the provided attributes.
    """
    def __init__(self, tmp_folder="tmp",
    config_file_path="config.json"):
        self.evidence_folder = f"{tmp_folder}/audit_evidence"       # Name of the evidence_folder
        self.config = load_config(config_file_path)                 # Control and sample exclusions
        self.evidence_client = aws_tests.EvidenceClient(evidence_folder_path=self.evidence_folder, debug=False)
        self.session = create_session()
        self.in_scope_regions = aws_tests.get_regions(self)        
        self.aws_account_id = get_aws_account_id(self)
        self.test_results = ""

    def to_dict(self):
        return {
            "metadata": {
                "scope": {
                    "aws_account_id": self.aws_account_id,
                    "in_scope_regions": self.in_scope_regions
                },
                "report_date": datetime.now(timezone.utc).strftime('%Y-%m-%d')
            },
            "test_results": [t.to_dict() for t in self.test_results],
            "config": self.config
        }

if __name__ == "__main__":
    print("\nRunning the AWS Audit Playbook (maintained by AJ Dehn - AuditOps.io)\n")

    tmp_folder_name = "tmp"
    # Confirm if you want to delete contents of the tmp folder (Select "N" to used cached evidence).
    confirm_delete_folder(tmp_folder_name)

    audit = Audit(tmp_folder=tmp_folder_name)
    audit.test_results = aws_tests.run_all_tests(audit)

    # Save audit report JSON file.
    with open(f"{tmp_folder_name}/aws_audit_report.json", "w") as f:
        json.dump(audit.to_dict(), f, indent=4)
        print(f"Report generated: {tmp_folder_name}/aws_audit_report.json")

    generate_pdf_report(audit, audit.test_results, "AWS", file_name=f"{tmp_folder_name}/aws_audit_report.pdf")

    # TODO: Support uploads to evidence repository (include PDF and supporting evidence).