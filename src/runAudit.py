import aws_tests
from utils import confirm_delete_folder, load_config, create_session, get_aws_account_id
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
        self.in_scope_regions = aws_tests.get_regions(self)        
        self.aws_account_id = get_aws_account_id(self)

if __name__ == "__main__":
    print("\nRunning the AWS Audit Playbook (maintained by AJ Dehn - AuditOps.io)\n")

    evidence_folder = "tmp/audit_evidence"
    # Confirm if you want to use cached evidence.
    confirm_delete_folder(evidence_folder)

    audit = Audit(evidence_folder=evidence_folder)
    tests = aws_tests.run_all_tests(audit)
    generate_pdf_report(audit, tests, "AWS", file_name="tmp/aws_audit_report.pdf")

    # TODO: Support uploads to evidence repository (include PDF and supporting evidence).