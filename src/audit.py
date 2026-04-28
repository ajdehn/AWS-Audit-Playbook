from datetime import datetime, timezone
from evidence_client import EvidenceClient
from utils import load_config, create_session, get_aws_account_id
import aws_tests

class Audit:
    """
    Initializes the audit instance with the provided attributes.
    """
    def __init__(self, tmp_folder="tmp",
    config_file_path="config.json"):
        self.evidence_folder = f"{tmp_folder}/audit_evidence"       # Name of the evidence_folder
        self.config = load_config(config_file_path)                 # Control and sample exclusions
        self.evidence_client = EvidenceClient(evidence_folder_path=self.evidence_folder, debug=False)
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