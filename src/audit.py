from datetime import datetime, timezone
from evidence_client import EvidenceClient

class Audit:
    def __init__(self, tmp_folder="tmp",
    config_file_path="config.json"):
        self.tmp_folder = tmp_folder
        self.evidence_folder = f"{tmp_folder}/audit_evidence"
        self.evidence_client = EvidenceClient(evidence_folder_path=self.evidence_folder, debug=False)
        self.config = None
        self.session = None
        self.aws_account_id = None
        self.test_results = None        
        self.in_scope_regions = None

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