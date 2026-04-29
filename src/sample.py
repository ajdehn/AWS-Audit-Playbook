from dataclasses import dataclass
from typing import Dict, Any

from utils import is_exclusion_active

# NOTE: Samples default to "is_passing: False" until logic determines sample passes the testing criteria.
@dataclass
class Sample:
    sample_id: Dict[str, Any]
    is_excluded: bool = False
    is_passing: bool = False
    comments: str = ""

    def __str__(self):
        return (
            f"sample_id: {self.sample_id}\n"
            f"is_excluded: {self.is_excluded}\n"
            f"is_passing: {self.is_passing}\n"
            f"comments: {self.comments}\n"
        )

    def to_dict(self):
        return {
            "sample_id": self.sample_id,
            "is_excluded": self.is_excluded,
            "is_passing": self.is_passing,
            "comments": self.comments,
        }
    
    def check_excluded(self, test, audit):
        # Returns true if when sample is excluded in the config file.
        exclusions = audit.config.get("sample_exclusions", {}).get(test.test_id, [])
        if not isinstance(exclusions, list):
            return False  # Invalid sample exclusion structure

        for e in exclusions:
            if not is_exclusion_active(e):
                continue

            config_sample_id = e.get("sample_id", {})

            if all(self.sample_id.get(k) == v for k, v in config_sample_id.items()):
                    self.is_excluded = True
                    self.comments = "Sample is excluded. See config.json"
                    # Add excluded sample to tests.
                    test.samples.append(self)
                    return True
        return False