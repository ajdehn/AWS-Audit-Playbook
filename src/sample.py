from dataclasses import dataclass
from typing import Dict, Any
from datetime import date

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
        sample_key = tuple(sorted(self.sample_id.items()))

        exclusion = audit.sample_exclusion_index.get((test.test_id, sample_key))

        if not exclusion:
            return False

        is_excluded = False
        # Permanent exclusions
        if exclusion["permanent"]:
            is_excluded = True

        # Check if exclusion is current
        exp = exclusion["expiration_date"]
        if exp and date.fromisoformat(exp) >= date.today():
            is_excluded = True

        # Document result
        if is_excluded:
            self.is_excluded = True
            self.comments = "Sample is excluded. See config.json"
            # Add excluded sample to tests.
            test.samples.append(self)
            return True
        else:
            # Exclusion was expired or invalid date format.
            return False