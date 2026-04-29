from dataclasses import dataclass, field
from typing import List, Optional

# NOTE: Tests default to "is_passing: True" until there is a failing sample or other logic determines the test has failed.
@dataclass
class Test:
    test_id: str
    test_description: str
    test_procedures: List[str]
    test_attributes: List[str]
    # Rating Matrix: 0 - Informational, 1 - Low, 2 - Medium, 3 - High.
    risk_rating: int
    table_headers: Optional[List[str]] = None
    include_sample_number: bool = False
    samples: List["Sample"] = field(default_factory=list)
    is_passing: bool = True
    comments: str = ""
    num_findings: int = 0
    num_exclusions: int = 0
    total_population: int = 0
    risk_rating_str: str = ""

    def __post_init__(self):
        self.risk_rating_str = self.create_risk_str()

    def __str__(self):
        return (
            f"test_id: {self.test_id}\n"
            f"test_description: {self.test_description}\n"
            f"risk_rating: {self.risk_rating}\n"
            f"is_passing: {self.is_passing}\n"
            f"comments: {self.comments}\n"         
        )

    def to_dict(self):
        result = {
            "test_id": self.test_id,
            "test_description": self.test_description,
            "risk_rating": self.risk_rating,
            "is_passing": self.is_passing,
            "comments": self.comments,
            "test_procedures": self.test_procedures,
            "test_attributes": self.test_attributes,
        }
        # Include samples, if present.
        if self.samples:  
            result["samples"] = [s.to_dict() for s in self.samples]

        return result

    def create_risk_str(self):
        if self.risk_rating == 0: return "Informational"
        elif self.risk_rating == 1: return "Low"
        elif self.risk_rating == 2: return "Medium"
        elif self.risk_rating == 3: return "High"
        else:
            raise ValueError(f"Invalid risk rating: {self.risk_rating}. Accepted values are 0 - 3.")

    def evaluate_samples(self):
        self.total_population = len(self.samples)
        self.num_exclusions = 0
        self.num_findings = 0

        for s in self.samples:
            if s.is_excluded:
                self.num_exclusions += 1
            elif not s.is_passing:
                self.num_findings += 1

        self.is_passing = self.num_findings == 0
        return self