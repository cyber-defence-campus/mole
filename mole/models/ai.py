from typing import Literal
from pydantic import BaseModel
from datetime import datetime


class VulnerabilityReport(BaseModel):
    falsePositive: bool
    vulnerabilityClass: Literal[
        "Out-of-Bounds Write",
        "Command Injection",
        "Out-of-Bounds Read",
        "Use-After-Free",
        "File Inclusion",
        "Resource Leak",
        "Null Pointer Dereference",
        "Buffer Overflow",
        "Integer Overflow",
        "Directory Traversal",
        "SQL Injection",
        "Cross-Site Scripting (XSS)",
        "Cross-Site Request Forgery (CSRF)",
        "Information Disclosure",
        "Other",
    ]
    shortExplanation: str
    severityLevel: Literal["Critical", "High", "Medium", "Low"]
    exploitabilityScore: float
    inputExample: str


class AiVulnerabilityReport(VulnerabilityReport):
    path_id: int
    model: str
    tool_calls: int
    turns: int
    prompt_tokens: int = 0
    completion_tokens: int = 0
    total_tokens: int = 0
    timestamp: datetime = None

    def model_dump(self):
        data = super().model_dump()
        # Convert datetime to ISO format string if it exists
        if data["timestamp"] is not None:
            data["timestamp"] = data["timestamp"].isoformat()
        return data
