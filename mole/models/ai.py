from enum import Enum
from pydantic import BaseModel
from datetime import datetime


class SeverityLevel(Enum):
    CRITICAL = 4
    HIGH = 3
    MEDIUM = 2
    LOW = 1

    def __str__(self) -> str:
        return self.name.capitalize()


class VulnerabilityClass(Enum):
    OUT_OF_BOUNDS_WRITE = "Out-of-Bounds Write"
    COMMAND_INJECTION = "Command Injection"
    OUT_OF_BOUNDS_READ = "Out-of-Bounds Read"
    USE_AFTER_FREE = "Use-After-Free"
    FILE_INCLUSION = "File Inclusion"
    RESOURCE_LEAK = "Resource Leak"
    NULL_POINTER_DEREFERENCE = "Null Pointer Dereference"
    BUFFER_OVERFLOW = "Buffer Overflow"
    INTEGER_OVERFLOW = "Integer Overflow"
    DIRECTORY_TRAVERSAL = "Directory Traversal"
    SQL_INJECTION = "SQL Injection"
    CROSS_SITE_SCRIPTING = "Cross-Site Scripting (XSS)"
    CROSS_SITE_REQUEST_FORGERY = "Cross-Site Request Forgery (CSRF)"
    INFORMATION_DISCLOSURE = "Information Disclosure"
    OTHER = "Other"


class VulnerabilityReport(BaseModel):
    truePositive: bool
    vulnerabilityClass: VulnerabilityClass
    shortExplanation: str
    severityLevel: SeverityLevel
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
