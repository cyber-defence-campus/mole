from datetime import datetime
from mole.models import IndexedLabeledEnum
from pydantic import BaseModel


class SeverityLevel(IndexedLabeledEnum):
    LOW = (1, "Low")
    MEDIUM = (2, "Medium")
    HIGH = (3, "High")
    CRITICAL = (4, "Critical")


class VulnerabilityClass(IndexedLabeledEnum):
    OUT_OF_BOUNDS_READ = (1, "Out-of-Bounds Read")
    OUT_OF_BOUNDS_WRITE = (2, "Out-of-Bounds Write")
    BUFFER_OVERFLOW = (3, "Buffer Overflow")
    INTEGER_OVERFLOW = (4, "Integer Overflow")
    NULL_POINTER_DEREFERENCE = (5, "Null Pointer Dereference")
    USE_AFTER_FREE = (6, "Use-After-Free")
    COMMAND_INJECTION = (7, "Command Injection")
    SQL_INJECTION = (8, "SQL Injection")
    CROSS_SITE_SCRIPTING = (9, "Cross-Site Scripting (XSS)")
    CROSS_SITE_REQUEST_FORGERY = (10, "Cross-Site Request Forgery (CSRF)")
    DIRECTORY_TRAVERSAL = (11, "Directory Traversal")
    FILE_INCLUSION = (12, "File Inclusion")
    RESOURCE_LEAK = (13, "Resource Leak")
    INFORMATION_DISCLOSURE = (14, "Information Disclosure")
    OTHER = (15, "Other")


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
