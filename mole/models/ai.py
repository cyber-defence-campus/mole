from __future__ import annotations
from datetime import datetime
from mole.models import IndexedLabeledEnum
from pydantic import BaseModel
from typing import Any, Dict


class SeverityLevel(IndexedLabeledEnum):
    LOW = (1, "Low")  # 0: Low* (false positive)
    MEDIUM = (3, "Medium")  # 2: Medium* (false positive)
    HIGH = (5, "High")  # 4: High* (false positive)
    CRITICAL = (7, "Critical")  # 6: Critical* (false positive)


class VulnerabilityClass(IndexedLabeledEnum):
    OUT_OF_BOUNDS_READ_WRITE = (
        1,
        "Out-of-Bounds Read / Write (CWE-119, CWE-125, CWE-787)",
    )
    BUFFER_OVERFLOW = (2, "Buffer Overflow (CWE-120, CWE-121, CWE-122)")
    INTEGER_OVERFLOW_UNDERFLOW = (3, "Integer Overflow / Underflow (CWE-190, CWE-191)")
    USE_AFTER_FREE = (4, "Use-After-Free / Dangling Pointer (CWE-416)")
    DOUBLE_FREE = (5, "Double Free / Invalid Free (CWE-415)")
    NULL_POINTER_DEREFERENCE = (6, "Null Pointer Dereference (CWE-476)")
    UNINITIALIZED_MEMORY_ACCESS = (7, "Uninitialized Memory Access (CWE-457)")
    MEMORY_RESOURCE_LEAK = (8, "Memory / Resource Leak (CWE-401)")
    COMMAND_CODE_INJECTION = (
        9,
        "Command Injection / Arbitrary Code Execution (CWE-77, CWE-94)",
    )
    RACE_CONDITION = (10, "Race Condition (CWE-362)")
    IMPROPER_ACCESS_CONTROL = (
        11,
        "Improper Access Control / Privilege Escalation (CWE-284)",
    )
    IMPROPER_INPUT_VALIDATION = (12, "Improper Input Validation (CWE-20)")
    INSECURE_PATH_FILE_ACCESS = (
        13,
        "Path Traversal / Insecure File Access (CWE-22, CWE-73)",
    )
    INFORMATION_DISCLOSURE = (14, "Information Disclosure / Insecure Storage (CWE-200)")
    OTHER = (15, "Other / Unknown")


class VulnerabilityReport(BaseModel):
    truePositive: bool
    vulnerabilityClass: VulnerabilityClass
    shortExplanation: str
    severityLevel: SeverityLevel
    inputExample: str

    def to_dict(self) -> Dict[str, Any]:
        return {
            "truePositive": self.truePositive,
            "vulnerabilityClass": self.vulnerabilityClass.index,
            "shortExplanation": self.shortExplanation,
            "severityLevel": self.severityLevel.index,
            "inputExample": self.inputExample,
        }


class AiVulnerabilityReport(VulnerabilityReport):
    path_id: int
    model: str
    turns: int
    tool_calls: int
    prompt_tokens: int
    completion_tokens: int
    total_tokens: int
    temperature: float
    timestamp: datetime

    def to_dict(self) -> Dict[str, Any]:
        d = super().to_dict()
        d.update(
            {
                "path_id": self.path_id,
                "model": self.model,
                "turns": self.turns,
                "tool_calls": self.tool_calls,
                "prompt_tokens": self.prompt_tokens,
                "completion_tokens": self.completion_tokens,
                "total_tokens": self.total_tokens,
                "temperature": self.temperature,
                "timestamp": self.timestamp.isoformat(),
            }
        )
        return d
