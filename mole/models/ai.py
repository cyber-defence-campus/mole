from __future__ import annotations
from dataclasses import dataclass
from datetime import datetime
from mole.models import IndexedLabeledEnum
from mole.core.ai import (
    get_callers_by_address,
    get_callers_by_name,
    get_code_for_functions_containing,
    get_code_for_functions_by_name,
)
from pydantic import BaseModel
from typing import Any, Callable, Dict, List, Optional


class SeverityLevel(IndexedLabeledEnum):
    LOW = (1, "Low")  # 0: Low* (false positive)
    MEDIUM = (3, "Medium")  # 2: Medium* (false positive)
    HIGH = (5, "High")  # 4: High* (false positive)
    CRITICAL = (7, "Critical")  # 6: Critical* (false positive)


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
    turns: int
    tool_calls: int
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


@dataclass
class ToolParameter:
    name: str
    type: str
    description: str
    enum: Optional[List[str]] = None


@dataclass
class ToolFunction:
    name: str
    description: str
    parameters: List[ToolParameter]
    required: List[str]
    handler: Optional[Callable[..., Any]] = None

    def to_dict(self) -> Dict:
        properties = {}
        for parameter in self.parameters:
            parameter_dict = {
                "type": parameter.type,
                "description": parameter.description,
            }
            if parameter.enum:
                parameter_dict["enum"] = parameter.enum
            properties[parameter.name] = parameter_dict
        return {
            "type": "function",
            "function": {
                "name": self.name,
                "description": self.description,
                "parameters": {
                    "type": "object",
                    "properties": properties,
                    "required": self.required,
                },
            },
        }


tools: Dict[str, ToolFunction] = {
    "get_code_for_functions_containing": ToolFunction(
        name="get_code_for_functions_containing",
        description="Retrieve code of functions containing the given address, in a desired Binary Ninja Intermediate Language (BNIL) representation.",
        parameters=[
            ToolParameter(
                name="addr",
                type="string",
                description="The address (e.g. '0x409fd4') to query",
            ),
            ToolParameter(
                name="il_type",
                type="string",
                description="The desired BNIL representation",
                enum=["PSEUDO_C", "HLIL", "MLIL", "LLIL"],
            ),
        ],
        required=["addr", "il_type"],
        handler=get_code_for_functions_containing,
    ),
    "get_code_for_functions_by_name": ToolFunction(
        name="get_code_for_functions_by_name",
        description="Retrieve code of functions with the given name, in a desired Binary Ninja Intermediate Language (BNIL) representation.",
        parameters=[
            ToolParameter(
                name="name",
                type="string",
                description="The name of the functions to retrieve",
            ),
            ToolParameter(
                name="il_type",
                type="string",
                description="The desired BNIL representation",
                enum=["PSEUDO_C", "HLIL", "MLIL", "LLIL"],
            ),
        ],
        required=["name", "il_type"],
        handler=get_code_for_functions_by_name,
    ),
    "get_callers_by_address": ToolFunction(
        name="get_callers_by_address",
        description="Retrieve all functions that call the function containing the specified address.",
        parameters=[
            ToolParameter(
                name="addr",
                type="string",
                description="The address (e.g. '0x409fd4') within the function whose callers are needed",
            )
        ],
        required=["addr"],
        handler=get_callers_by_address,
    ),
    "get_callers_by_name": ToolFunction(
        name="get_callers_by_name",
        description="Retrieve all functions that call the function with the given name.",
        parameters=[
            ToolParameter(
                name="name",
                type="string",
                description="The name of the function whose callers are needed",
            )
        ],
        required=["name"],
        handler=get_callers_by_name,
    ),
}
