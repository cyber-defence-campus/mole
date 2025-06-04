from dataclasses import dataclass
from datetime import datetime
from mole.models import IndexedLabeledEnum
from mole.common.help import FunctionHelper
from pydantic import BaseModel
from typing import Any, Callable, Dict, List, Optional
import enum


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


class ILType(str, enum.Enum):
    PSEUDO_C = "Pseudo_C"
    HLIL = "HLIL"
    MLIL = "MLIL"


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
    "get_function_containing_address": ToolFunction(
        name="get_function_containing_address",
        description="Retrieve the decompiled code of the function that contains a specific address.",
        parameters=[
            ToolParameter(
                name="addr",
                type="string",
                description="The address (hexadecimal string, e.g. '0x408f20') located within the target function.",
            ),
            ToolParameter(
                name="il_type",
                type="string",
                description="The desired Intermediate Language (IL) for decompilation.",
                enum=[il.value for il in ILType],
            ),
        ],
        required=["addr", "il_type"],
        handler=FunctionHelper.get_function_containing_address,
    ),
    "get_function_by_name": ToolFunction(
        name="get_function_by_name",
        description="Retrieve the decompiled code of a function specified by its name.",
        parameters=[
            ToolParameter(
                name="name",
                type="string",
                description="The exact name of the function to retrieve.",
            ),
            ToolParameter(
                name="il_type",
                type="string",
                description="The desired Intermediate Language (IL) for decompilation.",
                enum=[il.value for il in ILType],
            ),
        ],
        required=["name", "il_type"],
    ),
    "get_callers_by_address": ToolFunction(
        name="get_callers_by_address",
        description="List all functions that call the function containing a specific address.",
        parameters=[
            ToolParameter(
                name="address",
                type="string",
                description="The address (hexadecimal string, e.g., '0x409fd4') within the function whose callers are needed.",
            )
        ],
        required=["address"],
    ),
    "get_callers_by_name": ToolFunction(
        name="get_callers_by_name",
        description="List all functions that call the function specified by its name.",
        parameters=[
            ToolParameter(
                name="name",
                type="string",
                description="The exact name of the function whose callers are needed.",
            )
        ],
        required=["name"],
    ),
}
