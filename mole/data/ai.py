from __future__ import annotations
from dataclasses import dataclass
from mole.core.ai import (
    get_callers_by_address,
    get_callers_by_name,
    get_code_for_functions_containing,
    get_code_for_functions_by_name,
)
from typing import Any, Callable, Dict, List


@dataclass
class ToolParameter:
    name: str
    type: str
    description: str
    enum: List[str] | None = None


@dataclass
class ToolFunction:
    name: str
    description: str
    parameters: List[ToolParameter]
    required: List[str]
    handler: Callable[..., Any] | None = None

    def to_dict(self) -> Dict:
        properties = {}
        for parameter in self.parameters:
            parameter_dict: Dict[str, str | List[str]] = {
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
                    "additionalProperties": False,
                },
                "strict": True,
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
                description="The address (hexadecimal string, e.g. '0x409fd4') to query",
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
                description="The address (hexadecimal string, e.g. '0x409fd4') within the function whose callers are needed",
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
