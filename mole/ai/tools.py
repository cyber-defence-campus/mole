from pydantic import validate_call
from typing import Any, Union
from binaryninja import BinaryView, Function
from mole.common.binja import get_pseudo_c, get_hlil_code
from mole.common.help import FunctionHelper


class HexInt(int):
    @classmethod
    def __get_validators__(cls):
        yield cls.validate

    @classmethod
    def validate(cls, v: Union[int, str], field: Any) -> Any:
        """Validate and convert input to a HexInt."""
        if isinstance(v, str) and v.startswith("0x"):
            return cls(int(v, 16))
        elif isinstance(v, int):
            return cls(v)
        else:
            raise ValueError(
                "Invalid value for HexInt, must be int or hex string (e.g., '0x...')"
            )


@validate_call(config=dict(arbitrary_types_allowed=True))
def get_function_containing_address(
    binary_view: BinaryView, address: HexInt, il_type: str
):
    """
    Retrieves the code of the function containing the specified address,
    represented in the given Intermediate Language (IL) type.
    """
    for func in binary_view.get_functions_containing(address):
        code = get_code_content(func, il_type)
        if code:  # Check if code is not empty
            return (
                func.start,
                f"Decompiled {il_type} for the function containing address 0x{address:x}:\n\n{code}",
            )
    return (
        None,
        f"Could not find or decompile the function containing address 0x{address:x}.",
    )


@validate_call(config=dict(arbitrary_types_allowed=True))
def get_function_by_name(binary_view: BinaryView, name: str, il_type: str):
    """
    Retrieves the code of the function with the specified name,
    represented in the given Intermediate Language (IL) type.
    """
    for func in binary_view.get_functions_by_name(name):
        code = get_code_content(func, il_type)
        if code:  # Check if code is not empty
            return (
                func.start,
                f"Decompiled {il_type} for the function '{func.symbol.short_name}':\n\n{code}",
            )
    return (
        None,
        f"Could not find or decompile the function named '{name}'.",
    )


@validate_call(config=dict(arbitrary_types_allowed=True))
def get_callers_by_address(binary_view: BinaryView, address: HexInt):
    """
    Retrieves the list of functions that call the function containing the given address.
    """
    functions = binary_view.get_functions_containing(address)
    if not functions:
        return f"No function found containing address 0x{address:x}."

    func = functions[0]  # Typically only one function contains a given address
    callers = func.callers
    if callers:
        call_sites = "\n- ".join(
            [
                f"`{caller.symbol.short_name}` (at `{hex(caller.start)}`)"
                for caller in callers
            ]
        )
        return f"Callers of function `{func.symbol.short_name}` (containing 0x{address:x}):\n- {call_sites}"
    else:
        return f"No callers found for function `{func.symbol.short_name}` (containing 0x{address:x})."


@validate_call(config=dict(arbitrary_types_allowed=True))
def get_callers_by_name(binary_view: BinaryView, name: str):
    """
    Retrieves the list of functions that call the function with the given name.
    """
    functions = binary_view.get_functions_by_name(name)
    if not functions:
        return f"No function found with the name '{name}'."

    # Handle cases where multiple functions might share a name (e.g., overloads, imports)
    # For simplicity, we'll process the first one found. Consider refining if needed.
    func = functions[0]
    callers = func.callers
    if callers:
        call_sites = "\n- ".join(
            [
                f"`{caller.symbol.short_name}` (at `{hex(caller.start)}`)"
                for caller in callers
            ]
        )
        return f"Callers of function `{func.symbol.short_name}`:\n- {call_sites}"
    else:
        return f"No callers found for function `{func.symbol.short_name}`."


def get_code_content(func: Function, il_type: str) -> str:
    """
    Returns the decompiled code for the given function in the specified IL type.
    Returns an empty string if decompilation fails or the IL type is invalid.
    """
    if il_type == "Pseudo_C":
        return get_pseudo_c(func) or ""
    elif il_type == "HLIL":
        return get_hlil_code(func) or ""
    elif il_type == "MLIL":
        return FunctionHelper.get_mlil_code(func)

    # Consider adding logging or raising an error for invalid il_type
    return ""


def call_function(name, args):
    """Dispatches function calls based on name and arguments."""
    match name:
        case "get_function_containing_address":
            start, result = get_function_containing_address(**args)
            if start is None:
                print("No function found or decompilation failed.")
            return result
        case "get_function_by_name":
            start, result = get_function_by_name(**args)
            if start is None:
                print("No function found or decompilation failed.")
            return result
        case "get_callers_by_address":
            return get_callers_by_address(**args)
        case "get_callers_by_name":
            return get_callers_by_name(**args)
        case _:
            return f"Error: Unknown function name '{name}'."


tools = [
    {
        "type": "function",
        "function": {
            "name": "get_function_containing_address",
            "description": "Retrieve the decompiled code of the function that contains a specific address.",
            "parameters": {
                "type": "object",
                "properties": {
                    "address": {
                        "type": "string",
                        "description": "The address (hexadecimal string, e.g., '0x408f20') located within the target function.",
                    },
                    "il_type": {
                        "type": "string",
                        "description": "The desired Intermediate Language (IL) for decompilation.",
                        "enum": ["Pseudo_C", "HLIL", "MLIL"],
                    },
                },
                "required": ["address", "il_type"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "get_function_by_name",
            "description": "Retrieve the decompiled code of a function specified by its name.",
            "parameters": {
                "type": "object",
                "properties": {
                    "name": {
                        "type": "string",
                        "description": "The exact name of the function to retrieve.",
                    },
                    "il_type": {
                        "type": "string",
                        "description": "The desired Intermediate Language (IL) for decompilation.",
                        "enum": ["Pseudo_C", "HLIL", "MLIL"],
                    },
                },
                "required": [
                    "name",
                    "il_type",
                ],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "get_callers_by_address",
            "description": "List all functions that call the function containing a specific address.",
            "parameters": {
                "type": "object",
                "properties": {
                    "address": {
                        "type": "string",
                        "description": "The address (hexadecimal string, e.g., '0x409fd4') within the function whose callers are needed.",
                    }
                },
                "required": ["address"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "get_callers_by_name",
            "description": "List all functions that call the function specified by its name.",
            "parameters": {
                "type": "object",
                "properties": {
                    "name": {
                        "type": "string",
                        "description": "The exact name of the function whose callers are needed.",
                    }
                },
                "required": ["name"],
            },
        },
    },
]
