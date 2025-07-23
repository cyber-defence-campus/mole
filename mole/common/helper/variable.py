from __future__ import annotations
import binaryninja as bn


class VariableHelper:
    """
    This class provides helper functions with respect to variables.
    """

    @staticmethod
    def get_var_info(var: bn.Variable) -> str:
        """
        This method returns a string with information about the variable `var`.
        """
        return f"{var.name}"

    @staticmethod
    def get_ssavar_info(var: bn.SSAVariable) -> str:
        """
        This method returns a string with information about the SSA variable `var`.
        """
        return f"{var.name}#{var.version}"
