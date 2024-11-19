from __future__ import annotations
import importlib
import mole
import sys
import types

# Usage:
# - Run this script in Binary Ninja (File -> Run Script...)
# - To (re-)analyze the loaded binary with an updated version of Mole, run the following command in
#   Binary Ninja's Python console: `reload(mole); mole.Plugin().analyze_binary(bv)`

def reload(module: types.ModuleType) -> None:
    importlib.reload(module)
    modules = sys.modules.copy()
    for module_name in modules:
        if module_name.startswith(module.__name__ + '.'):
            importlib.reload(modules[module_name])
    return

reload(mole)