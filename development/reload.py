from __future__ import annotations
import importlib
import mole
import sys
import types

def reload(module: types.ModuleType) -> None:
    importlib.reload(module)
    modules = sys.modules.copy()
    for module_name in modules:
        if module_name.startswith(module.__name__ + '.'):
            importlib.reload(modules[module_name])
    return

reload(mole)