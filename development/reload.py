import importlib
import mole
import types


def reload(module: types.ModuleType) -> None:
    """
    Recursively reload modules.
    """
    if module.__name__ in ("binaryninja"):
        return
    for attribute_name in dir(module):
        attribute = getattr(module, attribute_name)
        if type(attribute) is types.ModuleType:
            reload(attribute)
    importlib.reload(module)
    return


reload(mole)