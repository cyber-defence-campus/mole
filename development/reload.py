import importlib
import mole
import types


def reload(module: types.ModuleType) -> None:
    """
    Recursively reload modules.
    """
    print(type(module))
    for attribute_name in dir(module):
        attribute = getattr(module, attribute_name)
        if type(attribute) is types.ModuleType:
            reload(attribute)
    importlib.reload(module)
    return


reload(mole)