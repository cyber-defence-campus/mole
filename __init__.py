from .mole.common.log import Logger
from .mole.plugin     import Plugin

# Initialize and register plugin in Binary Ninja
Plugin().register()