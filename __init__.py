from __future__       import annotations
from .mole.common.log import Logger
from .mole.plugin     import Plugin

# Initialize plugin and register it with Binary Ninja
Plugin(log=Logger(level="debug")).register()