from .mole.common.log import Logger
from .mole.plugin     import Plugin

# Initialize plugin and logger to operate in Binary Ninja
plugin = Plugin(
    runs_headless=False,
    log=Logger(level="debug", runs_headless=False)
)

# Register plugin in Binary Ninja
plugin.register()