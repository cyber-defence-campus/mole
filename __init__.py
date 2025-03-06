from __future__                 import annotations
from mole.core.controller       import Controller
from mole.common.log            import Logger

from mole.core.model import SidebarModel
from mole.controllers.config import ConfigController
from mole.models.config import ConfigModel
from mole.views.sidebar import SidebarView
from mole.views.config import ConfigView

# TODO: handle headless mode here
runs_headless = False
if runs_headless:
    import sys
    sys.exit(1)

tag = "Mole"
log = Logger(level="debug")

main_model = SidebarModel(tag, log).init()
config_model = ConfigModel()

config_view = ConfigView(tag, log)
main_view = SidebarView(config_view, tag, log)

main_controller = Controller(main_view, main_model, tag, log, runs_headless)
config_controller = ConfigController(config_model, config_view, log)

config_view.set_controller(config_controller)
main_view.set_controller(main_controller)

config_view.init()
main_view.init()