from __future__                 import annotations
from mole.core.controller       import Controller
from mole.common.log            import Logger

from mole.core.model import SidebarModel
from mole.controllers.config import ConfigController
from mole.models.config import ConfigModel
from mole.views.sidebar import MoleSidebar, SidebarView
from mole.views.config import ConfigView
from mole.services.config import ConfigService

# TODO: handle headless mode here
runs_headless = False
if runs_headless:
    import sys
    sys.exit(1)

tag = "Mole"
log = Logger(level="debug")

main_model = SidebarModel(tag, log).init()

config_service = ConfigService(log)
config_model = ConfigModel(config_service.load_configuration())

config_view = ConfigView(tag, log)
sidebar_view = SidebarView(config_view, tag, log)

main_controller = Controller(main_model, sidebar_view, config_model, tag, log)
config_controller = ConfigController(config_model, config_view, config_service, log)

config_view.set_controller(config_controller)
sidebar_view.set_controller(main_controller)

config_view.init()
sidebar_view.init()

# lets initialize the actual binary ninja sidebar
sidebar = MoleSidebar(sidebar_view, tag, log)
sidebar.init()