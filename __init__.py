from __future__              import annotations
from mole.common.log         import Logger
from mole.controllers.config import ConfigController
from mole.controllers.paths  import PathsController
from mole.models.config      import ConfigModel
from mole.services.config    import ConfigService
from mole.views.config       import ConfigView
from mole.views.sidebar      import MoleSidebar, SidebarView


tag = "Mole"
log = Logger(level="debug")

config_service = ConfigService(tag + ".Config", log)
config_model = ConfigModel(config_service.load_configuration())

config_view = ConfigView(tag, log)
sidebar_view = SidebarView(config_view, tag, log)

main_controller = PathsController(sidebar_view, config_model, tag, log)
config_controller = ConfigController(config_model, config_view, config_service, log)

config_view.set_controller(config_controller)
sidebar_view.set_controller(main_controller)

config_view.init()
sidebar_view.init()

# lets initialize the actual binary ninja sidebar
sidebar = MoleSidebar(sidebar_view, tag, log)
sidebar.init()