from __future__              import annotations
from mole.common.log         import Logger
from mole.controllers.config import ConfigController
from mole.controllers.paths  import PathController
from mole.models.config      import ConfigModel
from mole.services.config    import ConfigService
from mole.views.config       import ConfigView
from mole.views.sidebar      import MoleSidebar, SidebarView


tag = "Mole"
log = Logger(level="debug")

#from binaryninja import connect_vscode_debugger
#connect_vscode_debugger(port=3133)

# Models
config_service = ConfigService(f"{tag:s}.ConfigService", log)
config_model = ConfigModel(config_service.load_configuration())

# Views
config_view = ConfigView(f"{tag:s}.ConfigView", log)
sidebar_view = SidebarView(config_view, f"{tag:s}.SidebarView", log)

# Controllers
path_controller = PathController(sidebar_view, config_model, tag, log)
config_controller = ConfigController(config_model, config_view, config_service)

# Initialize views
config_view.init()
sidebar_view.init()

# Initialize sidebar in Binary Ninja
sidebar = MoleSidebar(sidebar_view, tag, log)
sidebar.init()