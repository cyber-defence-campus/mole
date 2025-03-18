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

# Services
config_service = ConfigService(f"{tag:s}.ConfigService", log)

# Models
config_model = ConfigModel(config_service.load_config())

# Views
config_view = ConfigView(f"{tag:s}.ConfigView", log)
sidebar_view = SidebarView(config_view, f"{tag:s}.SidebarView", log)

# Controllers
config_controller = ConfigController(config_model, config_view, config_service)
path_controller = PathController(sidebar_view, config_model, config_controller, tag, log)

# Initialize views
config_view.init()
sidebar_view.init()

# Initialize sidebar in Binary Ninja
sidebar = MoleSidebar(sidebar_view, tag, log)
sidebar.init()