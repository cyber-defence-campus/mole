from __future__              import annotations
from mole.common.log         import Logger
from mole.controllers.config import ConfigController
from mole.controllers.path  import PathController
from mole.models.config      import ConfigModel
from mole.services.config    import ConfigService
from mole.views.config       import ConfigView
from mole.views.path         import PathView
from mole.views.sidebar      import MoleSidebar


tag = "Mole"
log = Logger(level="debug")

# Services
config_service = ConfigService(f"{tag:s}.ConfigService", log)

# Models
config_model = ConfigModel(config_service.load_config())

# Views
config_view = ConfigView(f"{tag:s}.ConfigView", log)
sidebar_view = PathView(f"{tag:s}.SidebarView", log)

# Controllers
config_ctr = ConfigController(config_service, config_model, config_view)
path_ctr = PathController(sidebar_view, config_ctr, tag, log)

# Initialize views
config_view.init(config_ctr)
sidebar_view.init(path_ctr)

# Initialize sidebar in Binary Ninja
sidebar = MoleSidebar(sidebar_view, tag, log)
sidebar.init()