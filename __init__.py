from __future__              import annotations
from mole.controllers.config import ConfigController
from mole.controllers.path   import PathController
from mole.models.config      import ConfigModel
from mole.services.config    import ConfigService
from mole.views.config       import ConfigView
from mole.views.path         import PathView
from mole.views.sidebar      import MoleSidebar


# Services
config_service = ConfigService()

# Models
config_model = ConfigModel(config_service.load_config())

# Views
config_view = ConfigView()
path_view = PathView()

# Controllers
config_ctr = ConfigController(config_service, config_model, config_view)
path_ctr = PathController(config_ctr, path_view)

# Initialize views
config_view.init(config_ctr)
path_view.init(path_ctr)

# Initialize sidebar in Binary Ninja
sidebar = MoleSidebar(path_view)
sidebar.init()