from __future__ import annotations
from mole.controllers.config import ConfigController
from mole.controllers.path import PathController
from mole.controllers.ai import AiController
from mole.models.config import ConfigModel
from mole.services.config import ConfigService
from mole.services.ai import AiService
from mole.views.config import ConfigView
from mole.views.path import PathView
from mole.views.ai import AiView
from mole.views.sidebar import MoleSidebar


# Services
config_service = ConfigService()
ai_service = AiService(config_service)

# Models
config_model = ConfigModel(config_service.load_config())

# Views
config_view = ConfigView()
ai_result_view = AiView()
path_view = PathView()

# Controllers
config_ctr = ConfigController(config_service, config_model, config_view)
ai_ctr = AiController(ai_service, ai_result_view)
path_ctr = PathController(ai_service, config_ctr, ai_ctr, path_view)

# Initialize sidebar in Binary Ninja
sidebar = MoleSidebar(path_view)
sidebar.init()
