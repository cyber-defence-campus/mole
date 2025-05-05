from __future__ import annotations
from mole.controllers.config import ConfigController
from mole.controllers.path import PathController
from mole.controllers.ai import AiController
from mole.models.config import ConfigModel
from mole.services.config import ConfigService
from mole.services.ai import AIService
from mole.views.config import ConfigView
from mole.views.path import PathView
from mole.views.ai import AiResultView
from mole.views.sidebar import MoleSidebar


# Services
config_service = ConfigService()
ai_service = AIService(config_service)

# Models
config_model = ConfigModel(config_service.load_config())

# Views
config_view = ConfigView()
path_view = PathView()
ai_result_view = AiResultView()

# Controllers
ai_ctr = AiController(ai_service, ai_result_view)
config_ctr = ConfigController(config_service, config_model, config_view)
path_ctr = PathController(ai_service, config_ctr, ai_ctr, path_view)

# Initialize views
config_view.init(config_ctr)
path_view.init(path_ctr)

# Initialize sidebar in Binary Ninja
sidebar = MoleSidebar(path_view)
sidebar.init()
