from __future__ import annotations
from mole.controllers.config import ConfigController
from mole.controllers.path import PathController
from mole.controllers.ai import NewAiController
from mole.models.config import ConfigModel
from mole.services.config import ConfigService
from mole.services.ai import NewAiService
from mole.views.config import ConfigView
from mole.views.path import PathView
from mole.views.ai import AiView
from mole.views.sidebar import MoleSidebar


# Services
config_service = ConfigService()
ai_service = NewAiService()

# Models
config_model = ConfigModel(config_service.load_config())

# Views
config_view = ConfigView()
ai_view = AiView()
path_view = PathView()

# Controllers
config_ctr = ConfigController(config_service, config_model, config_view)
ai_ctr = NewAiController(ai_service, ai_view, config_ctr)
path_ctr = PathController(path_view, config_ctr, ai_ctr)

# Initialize sidebar in Binary Ninja
sidebar = MoleSidebar(path_view)
sidebar.init()
