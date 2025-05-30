from __future__ import annotations
from mole.controllers.config import ConfigController
from mole.core.data import Path
from mole.models.ai import AiVulnerabilityReport
from mole.views.ai import AiView
from mole.services.ai import AiService, NewAiService
import binaryninja as bn


tag = "Mole.AI"


class NewAiController:
    """
    This class implements a controller to analyze paths using AI.
    """

    def __init__(
        self,
        ai_service: NewAiService,
        ai_view: AiView,
        config_ctr: ConfigController,
    ) -> None:
        """
        This method initializes the AI controller.
        """
        # Initialization
        self.ai_service = ai_service
        self.ai_view = ai_view.init(self)
        self.config_ctr = config_ctr
        return

    def analyze_path(
        self, bv: bn.BinaryView, path_id: int, path: Path
    ) -> AiVulnerabilityReport:
        """
        This method analyzes a given path by generating an AI-based vulnerability report.
        """
        # Get OpenAI settings
        base_url_set = self.config_ctr.get_setting("openai_base_url")
        base_url = base_url_set.value if base_url_set else ""
        api_key_set = self.config_ctr.get_setting("openai_api_key")
        api_key = api_key_set.value if api_key_set else ""
        model_set = self.config_ctr.get_setting("openai_model")
        model = model_set.value if model_set else ""
        # AI-generated vulnerability report
        return self.ai_service.analyze_path(bv, path_id, path, base_url, api_key, model)


class AiController:
    """
    This class implements a controller to analyze paths using AI.
    """

    def __init__(
        self, ai_service: AiService, ai_view: AiView, config_ctr: ConfigController
    ) -> None:
        """
        This method initializes the AI controller.
        """
        # Initialization
        self.ai_service = ai_service
        self.ai_view = ai_view
        self.ai_view.init(self)
        return

    def show_report(self, path_id: int, result: AiVulnerabilityReport) -> None:
        """
        TODO: This method shows an AI analysis result in the view.
        """
        self.ai_view.show_report(path_id, result)
        return

    def clear_result(self) -> None:
        """
        TODO: This method clears the current result from the view.
        """
        self.ai_view.clear_report()
        return
