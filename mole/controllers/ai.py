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

    def analyze_path(self, bv: bn.BinaryView, path: Path) -> AiVulnerabilityReport:
        """
        This method analyzes a given path using AI and returns a corresponding
        vulnerability report.
        """
        return self.ai_service.analyze_path(bv, path)


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

    # def is_ai_configured(self) -> bool:
    #     """
    #     This method checks whether all required AI settings are configured.

    #     Returns:
    #         bool: True if all required settings are available, False otherwise
    #     """
    #     try:
    #         # Use the config service from ai_service to check for required settings
    #         config = self.ai_service._config_service.load_config()

    #         # Check for all three required settings
    #         for key in ["ai_api_key", "ai_api_url", "ai_model"]:
    #             if (
    #                 key not in config.settings
    #                 or not config.settings[key].value
    #                 or config.settings[key].value.strip() == ""
    #             ):
    #                 return False
    #         return True
    #     except Exception:
    #         # If any error occurs during checking, assume AI is not properly configured
    #         return False
