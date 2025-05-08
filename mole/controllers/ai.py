from __future__ import annotations
from mole.models.ai import AiVulnerabilityReport
from mole.views.ai import AiResultView
from mole.services.ai import AIService

tag = "Mole.AI"


class AiController:
    """
    This class implements a controller to handle AI-related operations.
    """

    def __init__(self, ai_service: AIService, ai_view: AiResultView) -> None:
        """
        This method initializes a controller (MVC pattern).
        """
        self.ai_service = ai_service
        self.ai_view = ai_view
        self.ai_view.init(self)
        return

    def show_result(self, path_id: int, result: AiVulnerabilityReport) -> None:
        """
        This method shows an AI analysis result in the view.
        """
        self.ai_view.show_result(path_id, result)
        return

    def clear_result(self) -> None:
        """
        This method clears the current result from the view.
        """
        self.ai_view.clear_result()
        return

    def is_ai_configured(self) -> bool:
        """
        This method checks whether all required AI settings are configured.

        Returns:
            bool: True if all required settings are available, False otherwise
        """
        try:
            # Use the config service from ai_service to check for required settings
            config = self.ai_service._config_service.load_config()

            # Check for all three required settings
            for key in ["ai_api_key", "ai_api_url", "ai_model"]:
                if (
                    key not in config.settings
                    or not config.settings[key].value
                    or config.settings[key].value.strip() == ""
                ):
                    return False
            return True
        except Exception:
            # If any error occurs during checking, assume AI is not properly configured
            return False
