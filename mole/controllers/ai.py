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
