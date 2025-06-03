from __future__ import annotations
from mole.controllers.config import ConfigController
from mole.core.data import Path
from mole.models.ai import AiVulnerabilityReport
from mole.views.ai import AiView
from mole.services.ai import AiService, BackgroundAiService, NewAiService
from typing import Callable, List, Tuple
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

    def analyze_paths(
        self,
        bv: bn.BinaryView,
        paths: List[Tuple[int, Path]],
        analyzed_path: Callable[[int, AiVulnerabilityReport], None],
    ) -> BackgroundAiService:
        """
        This method starts a service that analyzes each path using AI.
        """
        # Get settings
        max_workers = None
        max_workers_setting = self.config_ctr.get_setting("max_workers")
        if max_workers_setting:
            max_workers = int(max_workers_setting.value)
            if max_workers <= 0:
                max_workers = None
        base_url = ""
        base_url_setting = self.config_ctr.get_setting("openai_base_url")
        if base_url_setting:
            base_url = str(base_url_setting.value)
        api_key = ""
        api_key_setting = self.config_ctr.get_setting("openai_api_key")
        if api_key_setting:
            api_key = str(api_key_setting.value)
        model = ""
        model_setting = self.config_ctr.get_setting("openai_model")
        if model_setting:
            model = str(model_setting.value)
        max_turns = 10
        max_turns_setting = self.config_ctr.get_setting("max_turns")
        if max_turns_setting:
            max_turns = int(max_turns_setting.value)
        # Initialize and start AI service
        ai_service = BackgroundAiService(
            bv=bv,
            paths=paths,
            analyzed_path=analyzed_path,
            max_workers=max_workers,
            base_url=base_url,
            api_key=api_key,
            model=model,
            max_turns=max_turns,
            initial_progress_text="Mole analyzes paths...",
            can_cancel=True,
        )
        ai_service.start()
        # Return AI service instance
        return ai_service


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
