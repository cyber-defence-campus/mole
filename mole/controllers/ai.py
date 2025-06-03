from __future__ import annotations
from mole.controllers.config import ConfigController
from mole.core.data import Path
from mole.models.ai import AiVulnerabilityReport
from mole.views.ai import AiView
from mole.services.ai import AiService, BackgroundAiService, NewAiService
from typing import Callable, List, Optional, Tuple
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
        callback: Optional[Callable[[int, AiVulnerabilityReport], None]] = None,
    ) -> BackgroundAiService:
        """
        This method starts and returns a new AI service that analyzes the given paths.
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
        # Initialize and start AI service
        ai_service = BackgroundAiService(
            bv=bv,
            paths=paths,
            max_workers=max_workers,
            base_url=base_url,
            api_key=api_key,
            callback=callback,
            initial_progress_text="Mole analyzes paths...",
            can_cancel=True,
        )
        ai_service.start()
        # Return AI service instance
        return ai_service

    # def analyze_path(
    #     self, bv: bn.BinaryView, path: Path
    # ) -> AiVulnerabilityReport:
    #     """
    #     This method analyzes a given path by generating an AI-based vulnerability report.
    #     """
    #     # Get OpenAI settings
    #     base_url_set = self.config_ctr.get_setting("openai_base_url")
    #     base_url = base_url_set.value if base_url_set else ""
    #     api_key_set = self.config_ctr.get_setting("openai_api_key")
    #     api_key = api_key_set.value if api_key_set else ""
    #     model_set = self.config_ctr.get_setting("openai_model")
    #     model = model_set.value if model_set else ""
    #     max_completion_tokens_set = self.config_ctr.get_setting("openai_max_completion_tokens")
    #     max_completion_tokens = max_completion_tokens_set.value if max_completion_tokens_set else 4096
    #     # AI-generated vulnerability report
    #     return self.ai_service.analyze_path(bv, path, base_url, api_key, model, max_completion_tokens)


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
