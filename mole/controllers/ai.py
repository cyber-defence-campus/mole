from __future__ import annotations
from mole.common.log import Logger
from mole.models.ai import AiVulnerabilityReport
from mole.views.ai import AiView
from mole.services.ai import AiService
from typing import Callable, List, Tuple, TYPE_CHECKING
import binaryninja as bn

if TYPE_CHECKING:
    from mole.data.path import Path


tag = "Ai"


class AiController:
    """
    This class implements a controller for Mole's AI.
    """

    def __init__(
        self,
        bv: bn.BinaryView,
        log: Logger,
        ai_service: AiService,
        ai_view: AiView,
    ) -> None:
        """
        This method initializes the AI controller.
        """
        self.bv = bv
        self.log = log
        self.ai_service = ai_service
        self.ai_view = ai_view
        return

    def analyze_paths(
        self,
        paths: List[Tuple[int, Path]],
        path_callback: Callable[[int, AiVulnerabilityReport], None] | None = None,
    ) -> None:
        """
        This method analyzes the given paths with AI and adds the results to the model/view
        accordingly.
        """
        # Detect newly attached debuggers
        self.log.detect_attached_debugger()
        # Analyze paths in background thread
        self.ai_service.analyze_paths(
            paths=paths,
            path_callback=path_callback,
        )
        return

    def show_report(self, path: Path | None) -> None:
        """
        This method shows the given path's AI-generated report in the AI view.
        """
        # Detect newly attached debuggers
        self.log.detect_attached_debugger()
        # Show report in AI view
        if path is not None and path.ai_report is not None:
            bn.execute_on_main_thread(
                lambda report=path.ai_report: self.ai_view.show_report(report)
            )
        return
