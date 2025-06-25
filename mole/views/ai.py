from __future__ import annotations
from mole.models.ai import AiVulnerabilityReport
from typing import Optional, TYPE_CHECKING
import PySide6.QtWidgets as qtw


if TYPE_CHECKING:
    from mole.controllers.ai import AiController


class AiView(qtw.QWidget):
    """
    This class implements a view to display AI-generated vulnerability reports.
    """

    def __init__(self) -> None:
        """
        This method initializes the AI view.
        """
        super().__init__()
        self.ai_ctr: Optional[AiController] = None
        self._path_id_lbl: qtw.QLabel = qtw.QLabel("")
        self._vuln_type_lbl: qtw.QLabel = qtw.QLabel("")
        self._true_positive_lbl: qtw.QLabel = qtw.QLabel("")
        self._severity_lbl: qtw.QLabel = qtw.QLabel("")
        self._score_lbl: qtw.QLabel = qtw.QLabel("")
        self._explanation_txt: qtw.QPlainTextEdit = qtw.QPlainTextEdit(readOnly=True)
        self._input_example_txt: qtw.QPlainTextEdit = qtw.QPlainTextEdit(readOnly=True)
        self._model_lbl: qtw.QLabel = qtw.QLabel("")
        self._tool_calls_lbl: qtw.QLabel = qtw.QLabel("")
        self._turns: qtw.QLabel = qtw.QLabel("")
        self._token_usage_lbl: qtw.QLabel = qtw.QLabel("")
        self._temperature_lbl: qtw.QLabel = qtw.QLabel("")
        self._timestamp_lbl: qtw.QLabel = qtw.QLabel("")
        return

    def init(self, ai_ctr: AiController) -> AiView:
        """
        This method sets the controller and initializes relevant UI components.
        """
        # Set controller
        self.ai_ctr = ai_ctr
        # Summary layout
        summary_lay = qtw.QGridLayout()
        summary_lay.addWidget(qtw.QLabel("Path ID:"), 0, 0)
        summary_lay.addWidget(self._path_id_lbl, 0, 1)
        summary_lay.addWidget(qtw.QLabel("True Positive:"), 1, 0)
        summary_lay.addWidget(self._true_positive_lbl, 1, 1)
        summary_lay.addWidget(qtw.QLabel("Severity Level:"), 2, 0)
        summary_lay.addWidget(self._severity_lbl, 2, 1)
        summary_lay.addWidget(qtw.QLabel("Vulnerability Type:"), 3, 0)
        summary_lay.addWidget(self._vuln_type_lbl, 3, 1)
        # Summary widget
        summary_wid = qtw.QWidget()
        summary_wid.setLayout(summary_lay)
        # Summary box layout
        summary_box_lay = qtw.QVBoxLayout()
        summary_box_lay.addWidget(summary_wid)
        # Summary box widget
        summary_box_wid = qtw.QGroupBox("Summary:")
        summary_box_wid.setLayout(summary_box_lay)
        # Explanation box layout
        explanation_box_lay = qtw.QVBoxLayout()
        explanation_box_lay.addWidget(self._explanation_txt)
        # Explanation box widget
        explanation_box_wid = qtw.QGroupBox("Explanation:")
        explanation_box_wid.setLayout(explanation_box_lay)
        # Input box layout
        input_box_lay = qtw.QVBoxLayout()
        input_box_lay.addWidget(self._input_example_txt)
        # Input box widget
        input_box_wid = qtw.QGroupBox("Input Example:")
        input_box_wid.setLayout(input_box_lay)
        # Information layout
        info_lay = qtw.QGridLayout()
        info_lay.addWidget(qtw.QLabel("Model:"), 0, 0)
        info_lay.addWidget(self._model_lbl, 0, 1)
        info_lay.addWidget(qtw.QLabel("Conversation Turns:"), 1, 0)
        info_lay.addWidget(self._turns, 1, 1)
        info_lay.addWidget(qtw.QLabel("Tool Calls:"), 2, 0)
        info_lay.addWidget(self._tool_calls_lbl, 2, 1)
        info_lay.addWidget(qtw.QLabel("Token Usage:"), 3, 0)
        info_lay.addWidget(self._token_usage_lbl, 3, 1)
        info_lay.addWidget(qtw.QLabel("Temperature:"), 4, 0)
        info_lay.addWidget(self._temperature_lbl, 4, 1)
        info_lay.addWidget(qtw.QLabel("Timestamp:"), 5, 0)
        info_lay.addWidget(self._timestamp_lbl, 5, 1)
        # Information widget
        info_wid = qtw.QWidget()
        info_wid.setLayout(info_lay)
        # Information box layout
        info_box_lay = qtw.QVBoxLayout()
        info_box_lay.addWidget(info_wid)
        # Information box widget
        info_box_wid = qtw.QGroupBox("Information:")
        info_box_wid.setLayout(info_box_lay)
        # Report layout
        report_lay = qtw.QVBoxLayout()
        report_lay.addWidget(summary_box_wid)
        report_lay.addWidget(explanation_box_wid)
        report_lay.addWidget(input_box_wid)
        report_lay.addWidget(info_box_wid)
        # Widget to display an AI-generated vulnerability report
        report_wid = qtw.QWidget()
        report_wid.setLayout(report_lay)
        # Widget to display when a result is available
        scr_wid = qtw.QScrollArea()
        scr_wid.setWidgetResizable(True)
        scr_wid.setWidget(report_wid)
        # Main layout
        main_lay = qtw.QVBoxLayout()
        main_lay.addWidget(scr_wid)
        self.setLayout(main_lay)
        return self

    def show_report(self, report: AiVulnerabilityReport) -> None:
        """
        This method shows AI-generated `report` in the AI view.
        """
        warning_txt = "--- WARNING ---\n"
        warning_txt += "This report has been identified as a FALSE POSITIVE. Its severity and related details might be inaccurate.\n"
        warning_txt += "--------------\n\n"
        # Summary
        self._path_id_lbl.setText(str(report.path_id))
        self._true_positive_lbl.setText("Yes" if report.truePositive else "No")
        self._true_positive_lbl.setStyleSheet(
            "color: red;" if report.truePositive else "color: green;"
        )
        self._severity_lbl.setText(report.severityLevel.label)
        match report.severityLevel.label:
            case "Critical":
                self._severity_lbl.setStyleSheet("color: red;")
            case "High":
                self._severity_lbl.setStyleSheet("color: orange;")
            case "Medium":
                self._severity_lbl.setStyleSheet("color: yellow;")
            case _:
                self._severity_lbl.setStyleSheet("color: green;")
        self._vuln_type_lbl.setText(report.vulnerabilityClass.label)
        # Explanation
        msg_txt = report.shortExplanation
        if not report.truePositive:
            msg_txt = warning_txt + msg_txt
        self._explanation_txt.setPlainText(msg_txt)
        # Input example
        msg_txt = report.inputExample
        if not report.truePositive:
            msg_txt = warning_txt + msg_txt
        self._input_example_txt.setPlainText(msg_txt)
        # Information
        self._model_lbl.setText(report.model)
        self._tool_calls_lbl.setText(f"{report.tool_calls:d}")
        self._turns.setText(f"{report.turns:d}")
        token_usage_txt = f"Prompt: {report.prompt_tokens:d}, "
        token_usage_txt += f"Completion: {report.completion_tokens:d}, "
        token_usage_txt += f"Total: {report.total_tokens:d}"
        self._token_usage_lbl.setText(token_usage_txt)
        if report.timestamp:
            timestamp_txt = report.timestamp.strftime("%Y-%m-%d %H:%M:%S")
        else:
            timestamp_txt = "N/A"
        self._temperature_lbl.setText(f"{report.temperature:.1f}")
        self._timestamp_lbl.setText(timestamp_txt)
        return
