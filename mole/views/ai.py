from __future__ import annotations
from mole.models.ai import AiVulnerabilityReport
import PySide6.QtCore as qtc
import PySide6.QtWidgets as qtw


class AiView(qtw.QWidget):
    """
    This class implements a view for Mole's AI tab.
    """

    signal_show_ai_report_tab = qtc.Signal()

    def __init__(self) -> None:
        """
        This method initializes the AI view.
        """
        super().__init__()
        self._path_id_lbl: qtw.QLabel = qtw.QLabel("")
        self._true_positive_lbl: qtw.QLabel = qtw.QLabel("")
        self._severity_lbl: qtw.QLabel = qtw.QLabel("")
        self._vuln_type_lbl: qtw.QLabel = qtw.QLabel("")
        self._explanation_txt: qtw.QPlainTextEdit = qtw.QPlainTextEdit(readOnly=True)
        self._input_example_txt: qtw.QPlainTextEdit = qtw.QPlainTextEdit(readOnly=True)
        self._model_lbl = qtw.QLabel()
        self._turns: qtw.QLabel = qtw.QLabel()
        self._tool_calls_lbl: qtw.QLabel = qtw.QLabel()
        self._token_usage_lbl: qtw.QLabel = qtw.QLabel()
        self._temperature_lbl: qtw.QLabel = qtw.QLabel()
        self._timestamp_lbl: qtw.QLabel = qtw.QLabel()
        self._init_widgets()
        return

    def _init_widgets(self) -> None:
        """
        This method initializes the AI view's widgets.
        """
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
        # Info layout
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
        # Info widget
        info_wid = qtw.QWidget()
        info_wid.setLayout(info_lay)
        # Info box layout
        info_box_lay = qtw.QVBoxLayout()
        info_box_lay.addWidget(info_wid)
        # Info box widget
        info_box_wid = qtw.QGroupBox("Information:")
        info_box_wid.setLayout(info_box_lay)
        # Report layout
        report_lay = qtw.QVBoxLayout()
        report_lay.addWidget(summary_box_wid)
        report_lay.addWidget(explanation_box_wid)
        report_lay.addWidget(input_box_wid)
        report_lay.addWidget(info_box_wid)
        # Report widget
        report_wid = qtw.QWidget()
        report_wid.setLayout(report_lay)
        # Scroll widget
        scroll_wid = qtw.QScrollArea()
        scroll_wid.setWidgetResizable(True)
        scroll_wid.setWidget(report_wid)
        # Tab layout
        tab_lay = qtw.QVBoxLayout()
        tab_lay.addWidget(scroll_wid)
        self.setLayout(tab_lay)
        return

    def show_report(self, report: AiVulnerabilityReport, show_tab: bool = True) -> None:
        """
        This method shows the given AI-generated report in the AI view.
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
        # Switch to AI report tab
        if show_tab:
            self.signal_show_ai_report_tab.emit()
        return
