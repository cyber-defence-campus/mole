from __future__ import annotations
from mole.models.ai import AiVulnerabilityReport
from typing import Optional, TYPE_CHECKING

import PySide6.QtCore as qtc
import PySide6.QtWidgets as qtw

if TYPE_CHECKING:
    from mole.controllers.ai import AiController


class AiResultView(qtw.QWidget):
    """
    This class implements a view for displaying AI vulnerability analysis results.
    """

    def __init__(self) -> None:
        """
        This method initializes the AI result view.
        """
        super().__init__()
        self.ai_ctr: Optional[AiController] = None
        self._current_path_id: Optional[int] = None
        self._init_ui()
        return

    def init(self, ai_ctr: AiController) -> AiResultView:
        """
        This method sets the controller.
        """
        self.ai_ctr = ai_ctr
        return self

    def _init_ui(self) -> None:
        """
        This method initializes the UI components.
        """
        # Create main layout
        main_layout = qtw.QVBoxLayout()

        # Create form layout for detailed information
        form_layout = qtw.QFormLayout()

        # Create widgets for displaying AI analysis results
        self._path_id_label = qtw.QLabel("N/A")
        self._vulnerability_class_label = qtw.QLabel("N/A")
        self._false_positive_label = qtw.QLabel("N/A")
        self._severity_label = qtw.QLabel("N/A")
        self._score_label = qtw.QLabel("N/A")

        # Add widgets to form layout with descriptive labels
        form_layout.addRow("Path ID:", self._path_id_label)
        form_layout.addRow("Vulnerability Type:", self._vulnerability_class_label)
        form_layout.addRow("False Positive:", self._false_positive_label)
        form_layout.addRow("Severity Level:", self._severity_label)
        form_layout.addRow("Exploitability Score:", self._score_label)

        # Create explanation text area
        self._explanation_text = qtw.QTextEdit()
        self._explanation_text.setReadOnly(True)
        explanation_group = qtw.QGroupBox("Explanation")
        explanation_layout = qtw.QVBoxLayout()
        explanation_layout.addWidget(self._explanation_text)
        explanation_group.setLayout(explanation_layout)

        # Create example input text area
        self._input_example_text = qtw.QTextEdit()
        self._input_example_text.setReadOnly(True)
        input_example_group = qtw.QGroupBox("Input Example")
        input_example_layout = qtw.QVBoxLayout()
        input_example_layout.addWidget(self._input_example_text)
        input_example_group.setLayout(input_example_layout)

        # Add model info section
        model_form = qtw.QFormLayout()
        self._model_label = qtw.QLabel("N/A")
        self._tool_calls_label = qtw.QLabel("N/A")
        self._turns_label = qtw.QLabel("N/A")
        self._token_usage_label = qtw.QLabel("N/A")
        model_form.addRow("Model:", self._model_label)
        model_form.addRow("Tool Calls:", self._tool_calls_label)
        model_form.addRow("Conversation Turns:", self._turns_label)
        model_form.addRow("Token Usage:", self._token_usage_label)
        model_group = qtw.QGroupBox("AI Details")
        model_group.setLayout(model_form)

        # Create "no result" message widget
        self._no_result_widget = qtw.QLabel(
            "No AI analysis result available.\nSelect a path with AI analysis or run analysis on a path."
        )
        self._no_result_widget.setAlignment(qtc.Qt.AlignCenter)
        self._no_result_widget.setStyleSheet("color: gray; font-size: 14px;")

        # Create stacked widget to switch between "no result" and "result" views
        self._stack = qtw.QStackedWidget()

        # Create the result widget and add components to it
        result_widget = qtw.QWidget()
        result_layout = qtw.QVBoxLayout()
        result_layout.addLayout(form_layout)
        result_layout.addWidget(explanation_group, 1)
        result_layout.addWidget(input_example_group, 1)
        result_layout.addWidget(model_group)
        result_widget.setLayout(result_layout)

        # Add both widgets to stack
        self._stack.addWidget(self._no_result_widget)  # Index 0
        self._stack.addWidget(result_widget)  # Index 1

        # Start with "no result" view
        self._stack.setCurrentIndex(0)

        # Add the stack to the main layout
        main_layout.addWidget(self._stack)

        # Set the main layout
        self.setLayout(main_layout)
        return

    def show_result(self, path_id: int, result: AiVulnerabilityReport) -> None:
        """
        This method displays an AI analysis result.
        """
        self._current_path_id = path_id
        self._path_id_label.setText(str(path_id))

        self._vulnerability_class_label.setText(result.vulnerabilityClass)

        # Set false positive status
        self._false_positive_label.setText("Yes" if result.falsePositive else "No")
        self._false_positive_label.setStyleSheet(
            "color: #FF5252;" if result.falsePositive else "color: #8BC34A;"
        )

        # Set severity level with color coding
        self._severity_label.setText(result.severityLevel)
        if result.severityLevel == "Critical":
            self._severity_label.setStyleSheet("color: #FF5252; font-weight: bold;")
        elif result.severityLevel == "High":
            self._severity_label.setStyleSheet("color: #FF9800; font-weight: bold;")
        elif result.severityLevel == "Medium":
            self._severity_label.setStyleSheet("color: #FFC107;")
        else:  # Low
            self._severity_label.setStyleSheet("color: #8BC34A;")

        # Set exploitability score with color coding
        self._score_label.setText(f"{result.exploitabilityScore:.1f}")
        if result.exploitabilityScore >= 8.0:
            self._score_label.setStyleSheet("color: #FF5252; font-weight: bold;")
        elif result.exploitabilityScore >= 5.0:
            self._score_label.setStyleSheet("color: #FF9800;")
        elif result.exploitabilityScore > 0:
            self._score_label.setStyleSheet("color: #FFC107;")
        else:
            self._score_label.setStyleSheet("color: #8BC34A;")

        # Set explanation text
        explanation_text = result.shortExplanation
        if result.falsePositive:
            warning_message = "<p style='color:#FF5252;font-style:italic;font-weight:bold;'>⚠️ WARNING: This is identified as a FALSE POSITIVE. The severity, exploitability score, and other information should not be taken seriously.</p><hr>"
            explanation_text = warning_message + explanation_text
        self._explanation_text.setHtml(explanation_text)

        # Set input example
        self._input_example_text.setText(result.inputExample)

        # Set model information
        self._model_label.setText(result.model)
        self._tool_calls_label.setText(str(result.tool_calls))
        self._turns_label.setText(str(result.turns))

        # Set token usage information
        token_text = f"Prompt: {result.prompt_tokens}, Completion: {result.completion_tokens}, Total: {result.total_tokens}"
        self._token_usage_label.setText(token_text)

        # Switch to the result view
        self._stack.setCurrentIndex(1)
        return

    def clear_result(self) -> None:
        """
        This method clears the current result and shows the "no result" view.
        """
        self._current_path_id = None
        self._stack.setCurrentIndex(0)
        return
