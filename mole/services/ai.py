from __future__ import annotations
from concurrent import futures
from datetime import datetime
from mole.common.helper.instruction import InstructionHelper
from mole.common.log import Logger
from mole.common.worker import WorkerService
from mole.models.ai import (
    AiVulnerabilityReport,
    VulnerabilityClass,
    VulnerabilityReport,
    SeverityLevel,
    tools,
)
from mole.models.config import (
    ConfigModel,
    DoubleSpinboxSetting,
    SpinboxSetting,
    TextSetting,
)
from openai import OpenAI
from openai.types.chat import (
    ChatCompletionMessageParam,
    ParsedChatCompletionMessage,
    ParsedFunctionToolCall,
)
from typing import Any, Callable, cast, Dict, Iterable, List, Tuple, TYPE_CHECKING
import binaryninja as bn
import json
import os
import random
import textwrap

if TYPE_CHECKING:
    from mole.models.path import Path

tag = "Ai"


class AiService(WorkerService):
    """
    This class implements a service for Mole's AI.
    """

    def __init__(
        self, bv: bn.BinaryView, log: Logger, config_model: ConfigModel
    ) -> None:
        """
        This method initializes the AI service.
        """
        super().__init__()
        self.bv = bv
        self.log = log
        self.config_model = config_model
        self._tools = [tool.to_dict() for tool in tools.values()]
        return

    def _create_openai_client(
        self, openai_base_url: str, openai_api_key: str, custom_tag: str
    ) -> OpenAI | None:
        """
        This method creates a new OpenAI client.
        """
        client = None
        if openai_base_url and openai_api_key:
            try:
                client = OpenAI(base_url=openai_base_url, api_key=openai_api_key)
            except Exception as e:
                self.log.error(
                    custom_tag, f"Failed to create OpenAI client: {str(e):s}"
                )
        return client

    def _create_system_prompt(self, max_turns: int) -> str:
        vuln_class_lst = "\n".join(
            f"   - `{vuln_class:s}`" for vuln_class in list(VulnerabilityClass)
        )
        sevr_level_lst = "\n".join(
            f"   - `{sevr_level:s}`" for sevr_level in list(SeverityLevel)
        )
        tool_lst = "\n".join(f"- `{tool:s}`" for tool in tools.keys())
        prompt = textwrap.dedent(
            f"""You are a vulnerability research assistant specializing in static backward slicing of variables in Binary Ninja’s Medium Level Intermediate Language (MLIL) in Static Single Assignment (SSA) form. Your task is to determine whether a given slice corresponds to a real and exploitable vulnerability.
        
Perform the following steps:
- **Understand the Path and Reachability**: Use `get_code_for_functions_containing` or `get_code_for_functions_by_name` to retrieve the relevant function(s). Examine the code surrounding the sliced instructions. For reachability, use `get_callers_by_address` or `get_callers_by_name` to analyze the calling context.
- **Identify User-Controlled Variables**: Determine which variables in the slice are user-controlled. Trace their origin, propagation, and any transformations or sanitization.
- **Validate the Path**: Assess whether the path is logically valid and reachable, and eliminate false positives based on control flow or infeasible data dependencies.
- **Explain Your Findings**: Provide a concise and technically accurate explanation of whether and why the path constitutes a vulnerability.
- **Classify the Vulnerability**: Choose from the following classes:
{vuln_class_lst:s}
- **Rate the Vulnerability**: Choose from the following severity levels:
{sevr_level_lst:s}
- **Craft an Example Input**: Provide a realistic input that could trigger the issue.
                            
Use the following tools to support your analysis:
{tool_lst:s}

Be proactive in exploring upstream paths, analyzing data/control dependencies, and reasoning about practical exploitability. You have {max_turns:d} turns to complete your assessment.
"""
        )
        return prompt

    def _create_user_prompt(self, path: Path) -> str:
        # Filename
        filename = os.path.basename(self.bv.file.filename)
        if filename.endswith(".bndb"):
            filename = filename[:-5]
        # Function names and addresses
        prompt = textwrap.dedent(f"""
        Evaluate the path with source `{path.src_sym_name}` @ `0x{path.src_sym_addr:x}` and sink `{path.snk_sym_name}` @ `0x{path.snk_sym_addr:x}`.
        """)
        # Function arguments
        if path.src_par_var is None:
            prompt += textwrap.dedent(
                f"The interesting sink argument is `{str(path.snk_par_var):s}` (index {path.snk_par_idx:d})."
            )
        else:
            prompt += textwrap.dedent(
                f"The interesting source argument is `{str(path.src_par_var):s}` (index {path.src_par_idx:d}) and the interesting sink argument is `{str(path.snk_par_var):s}` (index {path.snk_par_idx:d})."
            )
        # Instruction statistics
        prompt += textwrap.dedent(f"""
        The path contains a total of {len(path.insts):d} instructions, out of which {len(path.phiis):d} instructions are of type MediumLevelILVarPhi. The path depends on {len(path.bdeps):d} branch conditions.

        --- Backward Slice in MLIL (SSA Form) ---
        """)
        # Backward slice
        basic_block = None
        for i, inst in enumerate(path.insts):
            call_level = path.call_graph.nodes[inst.function]["level"]
            if i < path.src_inst_idx:
                custom_tag = f"[Snk] [{call_level:+d}]"
            else:
                custom_tag = f"[Src] [{call_level:+d}]"
            try:
                inst_basic_block = inst.il_basic_block
                if inst_basic_block != basic_block:
                    basic_block = inst_basic_block
                    fun_name = (
                        basic_block.function.symbol.short_name
                        if basic_block.function is not None
                        else "unknown"
                    )
                    bb_addr = basic_block[0].address
                    prompt += (
                        f"{custom_tag:s} - FUN: '{fun_name:s}', BB: 0x{bb_addr:x}\n"
                    )
            except Exception:
                pass
            prompt += f"{custom_tag:s} {InstructionHelper.get_inst_info(inst):s}\n"
        # Call sequence
        prompt += "\n--- Call Sequence ---\n"
        min_call_level = min(path.calls, key=lambda x: x[1])[1]
        for call_func, call_level in path.calls:
            indent = call_level - min_call_level
            call_addr = call_func.source_function.start
            call_name = call_func.source_function.symbol.short_name
            prompt += f"{'>' * indent:s} 0x{call_addr:x} {call_name:s}\n"
        prompt += "\n"
        return prompt

    def _send_messages(
        self,
        client: OpenAI,
        messages: Iterable[ChatCompletionMessageParam],
        openai_model: str,
        max_completion_tokens: int | None,
        temperature: float | None,
        token_usage: Dict[str, int],
        custom_tag: str = tag,
    ) -> ParsedChatCompletionMessage | None:
        """
        This method sends the given messages to the OpenAI client and returns the completion
        message.
        """
        message = None
        try:
            # Send messages and receive completion message
            completion = client.beta.chat.completions.parse(
                messages=messages,
                model=openai_model,
                tools=self._tools,
                max_completion_tokens=max_completion_tokens,
                temperature=temperature,
                response_format=VulnerabilityReport,
            )
            message = completion.choices[0].message
            if completion.usage:
                token_usage["prompt_tokens"] += completion.usage.prompt_tokens
                token_usage["completion_tokens"] += completion.usage.completion_tokens
                token_usage["total_tokens"] += completion.usage.total_tokens
        except Exception as e:
            self.log.error(custom_tag, f"Failed to send messages: {str(e):s}")
        return message

    def _execute_tool_call(
        self, func_name: str, func_args: str, custom_tag: str = tag
    ) -> Any:
        """
        This method executes a tool call with the given function name and arguments and returns the
        result.
        """
        result = None
        try:
            args = json.loads(func_args)
            args["bv"] = self.bv
            args["log"] = self.log
            args["tag"] = custom_tag
            tool = tools.get(func_name, None)
            if tool is not None and tool.handler is not None:
                result = tool.handler(**args)
        except Exception as e:
            self.log.error(
                custom_tag,
                f"Failed to execute tool call '{func_name:s}' with arguments '{func_args:s}': {str(e):s}",
            )
        return result

    def _execute_tool_calls(
        self, tool_calls: List[ParsedFunctionToolCall], custom_tag: str = tag
    ) -> List[Dict[str, str]]:
        """
        This method executes the given tool calls and returns their results.
        """
        results = []
        for tool_call in tool_calls:
            try:
                if tool_call.type == "function":
                    result = self._execute_tool_call(
                        tool_call.function.name,
                        tool_call.function.arguments,
                        custom_tag,
                    )
                    content = str(result)
                else:
                    content = "Error: Unsupported tool call type"
            except Exception as e:
                content = f"Error: {str(e):s}"
                self.log.error(
                    custom_tag,
                    f"Failed to execute tool call '{tool_call.id:s}': {str(e):s}",
                )
            results.append(
                {"role": "tool", "tool_call_id": tool_call.id, "content": content}
            )
        return results

    def _analyze_path(
        self,
        path_id: int,
        path: Path,
        openai_base_url: str = "",
        openai_api_key: str = "",
        openai_model: str = "",
        max_turns: int = 0,
        max_completion_tokens: int | None = None,
        temperature: float | None = None,
    ) -> AiVulnerabilityReport | None:
        """
        This method analyzes the given path with AI.
        """
        # Custom tag for logging
        custom_tag = f"{tag:s}] [Path:{path_id:d}"
        # Create OpenAI client
        client = self._create_openai_client(openai_base_url, openai_api_key, custom_tag)
        # No OpenAI client available (mock mode)
        if client is None:
            self.log.warn(
                custom_tag, "Running in mock mode since no OpenAI client available"
            )
            vuln_report = AiVulnerabilityReport(
                truePositive=random.choice([True, True, True, False]),
                vulnerabilityClass=random.choice(list(VulnerabilityClass)),
                shortExplanation="Mock mode simulates a potential vulnerability.",
                severityLevel=random.choice(list(SeverityLevel)),
                inputExample=f"0x{random.getrandbits(32):08x}",
                path_id=path_id,
                model="mock-mode",
                turns=random.randint(1, max_turns),
                tool_calls=random.randint(1, max_turns * 2),
                prompt_tokens=random.randint(1, 100000),
                completion_tokens=random.randint(1, 100000),
                total_tokens=random.randint(1, 100000),
                temperature=random.uniform(0.0, 2.0),
                timestamp=datetime.now(),
            )
        # OpenAI client available
        else:
            # Initial messages
            messages = [
                {"role": "system", "content": self._create_system_prompt(max_turns)},
                {"role": "user", "content": self._create_user_prompt(path)},
            ]
            # Conversation turns
            response = None
            cnt_tool_calls = 0
            token_usage = {
                "prompt_tokens": 0,
                "completion_tokens": 0,
                "total_tokens": 0,
            }
            turn = 0
            for turn in range(1, max_turns + 1):
                # User cancellation
                if self.cancelled("analyze"):
                    self.log.warn(custom_tag, f"Cancel conversation in turn {turn:d}")
                    return None
                # Send messages and receive response
                self.log.info(
                    custom_tag, f"Sending messages in conversation turn {turn:d}"
                )
                response = self._send_messages(
                    client,
                    messages,
                    openai_model,
                    max_completion_tokens,
                    temperature,
                    token_usage,
                    custom_tag,
                )
                if not response:
                    self.log.error(
                        custom_tag,
                        f"No response received in conversation turn {turn:d}",
                    )
                    return None
                self.log.info(
                    custom_tag, f"Received response in conversation turn {turn:d}"
                )
                # Add response to conversation messages
                messages.append(
                    {
                        "role": response.role,
                        "content": response.content,
                        "tool_calls": [
                            {
                                "id": tool_call.id,
                                "type": tool_call.type,
                                "function": {
                                    "name": tool_call.function.name,
                                    "arguments": tool_call.function.arguments,
                                },
                            }
                            for tool_call in response.tool_calls
                        ]
                        if response.tool_calls is not None
                        else None,
                    }
                )
                # Terminate conversation if no more tool calls requested
                if not response.tool_calls:
                    self.log.info(
                        custom_tag,
                        f"Received final response in conversation turn {turn:d}",
                    )
                    break
                # User cancellation
                if self.cancelled("analyze"):
                    self.log.warn(custom_tag, f"Cancel conversation in turn {turn:d}")
                    return None
                # Execute tool calls and add results to the conversation messages
                messages.extend(
                    self._execute_tool_calls(response.tool_calls, custom_tag)
                )
                cnt_tool_calls += len(response.tool_calls)
            # Return vulnerability report if final response is available
            if not response or not response.parsed:
                self.log.error(custom_tag, "No vulnerability report received")
                return None
            report: VulnerabilityReport = response.parsed
            vuln_report = AiVulnerabilityReport(
                path_id=path_id,
                model=openai_model,
                turns=turn,
                tool_calls=cnt_tool_calls,
                prompt_tokens=token_usage["prompt_tokens"],
                completion_tokens=token_usage["completion_tokens"],
                total_tokens=token_usage["total_tokens"],
                temperature=temperature if temperature is not None else 1.0,
                timestamp=datetime.now(),
                **report.to_dict(),
            )
        # Return vulnerability report and log a summary
        self.log.info(custom_tag, "Vulnerability Report Summary:")
        self.log.info(
            custom_tag,
            f"- True Positive     : {'Yes' if vuln_report.truePositive else 'No'}",
        )
        self.log.info(
            custom_tag, f"- Severity Level    : {vuln_report.severityLevel.label:s}"
        )
        self.log.info(
            custom_tag,
            f"- Vulnerability Type: {vuln_report.vulnerabilityClass.label:s}",
        )
        return vuln_report

    def _analyze_paths(
        self,
        max_workers: int | None = None,
        openai_base_url: str = "",
        openai_api_key: str = "",
        openai_model: str = "",
        max_turns: int = 0,
        max_completion_tokens: int | None = None,
        temperature: float | None = None,
        paths: List[Tuple[int, Path]] = [],
        path_callback: Callable[[int, AiVulnerabilityReport], None] | None = None,
    ) -> None:
        """
        This method analyzes the given paths with AI.
        """
        self.log.info(tag, "Starting AI analysis")
        with futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
            # Submit tasks
            tasks: Dict[futures.Future, int] = {}
            for path_id, path in paths:
                if self.cancelled("analyze"):
                    break
                task = executor.submit(
                    self._analyze_path,
                    path_id=path_id,
                    path=path,
                    openai_base_url=openai_base_url,
                    openai_api_key=openai_api_key,
                    openai_model=openai_model,
                    max_turns=max_turns,
                    max_completion_tokens=max_completion_tokens,
                    temperature=temperature,
                )
                tasks[task] = path_id
            # Wait for tasks to complete
            for cnt, task in enumerate(futures.as_completed(tasks), start=1):
                self.log.debug(tag, f"Analyzed paths: {cnt:d}/{len(paths):d}")
                path_id = tasks[task]
                # Collect vulnerability reports from task results
                if task.done() and not task.exception():
                    vuln_report = cast(AiVulnerabilityReport | None, task.result())
                    if path_callback is not None and vuln_report is not None:
                        path_callback(path_id, vuln_report)
        self.log.info(tag, "AI analysis completed")
        return

    def analyze_paths(
        self,
        max_workers: int | None = None,
        openai_base_url: str = "",
        openai_api_key: str = "",
        openai_model: str = "",
        max_turns: int = 0,
        max_completion_tokens: int | None = None,
        temperature: float | None = None,
        paths: List[Tuple[int, Path]] = [],
        path_callback: Callable[[int, AiVulnerabilityReport], None] | None = None,
    ) -> None:
        """
        This method analyzes the given paths with AI in a background thread.
        """
        # Ensure no other analyze thread is running
        if self.is_alive("analyze"):
            self.log.warn(tag, "Another thread of the path service is still runnning")
            return
        # Determine settings
        self.log.debug(tag, "Settings")
        if max_workers is None:
            setting = self.config_model.get_setting("max_workers")
            if isinstance(setting, SpinboxSetting):
                max_workers = int(setting.value)
        if max_workers is not None and max_workers <= 0:
            max_workers = None
        self.log.debug(tag, f"- max_workers          : '{max_workers}'")
        setting = self.config_model.get_setting("openai_base_url")
        if isinstance(setting, TextSetting):
            openai_base_url = str(setting.value)
        self.log.debug(tag, f"- openai_base_url      : '{openai_base_url:s}'")
        setting = self.config_model.get_setting("openai_api_key")
        if isinstance(setting, TextSetting):
            openai_api_key = str(setting.value)
        self.log.debug(
            tag,
            f"- openai_api_key       : '{openai_api_key[:3]:s}{'...' if openai_api_key else 'mock-mode':s}'",
        )
        setting = self.config_model.get_setting("openai_model")
        if isinstance(setting, TextSetting):
            openai_model = str(setting.value)
        self.log.debug(tag, f"- openai_model         : '{openai_model:s}'")
        setting = self.config_model.get_setting("max_turns")
        if isinstance(setting, SpinboxSetting):
            max_turns = int(setting.value)
        self.log.debug(tag, f"- max_turns            : '{max_turns:d}'")
        if max_completion_tokens is None:
            setting = self.config_model.get_setting("max_completion_tokens")
            if isinstance(setting, SpinboxSetting):
                max_completion_tokens = int(setting.value)
        if max_completion_tokens is not None and max_completion_tokens <= 0:
            max_completion_tokens = None
        self.log.debug(tag, f"- max_completion_tokens: '{max_completion_tokens}'")
        if temperature is None:
            setting = self.config_model.get_setting("temperature")
            if isinstance(setting, DoubleSpinboxSetting):
                temperature = float(setting.value)
        if temperature is not None and (temperature < 0.0 or temperature > 2.0):
            temperature = None
        self.log.debug(tag, f"- temperature          : '{temperature}'")
        # Start background task
        self.start(
            thread_name="analyze",
            run=self._analyze_paths,
            max_workers=max_workers,
            openai_base_url=openai_base_url,
            openai_api_key=openai_api_key,
            openai_model=openai_model,
            max_turns=max_turns,
            max_completion_tokens=max_completion_tokens,
            temperature=temperature,
            paths=paths,
            path_callback=path_callback,
        )
        return
