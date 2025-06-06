from __future__ import annotations
from concurrent import futures
from datetime import datetime
from mole.common.help import InstructionHelper
from mole.common.log import log
from mole.common.task import BackgroundTask
from mole.core.data import Path
from mole.models.ai import (
    AiVulnerabilityReport,
    SeverityLevel,
    tools,
    VulnerabilityClass,
)
from openai import OpenAI
from openai.types.chat import (
    ChatCompletionMessageParam,
    ParsedChatCompletionMessage,
    ParsedFunctionToolCall,
)
from typing import Any, Callable, Dict, Iterable, List, Optional, Tuple
import binaryninja as bn
import json
import os
import random
import textwrap


tag = "Mole.AI"


class AiService(BackgroundTask):
    """
    This class implements a background task that analyzes paths using AI.
    """

    def __init__(
        self,
        bv: bn.BinaryView,
        paths: List[Tuple[int, Path]],
        analyzed_path: Callable[[int, AiVulnerabilityReport], None],
        max_workers: Optional[int],
        base_url: str,
        api_key: str,
        model: str,
        max_turns: int,
        max_completion_tokens: int,
        initial_progress_text: str = "",
        can_cancel: bool = False,
    ) -> None:
        """
        This method initializes the AI service.
        """
        super().__init__(initial_progress_text, can_cancel)
        self._bv = bv
        self._paths = paths
        self._analyzed_path = analyzed_path
        self._max_workers = max_workers
        self._base_url = base_url
        self._api_key = api_key
        self._model = model
        self._max_turns = max_turns
        self._max_completion_tokens = max_completion_tokens
        self._tools = [tool.to_dict() for tool in tools.values()]
        return

    def _create_openai_client(self) -> Optional[OpenAI]:
        """
        This method creates a new OpenAI client.
        """
        client = None
        if self._base_url and self._api_key:
            try:
                client = OpenAI(base_url=self._base_url, api_key=self._api_key)
            except Exception as e:
                log.error(self.tag, f"Failed to create OpenAI client: {str(e):s}")
        return client

    def _create_system_prompt(self) -> str:
        prompt = textwrap.dedent(f"""
        You are an expert vulnerability research assistant specializing in sink-to-source analysis using Binary Ninja's MLIL SSA form. Your task is to evaluate potential vulnerability paths identified by static backward slicing.

        1. Analyze the Path Context and Reachability: Use tools (`get_function_containing_address`, `get_function_by_name`) to retrieve function code involved in the path. Examine instructions before and after the sliced instructions. Use caller analysis tools (`get_callers_by_address`, `get_callers_by_name`) to investigate reachability.
        2. Identify User-Controlled Variables: Determine which variables are user-controlled, their origins, and any transformations or validations.
        3. Validate the Path: Determine if the path is logically valid, reachable, and not a false positive.
        4. Identify Vulnerability: If valid, identify the potential vulnerability type.
        5. Explain Concisely: Provide a clear explanation of why the vulnerability exists.
        6. Assess Severity: Assign a severity level (Critical, High, Medium, Low).
        7. Craft Example Input: Create a realistic input example that could trigger the vulnerability.

        Use the tools proactively to understand the code path and its upstream callers to provide a well-reasoned analysis, assess true reachability, and craft a plausible triggering input. You have a maximum of {self._max_turns} conversation turns to complete this analysis.
        """)
        return prompt

    def _create_user_prompt(self, path: Path) -> str:
        # Filename
        filename = os.path.basename(self._bv.file.filename)
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
            call_level = path.call_graph.nodes[inst.function]["call_level"]
            if i < path.src_inst_idx:
                custom_tag = f"[Snk] [{call_level:+d}]"
            else:
                custom_tag = f"[Src] [{call_level:+d}]"
            if inst.il_basic_block != basic_block:
                basic_block = inst.il_basic_block
                fun_name = basic_block.function.name
                bb_addr = basic_block[0].address
                prompt += f"{custom_tag:s} - FUN: '{fun_name:s}', BB: 0x{bb_addr:x}\n"
            prompt += f"{custom_tag:s} {InstructionHelper.get_inst_info(inst):s}\n"
        # Call sequence
        prompt += "\n--- Call Sequence ---\n"
        min_call_level = min(path.calls, key=lambda x: x[2])[2]
        for call_addr, call_name, call_level in path.calls:
            indent = call_level - min_call_level
            prompt += f"{'>' * indent:s} 0x{call_addr:x} {call_name:s}\n"
        prompt += "\n"
        return prompt

    def _send_messages(
        self, client: OpenAI, messages: Iterable[ChatCompletionMessageParam]
    ) -> Optional[ParsedChatCompletionMessage]:
        """
        This method sends the given messages to the OpenAI client and returns the completion
        message.
        """
        message = None
        try:
            # Send messages and receive completion message
            completion = None
            with client.beta.chat.completions.stream(
                messages=messages,
                model=self._model,
                tools=self._tools,
                max_completion_tokens=self._max_completion_tokens,
                response_format=AiVulnerabilityReport,
                stream_options={"include_usage": True},
            ) as stream:
                for chunk_cnt, _ in enumerate(stream):
                    if self.cancelled:
                        log.warn(
                            self.tag,
                            f"Cancel message streaming after {chunk_cnt:d} chunks",
                        )
                        return None
                    chunk_cnt += 1
                log.debug(
                    self.tag, f"Streaming messages finished after {chunk_cnt:d} chunks"
                )
                completion = stream.get_final_completion()
            message = completion.choices[0].message
        except Exception as e:
            log.error(self.tag, f"Failed to send messages: {str(e):s}")
        return message

    def _execute_tool_call(self, func_name: str, func_args: str) -> Any:
        """
        This method executes a tool call with the given function name and arguments and returns the
        result.
        """
        result = None
        try:
            args = json.loads(func_args)
            args["bv"] = self._bv
            args["tag"] = self.tag
            result = tools[func_name].handler(**args)
        except Exception as e:
            log.error(
                self.tag,
                f"Failed to execute tool call '{func_name:s}' with arguments '{func_args:s}': {str(e):s}",
            )
        return result

    def _execute_tool_calls(
        self, tool_calls: List[ParsedFunctionToolCall]
    ) -> List[Dict[str, str]]:
        """
        This method executes the given tool calls and returns their results.
        """
        results = []
        for tool_call in tool_calls:
            try:
                if tool_call.type == "function":
                    result = self._execute_tool_call(
                        tool_call.function.name, tool_call.function.arguments
                    )
                    content = str(result)
                else:
                    content = "Error: Unsupported tool call type"
            except Exception as e:
                content = f"Error: {str(e):s}"
                log.error(
                    self.tag,
                    f"Failed to execute tool call '{tool_call.id:s}': {str(e):s}",
                )
            results.append(
                {"role": "tool", "tool_call_id": tool_call.id, "content": content}
            )
        return results

    def _analyze_path(
        self, path_id: int, path: Path
    ) -> Optional[AiVulnerabilityReport]:
        """
        This method analyzes a path using AI and returns a vulnerability report.
        """
        # Custom tag for logging
        self.tag = f"{tag:s}] [Path:{path_id:d}"
        # Create OpenAI client
        client = self._create_openai_client()
        # Mock mode if no OpenAI client available
        if client is None:
            log.warn(self.tag, "Running in mock mode since no OpenAI client available")
            report = AiVulnerabilityReport(
                truePositive=random.choice([True, True, True, False]),
                vulnerabilityClass=random.choice(list(VulnerabilityClass)),
                shortExplanation="Mock mode simulates a potential vulnerability.",
                severityLevel=random.choice(list(SeverityLevel)),
                inputExample=f"0x{random.getrandbits(32):08x}",
                path_id=random.randint(1, 1000),
                model="mock-mode",
                tool_calls=random.randint(1, 5),
                turns=random.randint(1, self._max_turns),
                prompt_tokens=random.randint(1, self._max_completion_tokens),
                completion_tokens=random.randint(1, self._max_completion_tokens),
                total_tokens=random.randint(1, self._max_completion_tokens),
                timestamp=datetime.now(),
            )
            return report
        # Initial messages
        messages = [
            {"role": "system", "content": self._create_system_prompt()},
            {"role": "user", "content": self._create_user_prompt(path)},
        ]
        # Conversation turns
        response = None
        for turn in range(1, self._max_turns + 1):
            # User cancellation
            if self.cancelled:
                log.warn(self.tag, f"Cancel conversation in turn {turn:d}")
                return None
            # Send messages and receive response
            log.info(self.tag, f"Sending messages in conversation turn {turn:d}")
            response = self._send_messages(client, messages)
            if not response:
                log.error(
                    self.tag, f"No response received in conversation turn {turn:d}"
                )
                return None
            log.info(self.tag, f"Received response in conversation turn {turn:d}")
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
                log.info(
                    self.tag, f"Received final response in conversation turn {turn:d}"
                )
                break
            # Execute tool calls and add results to the conversation messages
            messages.extend(self._execute_tool_calls(response.tool_calls))
        # Return vulnerability report if final response is available
        if not response:
            log.error(self.tag, "No vulnerability report received")
            return None
        vuln_report: AiVulnerabilityReport = response.parsed
        vuln_report_summary = textwrap.dedent(f"""Summary Vulnerability Report Path {path_id:d}:
        - True Positive      : {"Yes" if vuln_report.truePositive else "No"}
        - Severity Level     : {vuln_report.severityLevel.name:s}
        - Vulnerability Class: {vuln_report.vulnerabilityClass.name:s}
        """)
        log.info(self.tag, vuln_report_summary)
        return vuln_report

    def run(self) -> None:
        """
        This method analyzes each path in a worker thread.
        """
        log.info(tag, "Starting AI analysis")
        # Settings
        log.debug(tag, "Settings")
        log.debug(tag, f"- max_workers          : '{self._max_workers}'")
        log.debug(tag, f"- base_url             : '{self._base_url}'")
        log.debug(
            tag, f"- api_key              : '{'[API_KEY]' if self._api_key else ''}'"
        )
        log.debug(tag, f"- model                : '{self._model:s}'")
        log.debug(tag, f"- max_turns            : '{self._max_turns:d}'")
        log.debug(tag, f"- max_completion_tokens: '{self._max_completion_tokens:d}'")
        # Analyze paths using AI
        with futures.ThreadPoolExecutor(max_workers=self._max_workers) as executor:
            # Submit tasks
            tasks: Dict[futures.Future, int] = {}
            for path_id, path in self._paths:
                if self.cancelled:
                    break
                task = executor.submit(self._analyze_path, path_id, path)
                tasks[task] = path_id
            # Wait for tasks to complete
            for cnt, task in enumerate(futures.as_completed(tasks)):
                if self.cancelled:
                    break
                self.progress = f"Mole analyzes path {cnt + 1:d}/{len(self._paths):d}"
                path_id = tasks[task]
                # Collect vulnerability reports from task results
                if task.done() and not task.exception():
                    vuln_report = task.result()
                    if vuln_report:
                        self._analyzed_path(path_id, vuln_report)
        log.info(tag, "AI analysis completed")
        return
