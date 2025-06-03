from concurrent import futures
from datetime import datetime
from mole.ai.tools import call_function, tools
from mole.common.help import InstructionHelper
from mole.common.log import log
from mole.common.task import BackgroundTask, ProgressCallback
from mole.core.data import Path
from mole.models.ai import (
    AiVulnerabilityReport,
    SeverityLevel,
    VulnerabilityClass,
    VulnerabilityReport,
)
from mole.services.config import ConfigService
from openai import OpenAI
from openai.lib.streaming.chat._completions import LengthFinishReasonError
from openai.types.chat import ChatCompletionMessageParam
from pprint import pformat
from types import SimpleNamespace
from typing import Callable, Dict, Iterable, List, Optional, Tuple
import binaryninja as bn
import json
import os
import random
import textwrap
import time
import traceback


tag = "Mole.AI"


class BackgroundAiService(BackgroundTask):
    """
    This class implements a background task that analyzes paths using AI.

    TODO: Rename to `AiService`.
    """

    def __init__(
        self,
        bv: bn.BinaryView,
        paths: List[Tuple[int, Path]],
        max_workers: Optional[int] = None,
        base_url: str = "",
        api_key: str = "",
        callback: Optional[Callable[[int, AiVulnerabilityReport], None]] = None,
        initial_progress_text: str = "",
        can_cancel: bool = False,
    ) -> None:
        """
        This method initializes the AI service.
        """
        super().__init__(initial_progress_text, can_cancel)
        self._bv = bv
        self._paths = paths
        self._max_workers = max_workers
        self._base_url = base_url
        self._api_key = api_key
        self._callback = callback
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

    def _analyze_path(
        self, path_id: int, path: Path, canceled: Callable[[], bool]
    ) -> AiVulnerabilityReport:
        """ """
        # Custom tag for logging
        self.tag = f"{tag:s}] [Path:{path_id:d}"
        # Create OpenAI client
        client = self._create_openai_client()
        # Mock mode if no OpenAI client available
        if client is None:
            log.warn(self.tag, "Running in mock mode since no OpenAI client available")
            time.sleep(random.uniform(0.25, 2.0))
            report = AiVulnerabilityReport(
                truePositive=random.choice([True, True, True, False]),
                vulnerabilityClass=random.choice(list(VulnerabilityClass)),
                shortExplanation="Mock mode simulates a potential vulnerability.",
                severityLevel=random.choice(list(SeverityLevel)),
                inputExample=f"0x{random.getrandbits(32):08x}",
                path_id=random.randint(1, 1000),
                model="mock-mode",
                tool_calls=random.randint(1, 5),
                turns=random.randint(1, 5),
                prompt_tokens=random.randint(50, 150),
                completion_tokens=random.randint(50, 150),
                total_tokens=random.randint(100, 300),
                timestamp=datetime.now(),
            )
            return report
        return None

    def run(self) -> None:
        """
        This method analyzes each path in a worker thread.
        """
        log.info(tag, "Starting AI analysis")
        # Settings
        log.debug(tag, "Settings")
        log.debug(tag, f"- max_workers: '{self._max_workers}'")
        log.debug(tag, f"- base_url   : '{self._base_url}'")
        log.debug(tag, f"- api_key    : '{'[API_KEY]' if self._api_key else ''}'")
        # Analyze paths using AI
        with futures.ThreadPoolExecutor(max_workers=self._max_workers) as executor:
            # Submit tasks
            tasks: Dict[futures.Future, int] = {}
            for path_id, path in self._paths:
                if self.cancelled:
                    break
                task = executor.submit(
                    self._analyze_path, path_id, path, lambda: self.cancelled
                )
                tasks[task] = path_id
            # Wait for tasks to complete
            for cnt, task in enumerate(futures.as_completed(tasks)):
                if self.cancelled:
                    break
                self.progress = f"Mole analyzes path {cnt + 1:d}/{len(self._paths):d}"
                path_id = tasks[task]
                # Collect vulnerability reports from task results
                if self._callback and task.done() and not task.exception():
                    vuln_report = task.result()
                    self._callback(path_id, vuln_report)
        log.info(tag, "AI analysis completed")
        return


class NewAiService:
    """
    This class implements a service to analyze paths using AI.
    """

    tools = [
        {
            "type": "function",
            "function": {
                "name": "get_function_containing_address",
                "description": "Retrieve the decompiled code of the function that contains a specific address.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "address": {
                            "type": "string",
                            "description": "The address (hexadecimal string, e.g., '0x408f20') located within the target function.",
                        },
                        "il_type": {
                            "type": "string",
                            "description": "The desired Intermediate Language (IL) for decompilation.",
                            "enum": ["Pseudo_C", "HLIL", "MLIL"],
                        },
                    },
                    "required": ["address", "il_type"],
                },
            },
        },
        {
            "type": "function",
            "function": {
                "name": "get_function_by_name",
                "description": "Retrieve the decompiled code of a function specified by its name.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "name": {
                            "type": "string",
                            "description": "The exact name of the function to retrieve.",
                        },
                        "il_type": {
                            "type": "string",
                            "description": "The desired Intermediate Language (IL) for decompilation.",
                            "enum": ["Pseudo_C", "HLIL", "MLIL"],
                        },
                    },
                    "required": [
                        "name",
                        "il_type",
                    ],
                },
            },
        },
        {
            "type": "function",
            "function": {
                "name": "get_callers_by_address",
                "description": "List all functions that call the function containing a specific address.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "address": {
                            "type": "string",
                            "description": "The address (hexadecimal string, e.g., '0x409fd4') within the function whose callers are needed.",
                        }
                    },
                    "required": ["address"],
                },
            },
        },
        {
            "type": "function",
            "function": {
                "name": "get_callers_by_name",
                "description": "List all functions that call the function specified by its name.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "name": {
                            "type": "string",
                            "description": "The exact name of the function whose callers are needed.",
                        }
                    },
                    "required": ["name"],
                },
            },
        },
    ]

    def __init__(self) -> None:
        self._max_turns = 10
        self._system_prompt = textwrap.dedent(f"""
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
        return

    def _create_openai_client(self, base_url: str, api_key: str) -> Optional[OpenAI]:
        """
        This method creates an OpenAI client using the provided base URL and API key.
        """
        client = None
        if base_url and api_key:
            try:
                client = OpenAI(base_url=base_url, api_key=api_key)
            except Exception as e:
                log.error(tag, f"Failed to initialize OpenAI client: {str(e):s}")
        return client

    def _generate_first_message(self, bv: bn.BinaryView, path: Path) -> str:
        # Filename
        filename = os.path.basename(bv.file.filename)
        if filename.endswith(".bndb"):
            filename = filename[:-5]
        # Function names and addresses
        msg = textwrap.dedent(f"""
        Evaluate the path with source `{path.src_sym_name}` @ `0x{path.src_sym_addr:x}` and sink `{path.snk_sym_name}` @ `0x{path.snk_sym_addr:x}`.
        """)
        # Function arguments
        if path.src_par_var is None:
            msg += textwrap.dedent(
                f"The interesting sink argument is `{str(path.snk_par_var):s}` (index {path.snk_par_idx:d})."
            )
        else:
            msg += textwrap.dedent(
                f"The interesting source argument is `{str(path.src_par_var):s}` (index {path.src_par_idx:d}) and the interesting sink argument is `{str(path.snk_par_var):s}` (index {path.snk_par_idx:d})."
            )
        # Instruction statistics
        msg += textwrap.dedent(f"""
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
                msg += f"{custom_tag:s} - FUN: '{fun_name:s}', BB: 0x{bb_addr:x}\n"
            msg += f"{custom_tag:s} {InstructionHelper.get_inst_info(inst):s}\n"
        # Call sequence
        msg += "\n--- Call Sequence ---\n"
        min_call_level = min(path.calls, key=lambda x: x[2])[2]
        for call_addr, call_name, call_level in path.calls:
            indent = call_level - min_call_level
            msg += f"{'>' * indent:s} 0x{call_addr:x} {call_name:s}\n"
        msg += "\n"
        return msg

    def _send_messages(
        self,
        openai_client: OpenAI,
        messages: Iterable[ChatCompletionMessageParam],
        model: str,
        max_completion_tokens: int,
    ) -> None:
        completion = openai_client.chat.completions.create(
            model=model,
            messages=messages,
            tools=self.tools,
            max_completion_tokens=max_completion_tokens,
            response_format=VulnerabilityReport,
        )
        message = completion.choices[0].message
        print(message)
        return None

    def analyze_path(
        self,
        bv: bn.BinaryView,
        path: Path,
        base_url: str,
        api_key: str,
        model: str,
        max_completion_tokens: int,
    ) -> AiVulnerabilityReport:
        """
        This method analyzes a given path using an OpenAI model and returns a corresponding
        vulnerability report.
        """
        # Create OpenAI client
        openai_client = self._create_openai_client(base_url, api_key)
        # Operate in mock mode if no valid OpenAI client is available
        if openai_client is None:
            log.warn(tag, "Running in mock mode since no OpenAI client available")
            time.sleep(random.uniform(0.25, 2.0))
            report = AiVulnerabilityReport(
                truePositive=random.choice([True, True, True, False]),
                vulnerabilityClass=random.choice(list(VulnerabilityClass)),
                shortExplanation="Mock mode simulates a potential vulnerability.",
                severityLevel=random.choice(list(SeverityLevel)),
                inputExample=f"0x{random.getrandbits(32):08x}",
                path_id=random.randint(1, 1000),
                model="mock-mode",
                tool_calls=random.randint(1, 5),
                turns=random.randint(1, 5),
                prompt_tokens=random.randint(50, 150),
                completion_tokens=random.randint(50, 150),
                total_tokens=random.randint(100, 300),
                timestamp=datetime.now(),
            )
            return report
        # TODO
        messages = [
            {"role": "system", "content": self._system_prompt},
            {"role": "user", "content": self._generate_first_message(bv, path)},
        ]
        print(messages)
        return


class AiService:
    """
    This class implements a service to analyze paths using AI.
    """

    def __init__(self, config_service: ConfigService):
        self._config_service = config_service
        # Maximum number of conversation turns (requests)
        self.max_turns = 10
        self.system_prompt = f"""You are an expert vulnerability research assistant specializing in sink-source analysis using Binary Ninja's MLIL SSA form.
    Your task is to evaluate potential vulnerability paths identified by static backward analysis.
    1. Analyze the Path Context and Reachability: Use tools (`get_function_containing_address`, `get_function_by_name`) to retrieve function code involved in the path. Examine instructions before and after the sliced instructions. Use caller analysis tools (`get_callers_by_address`, `get_callers_by_name`) to investigate reachability.
    2. Identify User-Controlled Variables: Determine which variables are user-controlled, their origins, and any transformations or validations.
    3. Validate the Path: Determine if the path is logically valid, reachable, and not a false positive.
    4. Identify Vulnerability: If valid, identify the potential vulnerability type.
    5. Explain Concisely: Provide a clear explanation of why the vulnerability exists.
    6. Assess Severity: Assign a severity level (Critical, High, Medium, Low).
    7. Craft Example Input: Create a realistic input example that could trigger the vulnerability.

    Use the tools proactively to understand the code path and its upstream callers to provide a well-reasoned analysis, assess true reachability, and craft a plausible triggering input. You have a maximum of {self.max_turns} conversation turns to complete this analysis.
    """

    def _get_openai_client(self) -> OpenAI:
        """
        Create and return an OpenAI client using API settings from configuration.
        """
        config = self._config_service.load_config()

        if (
            "openai_api_key" not in config.settings
            or "opnai_base_url" not in config.settings
        ):
            raise ValueError("AI API key or URL not found in configuration.")

        api_key = config.settings["openai_api_key"].value
        base_url = config.settings["openai_base_url"].value

        # Return client with configured settings
        return OpenAI(api_key=api_key, base_url=base_url)

    def _log_message(self, messages):
        short_messages = []
        for m in messages:
            content = "EMPTY CONTENT"
            content_length = 0
            if m["content"] is not None:
                content = m["content"][:50]
                content_length = len(m["content"])

            msg_info = {
                "role": m["role"],
                "content": f"{content} ({content_length} chars)",
            }
            if "tool_calls" in m and m["tool_calls"]:
                tool_names = [tool["function"]["name"] for tool in m["tool_calls"]]
                msg_info["tool_calls"] = tool_names
            short_messages.append(msg_info)
        log.debug(tag, f"Sending messages to AI: \n{pformat(short_messages)}")

    def _send_messages(
        self, ai_model: str, messages, progress: ProgressCallback, token_usage: dict
    ):
        """
        Send a conversation to the AI using streaming and get the aggregated response.
        Checks for cancellation during the stream. Updates progress.
        """
        client = self._get_openai_client()
        stream = None
        chunk_count = 0
        final_tool_calls = []
        # Store the parsed structured response
        parsed_content = None
        content = None

        try:
            if progress and progress.cancelled():
                log.info(tag, "AI analysis cancelled just before sending request")
                return None

            # self._log_message(messages)
            with client.beta.chat.completions.stream(
                model=ai_model,
                messages=messages,
                tools=tools,
                max_completion_tokens=4096,
                stream_options={
                    "include_usage": True,
                },
                response_format=VulnerabilityReport,
            ) as stream:
                log.debug(tag, f"[{ai_model}] Streaming response from AI...")

                for event in stream:
                    chunk_count += 1
                    if progress and progress.cancelled():
                        log.info(tag, "AI analysis cancelled during streaming response")
                        return None

                    if chunk_count % 5 == 0:
                        log.debug(
                            tag,
                            f"[{ai_model}] Receiving AI response (chunk {chunk_count})...",
                        )
                    elif event.type == "error":
                        log.error(tag, f"[{ai_model}] Error in stream: {event.error}")
                        return None

            log.info(
                tag, f"[{ai_model}] Finished streaming after {chunk_count} chunks."
            )

            # Get the final completion from the stream
            final_completion = stream.get_final_completion()

            # Extract role, content, and tool calls from the final completion
            content = final_completion.choices[0].message.content
            tool_calls = final_completion.choices[0].message.tool_calls

            # Get the parsed structured response if available
            if hasattr(final_completion.choices[0].message, "parsed"):
                parsed_content = final_completion.choices[0].message.parsed

            # Track token usage if available in the completion
            if hasattr(final_completion, "usage") and final_completion.usage:
                usage = final_completion.usage
                token_usage["prompt_tokens"] += usage.prompt_tokens
                token_usage["completion_tokens"] += usage.completion_tokens
                token_usage["total_tokens"] += usage.total_tokens
                log.debug(
                    tag,
                    f"[{ai_model}] Token usage for this request: {usage.prompt_tokens} prompt, "
                    + f"{usage.completion_tokens} completion, {usage.total_tokens} total",
                )

            # Convert tool calls to SimpleNamespace for compatibility with existing code
            final_tool_calls = []
            if tool_calls:
                for tc in tool_calls:
                    final_tool_calls.append(
                        SimpleNamespace(
                            id=tc.id,
                            type=tc.type,
                            function=SimpleNamespace(
                                name=tc.function.name,
                                arguments=tc.function.arguments,
                            ),
                        )
                    )

            # Construct the final message object
            final_message = SimpleNamespace(
                role="assistant",
                content=content,
                tool_calls=final_tool_calls if final_tool_calls else None,
                parsed=parsed_content,
            )
            return final_message

        except LengthFinishReasonError as length_error:
            log.warn(
                tag,
                f"Response exceeded length limits. Will attempt to use partial content. Error: {str(length_error)}",
            )

            # TODO: handle partial content (e.g. `length_error.completion`)
            return None

        except Exception as e:
            # Check for cancellation again in case the exception was due to cancellation interrupting IO
            if progress and progress.cancelled():
                log.info(tag, "AI analysis cancelled during exception handling.")
                return None
            else:
                error_details = traceback.format_exc()
                log.error(
                    tag,
                    f"Error processing AI stream or request: {str(e)}\nCallstack:\n{error_details}",
                )
                if progress:
                    progress.progress(f"Error in AI service: {str(e)}")
                return None

    def _process_tool_calls(
        self, tool_calls, binary_view, progress: ProgressCallback, path_info=""
    ) -> list:
        results = []
        for idx, tool in enumerate(tool_calls):
            progress.progress(
                f"{path_info}Tool call {idx + 1}/{len(tool_calls)}: {tool.function.name}"
            )
            if tool.type != "function":
                log.warn(tag, f"Skipping non-function tool call: {tool.type}")
                results.append(
                    {
                        "role": "tool",
                        "tool_call_id": tool.id,
                        "content": "Error: Tool type not supported.",
                    }
                )
                continue
            try:
                args = json.loads(tool.function.arguments)
                args["binary_view"] = binary_view
                log.info(tag, f"Calling tool {tool.function.name} with args: {args}")
                output_data = call_function(tool.function.name, args)
                content = (
                    str(output_data)
                    if output_data is not None
                    else f"Error: Function '{tool.function.name}' returned no output."
                )
            except Exception as e:
                log.error(tag, f"Error processing tool call {tool.id}: {e}")
                content = f"Error: {e}"
            results.append(
                {"role": "tool", "tool_call_id": tool.id, "content": content}
            )
        return results

    def _generate_first_message(self, binary_view: bn.BinaryView, path: Path) -> str:
        filename = (
            binary_view.file.filename.replace(".bndb", "")
            if binary_view.file.filename
            else "unknown"
        )

        msg = f"""Evaluate path from source `{path.src_sym_name}` @ 0x`{path.src_sym_addr:x}` to sink `{path.snk_sym_name} @ 0x{path.snk_sym_addr:x}`
        Interested source parameter is `{path.src_par_var}` at index {path.src_par_idx}, sink parameter is `{path.snk_par_var}` at index {path.snk_par_idx}.
        Path hits {len(path.insts)} instructions and {len(path.phiis)} PHI nodes.
        The binary being analysed is called `{filename}`.

        --- Backward Slice in MLIL (SSA Form) ---
        """

        slice_trace = ""
        insts = path.insts
        basic_block = None
        reverse = False

        for i, inst in enumerate(insts):
            if inst.function not in path.call_graph.nodes:
                log.warn(tag, f"Function {inst.function} not found in call graph.")
                continue
            call_level = path.call_graph.nodes[inst.function]["call_level"]
            if (not reverse and i < path.src_inst_idx) or (
                reverse and i >= path.src_inst_idx
            ):
                custom_tag = f"[Snk] [{call_level:+d}"
            else:
                custom_tag = f"[Src] [{call_level:+d}"
            if inst.il_basic_block != basic_block:
                basic_block = inst.il_basic_block
                fun_name = basic_block.function.name
                bb_addr = basic_block[0].address
                slice_trace += (
                    f"{custom_tag} - FUN: '{fun_name:s}', BB: 0x{bb_addr:x}\n"
                )
            slice_trace += custom_tag + InstructionHelper.get_inst_info(inst) + "\n"

        msg += f"{slice_trace:s}\n"

        msg += "--- Call Stack ---\n"
        calls = path.calls
        min_call_level = min(calls, key=lambda x: x[2])[2] if calls else 0
        for call_addr, call_name, call_level in calls:
            indent = call_level - min_call_level
            msg += f"{'>' * indent:s} 0x{call_addr:x} {call_name:s}\n"
        msg += "\n"
        return msg

    def _analyse_path(
        self,
        binary_view: bn.BinaryView,
        path: Path,
        progress: ProgressCallback,
        path_info="",
    ) -> AiVulnerabilityReport | None:
        # if MOCK_AI:
        if False:
            log.info(tag, "Mock AI mode enabled. Skipping actual analysis.")
            progress.progress(f"{path_info}Mock AI mode: analysis skipped.")

            # Get the list of vulnerability class literals from the model
            vulnerability_classes = list(
                VulnerabilityReport.model_fields[
                    "vulnerabilityClass"
                ].annotation.__args__
            )

            if progress.cancelled():
                return None

            # fake some time consumption
            import time

            time.sleep(0.25)

            return AiVulnerabilityReport(
                truePositive=random.choice(
                    [True, True, True, False]
                ),  # 25% chance of false positive
                vulnerabilityClass=random.choice(vulnerability_classes),
                shortExplanation="Mock analysis: Found potential issue.",
                severityLevel=random.choice(list(SeverityLevel)),
                inputExample=f"0x{random.getrandbits(32):08x}",
                path_id=random.randint(1, 1000),
                model="mockgpt-4",
                tool_calls=random.randint(1, 5),
                turns=random.randint(1, 5),
                prompt_tokens=random.randint(50, 150),
                completion_tokens=random.randint(50, 150),
                total_tokens=random.randint(100, 300),
                timestamp=datetime.now(),
            )

        messages = [
            {"role": "system", "content": self.system_prompt},
        ]

        first_msg = self._generate_first_message(binary_view, path)
        messages.append({"role": "user", "content": first_msg})

        config = self._config_service.load_config()
        if "ai_model" not in config.settings:
            raise ValueError("Missing AI model in configuration.")

        ai_model = config.settings["ai_model"].value

        turns = 0
        # Keep track across turns
        total_tool_calls_processed = 0
        message = None
        final_content = None
        token_usage = {"prompt_tokens": 0, "completion_tokens": 0, "total_tokens": 0}

        log.info(tag, f"{path_info}Starting AI analysis conversation")

        while turns < self.max_turns:
            if progress.cancelled():
                log.info(
                    tag,
                    f"{path_info}AI analysis cancelled before processing turn {turns + 1}",
                )
                return None

            request_num = turns + 1
            progress.progress(
                f"{path_info}Sending request {request_num}/{self.max_turns} to AI service..."
            )

            message = self._send_messages(ai_model, messages, progress, token_usage)

            if message is None:
                if progress.cancelled():
                    log.info(
                        tag,
                        f"{path_info}AI analysis cancelled during request {request_num}.",
                    )
                else:
                    log.error(
                        tag,
                        f"{path_info}Failed to get response for request {request_num}.",
                    )
                    progress.progress(
                        f"{path_info}Error during AI request {request_num}."
                    )
                return None

            log.debug(
                tag,
                f"{path_info}Received response for turn {turns + 1}: Content: {bool(message.content)}, Tools: {len(message.tool_calls) if message.tool_calls else 0}",
            )

            # Check if the response contains tool calls
            if message.tool_calls is not None and len(message.tool_calls) > 0:
                messages.append(
                    {
                        "role": message.role,
                        "content": message.content,
                        "tool_calls": [
                            {
                                "id": tc.id,
                                "type": tc.type,
                                "function": {
                                    "name": tc.function.name,
                                    "arguments": tc.function.arguments,
                                },
                            }
                            for tc in message.tool_calls
                        ],
                    }
                )
                tool_calls = message.tool_calls
                tool_count = len(tool_calls)
                total_tool_calls_processed += tool_count

                log.info(
                    tag,
                    f"{path_info}Request {request_num}/{self.max_turns}: Received {tool_count} tool calls",
                )
                progress.progress(
                    f"{path_info}Processing {tool_count} tool calls (request {request_num}/{self.max_turns})..."
                )

                tool_results = self._process_tool_calls(
                    tool_calls, binary_view, progress, path_info
                )
                if len(tool_results) != tool_count:
                    log.warn(
                        tag,
                        f"{path_info}Tool call processing failed: expected {tool_count} results, got {len(tool_results)}.",
                    )
                messages.extend(tool_results)
                turns += 1

                # Check if max turns reached after processing tools
                if turns >= self.max_turns:
                    log.warn(
                        tag,
                        f"{path_info}Reached max conversation turns ({self.max_turns}) after processing tools. Finishing analysis.",
                    )
                    # Use content from the message that *requested* the tools
                    final_content = (
                        message.content
                        if message and message.content
                        else "Analysis incomplete: reached maximum conversation turns after tool execution."
                    )
                    progress.progress(
                        f"{path_info}Analysis finished (max turns {self.max_turns} reached, {total_tool_calls_processed} tools processed)."
                    )
                    break
            else:
                # No tool calls in the response, analysis should be complete
                log.info(
                    tag,
                    f"{path_info}AI analysis completed after {request_num} requests and {total_tool_calls_processed} tool calls. No further tool calls requested.",
                )
                final_content = (
                    message.parsed if message and hasattr(message, "parsed") else None
                )

                progress.progress(
                    f"{path_info}Analysis finished ({request_num} requests, {total_tool_calls_processed} tools)."
                )
                log.info(
                    tag, f"{path_info}Final content received: {type(final_content)}"
                )
                # Break the loop to use the final content
                break

        log.info(
            tag,
            f"{path_info}Total token usage for this analysis: {token_usage['prompt_tokens']} prompt, "
            f"{token_usage['completion_tokens']} completion, "
            f"{token_usage['total_tokens']} total tokens",
        )

        # If the loop finished, use the final_content
        if final_content:
            if isinstance(final_content, VulnerabilityReport):
                vuln: VulnerabilityReport = final_content

                if vuln.truePositive:
                    summary = (
                        f"\nAI analysis confirms a potential {vuln.severityLevel.label} {vuln.vulnerabilityClass} vulnerability "
                        f"Explanation: {vuln.shortExplanation}.\n"
                        f"Example input: {vuln.inputExample}.\n"
                    )
                else:
                    summary = (
                        "AI analysis concluded the path is likely a false positive."
                    )
                log.info(tag, summary)
                return AiVulnerabilityReport(
                    path_id=0,  # Placeholder, will be set in the caller
                    model=ai_model,
                    tool_calls=total_tool_calls_processed,
                    turns=turns,
                    prompt_tokens=token_usage["prompt_tokens"],
                    completion_tokens=token_usage["completion_tokens"],
                    total_tokens=token_usage["total_tokens"],
                    timestamp=datetime.now(),
                    **vuln.model_dump(),
                )
            else:
                # Handle non-VulnerabilityReport responses (error cases, strings, dictionaries)
                error_msg = (
                    f"Analysis returned invalid result type: {type(final_content)}"
                )
                if isinstance(final_content, dict) and "error" in final_content:
                    error_msg = final_content["error"]
                elif isinstance(final_content, str):
                    error_msg = final_content

                log.error(tag, f"{path_info}Invalid analysis result: {error_msg}")
                progress.progress(f"{path_info}Analysis failed: {error_msg}")
                return None
        else:
            # Handle cases where loop finished unexpectedly or no content was ever received
            log.warn(
                tag,
                f"AI analysis loop finished after {turns} turns (max: {self.max_turns}) without definitive final content.",
            )
            log.error(tag, f"{path_info}Analysis incomplete: no final content received")
            return None

    def analyse(
        self,
        binary_view: bn.BinaryView,
        paths: list[tuple[int, Path]],
        progress: ProgressCallback[AiVulnerabilityReport],
    ) -> None:
        """Analyze potential vulnerability paths in the binary using a progress/cancellation callback."""
        total_paths = len(paths)

        for idx, (path_id, path) in enumerate(paths):
            # Only add path_info prefix if we have multiple paths
            path_info = "" if total_paths == 1 else f"[Path {idx + 1}/{total_paths}] "

            progress.progress(f"{path_info}Starting analysis of path {path_id}...")

            vuln = self._analyse_path(binary_view, path, progress, path_info)

            if vuln is not None:
                vuln.path_id = path_id
                progress.new_result(vuln)
