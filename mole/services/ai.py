import json
import traceback
from types import SimpleNamespace
import random

from binaryninja import BinaryView
from openai import OpenAI
from pprint import pformat

from mole.ai.tools import call_function, tools
from mole.models.ai import AiVulnerabilityReport, VulnerabilityReport

from mole.common.help import InstructionHelper
from mole.common.log import log
from mole.common.task import ProgressCallback

from mole.core.data import Path
from mole.services.config import ConfigService

MOCK_AI = False

tag = "Mole.AI"


class AIService:
    """Service for handling AI-based vulnerability analysis."""

    def __init__(self, config_service: ConfigService):
        self._config_service = config_service
        # self._cancel_event = threading.Event() # BackgroundTask handles cancellation signal
        self.system_prompt = """You are an expert vulnerability research assistant specializing in sink-source analysis using Binary Ninja's MLIL SSA form.
    Your task is to evaluate potential vulnerability paths identified by static backward analysis. For a given path:

    1.  **Analyze the Path Context and Reachability:** The provided trace shows instructions directly involved in the data flow from source to sink. However, understanding the *full context* and *reachability* is crucial.
        *   **Local Context:** **Actively use the available tools (`get_function_containing_address`, `get_function_by_name`) to retrieve the code (e.g., Pseudo_C) of the functions involved in the path.** Examine the instructions *before and after* the sliced instructions within their basic blocks and functions. Look for conditional checks, loops, data transformations, or other logic that affects whether the path is truly reachable and exploitable *within* those functions.
        *   **Global Reachability:** **Use the caller analysis tools (`get_callers_by_address`, `get_callers_by_name`) to investigate how the source function (or functions higher in the call stack provided) are invoked.** Determine if the path originates from a location reachable by external input or an untrusted source. Analyze the conditions or checks imposed by these callers that might prevent the path from being triggered. Understanding this call chain context is essential to determine if the vulnerability is practically exploitable.
    2.  **Identify User-Controlled Variables:** Determine precisely which variables and conditions in the path are user-controlled.
        *   Trace each variable back to its origin to determine if and how it can be influenced by external inputs
        *   Specify the exact form of user control (e.g., direct command-line argument, HTTP request parameter, file content, network packet data)
        *   Identify any transformations or validations that occur between the user input and its use in the vulnerable path
        *   Note any size limitations, character restrictions, or other constraints on the user input
    3.  **Validate the Path:** Based on your contextual analysis (both local and global), determine if the path from source to sink is logically valid, reachable from an appropriate entry point, and not a false positive. Consider constraints or sanitization routines that might exist nearby or in callers.
    4.  **Identify Vulnerability:** If the path is valid and reachable, identify the potential vulnerability type (e.g., Out-of-Bounds Write, Command Injection, Use-After-Free).
    5.  **Explain Concisely:** Provide a clear and short explanation of why the vulnerability exists, referencing specific code patterns (or lack thereof) identified during your analysis of the slice, surrounding code, and caller context. Explain *how* the path can be triggered, considering caller conditions.
    6.  **Assess Severity:** Assign a severity level (Critical, High, Medium, Low) based on the potential impact.
    7.  **Score Exploitability:** Provide an exploitability score (0-10), justifying it based on the complexity of triggering the path (considering caller constraints) and controlling the vulnerable operation. Your contextual analysis using the tools is key here.
    8.  **Craft Example Input:** **Crucially, use your understanding of the surrounding code logic (conditions, checks, data formats obtained via tools) *and* the conditions imposed by callers to create a realistic input example that could trigger the vulnerability.** If the input is binary data, provide it in hexdump format. If it's text (like JSON or command arguments), format it appropriately. The example must aim to satisfy the conditions needed to reach the sink via the identified path, considering the full function and call chain context.

    **Your Goal:** Go beyond the slice itself. Use the tools proactively to understand the neighbourhood of the code path *and* its upstream callers function code to provide a well-reasoned analysis, assess true reachability, and craft a *plausible* triggering input based on that broader context.
"""

    def _get_openai_client(self) -> OpenAI:
        """
        Create and return an OpenAI client using API settings from configuration.
        """
        config = self._config_service.load_config()

        if "ai_api_key" not in config.settings or "ai_api_url" not in config.settings:
            raise ValueError("AI API key or URL not found in configuration.")

        api_key = config.settings["ai_api_key"].value
        base_url = config.settings["ai_api_url"].value

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

    def _send_messages(self, ai_model: str, messages, progress: ProgressCallback):
        """
        Send a conversation to the AI using streaming and get the aggregated response.
        Checks for cancellation during the stream. Updates progress.
        """
        client = self._get_openai_client()
        stream = None
        chunk_count = 0
        final_tool_calls = []
        role = "assistant"  # Default role
        parsed_content = None  # Store the parsed structured response

        try:
            # --- Start of cancellable section ---
            if progress and progress.cancelled():
                log.info(tag, "AI analysis cancelled just before sending request")
                return None

            # self._log_message(messages)
            with client.beta.chat.completions.stream(
                model=ai_model,
                messages=messages,
                tools=tools,
                max_completion_tokens=4096,
                response_format=VulnerabilityReport,
            ) as stream:
                log.debug(tag, f"[{ai_model}] Streaming response from AI...")

                for event in stream:
                    chunk_count += 1
                    if progress and progress.cancelled():
                        log.info(tag, "AI analysis cancelled during streaming response")
                        return None

                    if progress and chunk_count % 5 == 0:
                        progress.progress(
                            f"Receiving AI response (chunk {chunk_count})..."
                        )

                    # Handle different event types
                    if event.type == "content.delta":
                        if event.parsed is not None:
                            # Store structured parsed response
                            parsed_content = event.parsed

                    elif event.type == "tool_calls.delta":
                        # Tool calls are tracked by the stream object
                        pass

                    elif event.type == "error":
                        log.error(tag, f"Error in stream: {event.error}")
                        if progress:
                            progress.progress(f"Error in AI service: {event.error}")
                        return None

            # --- End of cancellable section (streaming loop) ---
            log.debug(
                tag, f"[{ai_model}] Finished streaming after {chunk_count} chunks."
            )

            # Check if cancelled *just* after the stream finished
            if progress and progress.cancelled():
                log.info(tag, "AI analysis cancelled immediately after stream finished")
                return None

            # Get the final completion from the stream
            final_completion = stream.get_final_completion()

            # Extract role, content, and tool calls from the final completion
            role = "assistant"
            content = final_completion.choices[0].message.content
            tool_calls = final_completion.choices[0].message.tool_calls

            # Get the parsed structured response if available
            if hasattr(final_completion.choices[0].message, "parsed"):
                parsed_content = final_completion.choices[0].message.parsed

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
                role=role,
                content=content,
                tool_calls=final_tool_calls if final_tool_calls else None,
                parsed=parsed_content,
            )
            return final_message

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

    def _check_cancelled(self, progress: ProgressCallback):
        if progress.cancelled():
            log.info(tag, "AI analysis cancelled.")
            raise RuntimeError("cancelled")

    def _process_tool_calls(
        self, tool_calls, binary_view, progress: ProgressCallback
    ) -> list:
        results = []
        for idx, tool in enumerate(tool_calls):
            # unify cancellation check
            self._check_cancelled(progress)
            progress.progress(
                f"Processing tool call {idx + 1}/{len(tool_calls)}: {tool.function.name}"
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
                # check again after long call
                self._check_cancelled(progress)
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

    def _generate_first_message(self, binary_view: BinaryView, path: Path) -> str:
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
        self, binary_view: BinaryView, path: Path, progress: ProgressCallback
    ) -> AiVulnerabilityReport | None:
        if MOCK_AI:
            log.info(tag, "Mock AI mode enabled. Skipping actual analysis.")
            progress.progress("Mock AI mode: analysis skipped.")

            # Get the list of vulnerability class literals from the model
            vulnerability_classes = list(
                VulnerabilityReport.model_fields[
                    "vulnerabilityClass"
                ].annotation.__args__
            )
            severity_levels = list(
                VulnerabilityReport.model_fields["severityLevel"].annotation.__args__
            )

            if progress.cancelled():
                return None

            # fake some time consumption
            import time

            time.sleep(0.25)

            return AiVulnerabilityReport(
                falsePositive=random.choice(
                    [True, False, False, False]
                ),  # 25% chance of false positive
                vulnerabilityClass=random.choice(vulnerability_classes),
                shortExplanation="Mock analysis: Found potential issue.",
                severityLevel=random.choice(severity_levels),
                exploitabilityScore=round(random.uniform(4.0, 9.8), 1),
                inputExample=f"0x{random.getrandbits(32):08x}",
                path_id=random.randint(1, 1000),
                model="mockgpt-4",
                tool_calls=random.randint(1, 5),
                turns=random.randint(1, 5),
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
        max_turns = 5  # Maximum number of conversation turns (requests)
        total_tool_calls_processed = 0  # Keep track across turns
        message = None  # Initialize message variable
        final_content = None  # Store the final content string

        log.info(tag, "Starting AI analysis conversation")

        while turns < max_turns:
            # Check for cancellation at the start of each loop iteration
            if progress.cancelled():
                log.info(
                    tag, f"AI analysis cancelled before processing turn {turns + 1}"
                )
                # Progress updated by ProgressCallback cancellation handler
                return None  # Return None on cancellation

            request_num = turns + 1
            progress.progress(
                f"Sending request {request_num}/{max_turns} to AI service (Turn {turns + 1})..."
            )

            # Send messages and get streamed/aggregated response
            message = self._send_messages(ai_model, messages, progress)

            # Handle cancellation or error during _send_messages
            if message is None:
                if progress.cancelled():
                    log.info(
                        tag, f"AI analysis cancelled during request {request_num}."
                    )
                    # Progress updated by ProgressCallback cancellation handler or _send_messages
                else:
                    log.error(tag, f"Failed to get response for request {request_num}.")
                    progress.progress(f"Error during AI request {request_num}.")
                return None  # Stop analysis, return None on error/cancellation

            log.debug(
                tag,
                f"Received response for turn {turns + 1}: Content: {bool(message.content)}, Tools: {len(message.tool_calls) if message.tool_calls else 0}",
            )

            # Check if the response contains tool calls
            if message.tool_calls is not None and len(message.tool_calls) > 0:
                messages.append(
                    {
                        "role": message.role,
                        "content": message.content,  # Include content even if there are tool calls
                        "tool_calls": [  # Convert back to dict format for API
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
                    f"Request {request_num}/{max_turns}: Received {tool_count} tool calls",
                )
                progress.progress(
                    f"Processing {tool_count} tool calls (request {request_num}/{max_turns})..."
                )

                tool_results = self._process_tool_calls(
                    tool_calls, binary_view, progress
                )
                if len(tool_results) != tool_count:
                    log.warn(
                        tag,
                        f"Tool call processing failed: expected {tool_count} results, got {len(tool_results)}.",
                    )
                messages.extend(tool_results)
                turns += 1  # Increment turn count after processing tool calls

                # Check if max turns reached after processing tools
                if turns >= max_turns:
                    log.warn(
                        tag,
                        f"Reached max conversation turns ({max_turns}) after processing tools. Finishing analysis.",
                    )
                    # Use content from the message that *requested* the tools
                    final_content = (
                        message.content
                        if message and message.content
                        else "Analysis incomplete: reached maximum conversation turns after tool execution."
                    )
                    progress.progress(
                        f"Analysis finished (max turns {max_turns} reached, {total_tool_calls_processed} tools processed)."
                    )
                    # Break the loop to parse the final content
                    break

                # Continue to the next turn (will send another request)

            else:
                # No tool calls in the response, analysis should be complete
                log.info(
                    tag,
                    f"AI analysis completed after {request_num} requests and {total_tool_calls_processed} tool calls. No further tool calls requested.",
                )
                # Use the parsed field directly instead of calling _parse_final_response
                final_content = (
                    message.parsed if message and hasattr(message, "parsed") else None
                )

                progress.progress(
                    f"Analysis finished ({request_num} requests, {total_tool_calls_processed} tools)."
                )
                log.info(tag, f"Final content received: {type(final_content)}")
                # Break the loop to use the final content
                break

        # --- End of while loop ---

        # If the loop finished, use the final_content
        if final_content:
            # The response is already a VulnerabilityReport Pydantic model
            vuln: VulnerabilityReport = final_content

            # Pretty-print the model for detailed logging
            try:
                log.debug(
                    tag, f"Full AI analysis result:\n{vuln.model_dump_json(indent=4)}"
                )
            except Exception as e:
                log.debug(tag, f"Failed to serialize result: {e}\n{vuln}")

            # Generate and log a summary paragraph
            if vuln.falsePositive:
                summary = "AI analysis concluded the path is likely a false positive."
            else:
                summary = (
                    f"\nAI analysis confirms a potential {vuln.severityLevel} {vuln.vulnerabilityClass} vulnerability "
                    f"with exploitability score of {vuln.exploitabilityScore}.\n"
                    f"Explanation: {vuln.shortExplanation}.\n"
                    f"Example input: {vuln.inputExample}.\n"
                )
            log.info(tag, summary)
            return AiVulnerabilityReport(
                path_id=0,  # Placeholder, will be set in the caller
                model=ai_model,
                tool_calls=total_tool_calls_processed,
                turns=turns,
                **vuln.model_dump(),
            )
        elif progress.cancelled():
            # Should have returned None earlier, but double-check
            log.info(
                tag, "Analysis was cancelled before final content could be processed."
            )
            return None
        else:
            # Handle cases where loop finished unexpectedly or no content was ever received
            log.warn(
                tag,
                f"AI analysis loop finished after {turns} turns (max: {max_turns}) without definitive final content.",
            )
            progress.progress(
                f"Analysis finished (max turns {max_turns} reached, {total_tool_calls_processed} tools processed), but no final content."
            )
            return {
                "error": "Analysis incomplete: maximum conversation turns reached or no final content received.",
                "raw_content": None,  # No content to provide
            }

    def analyse(
        self,
        binary_view: BinaryView,
        paths: list[tuple[int, Path]],
        progress: ProgressCallback[AiVulnerabilityReport],
    ) -> None:
        """Analyze potential vulnerability paths in the binary using a progress/cancellation callback."""
        for path_id, path in paths:
            vuln = self._analyse_path(binary_view, path, progress)
            if vuln is not None:
                vuln.path_id = path_id
                progress.new_result(vuln)
