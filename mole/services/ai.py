import json
from types import SimpleNamespace

from binaryninja import BinaryView
from openai import OpenAI

from mole.ai.tools import call_function, tools
from mole.common.help import InstructionHelper
from mole.common.log import log
from mole.common.task import BackgroundTask
from mole.core.data import Path
from mole.services.config import ConfigService

tag = "Mole.AI"


class AIService:
    """Service for handling AI-based vulnerability analysis."""

    def __init__(self, config_service: ConfigService):
        self._config_service = config_service
        self._current_task = None
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
    5.  **Explain Concisely:** Provide a clear explanation of why the vulnerability exists, referencing specific code patterns (or lack thereof) identified during your analysis of the slice, surrounding code, and caller context. Explain *how* the path can be triggered, considering caller conditions.
    6.  **Assess Severity:** Assign a severity level (Critical, High, Medium, Low) based on the potential impact.
    7.  **Score Exploitability:** Provide an exploitability score (0-10), justifying it based on the complexity of triggering the path (considering caller constraints) and controlling the vulnerable operation. Your contextual analysis using the tools is key here.
    8.  **Craft Example Input:** **Crucially, use your understanding of the surrounding code logic (conditions, checks, data formats obtained via tools) *and* the conditions imposed by callers to create a realistic input example that could trigger the vulnerability.** If the input is binary data, provide it in hexdump format. If it's text (like JSON or command arguments), format it appropriately. The example must aim to satisfy the conditions needed to reach the sink via the identified path, considering the full function and call chain context.

    **Your Goal:** Go beyond the slice itself. Use the tools proactively to understand the neighbourhood of the code path *and* its upstream callers function code to provide a well-reasoned analysis, assess true reachability, and craft a *plausible* triggering input based on that broader context.

**Output JSON Format:**
{
  "is_false_positive": false,
  "vulnerability_type": "Command Injection",
  "explanation": "The input buffer from the source function 'process_request', reachable via the '/api/cmd' endpoint, is used directly in a command executed by the sink 'execute_command' without proper sanitization. Caller 'handle_connection' does not impose restrictions beyond checking for authentication.",
  "severity_level": "Critical",
  "exploitability_score": 9.5,
  "input_example": "POST /api/cmd HTTP/1.1\\nHost: example.com\\nContent-Type: application/json\\n\\n{\\n\"cmd\": \"echo 'malicious_command' > /tmp/pwned\"\\n}"
}
"""

    def _get_openai_client(self):
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

    def _send_messages(self, messages, task: BackgroundTask):
        """
        Send a conversation to the AI using streaming and get the aggregated response.
        Checks for cancellation during the stream. Updates task progress.
        """
        client = self._get_openai_client()
        stream = None
        full_response_content = ""
        # Stores aggregated tool call data: {index: {"id": str, "type": "function", "function": {"name": str, "arguments": str}}}
        tool_calls_aggregator = {}
        role = "assistant"  # Default role
        chunk_count = 0

        try:
            # --- Start of cancellable section ---
            if task and task.cancelled:
                log.info(tag, "AI analysis cancelled just before sending request")
                return None

            stream = client.chat.completions.create(
                model="deepseek-chat",
                messages=messages,
                tools=tools,
                temperature=0.0,
                stream=True,
                max_tokens=1024,
                # Consider adding a timeout if the API supports it via extra_body or similar
                # timeout=30.0 # Example: httpx timeout
            )

            log.debug(tag, "Streaming response from AI...")
            for chunk in stream:
                chunk_count += 1
                if task and task.cancelled:
                    log.info(tag, "AI analysis cancelled during streaming response")
                    log.info(tag, "Received answer so far: \n" + full_response_content)
                    return None

                if task and chunk_count % 5 == 0:
                    task.progress = f"Receiving AI response (chunk {chunk_count})..."

                delta = chunk.choices[0].delta
                if delta is None:
                    continue

                if delta.role:
                    role = delta.role

                if delta.content:
                    full_response_content += delta.content

                if delta.tool_calls:
                    for tc_chunk in delta.tool_calls:
                        index = tc_chunk.index
                        if index not in tool_calls_aggregator:
                            # Initialize tool call entry if it's the first chunk for this index
                            tool_calls_aggregator[index] = {
                                "id": tc_chunk.id,  # ID usually comes first
                                "type": "function",
                                "function": {"name": "", "arguments": ""},
                            }
                            # Update ID if it arrives later (though usually first)
                            if tc_chunk.id:
                                tool_calls_aggregator[index]["id"] = tc_chunk.id
                        # Aggregate name and arguments
                        if tc_chunk.function:
                            if tc_chunk.function.name:
                                tool_calls_aggregator[index]["function"]["name"] = (
                                    tc_chunk.function.name
                                )
                            if tc_chunk.function.arguments:
                                tool_calls_aggregator[index]["function"][
                                    "arguments"
                                ] += tc_chunk.function.arguments

            # --- End of cancellable section (streaming loop) ---
            log.debug(tag, f"Finished streaming after {chunk_count} chunks.")

            # Check if task was cancelled *just* after the stream finished
            if task and task.cancelled:
                log.info(tag, "AI analysis cancelled immediately after stream finished")
                return None

            # Assemble the final tool calls list from the aggregated data
            final_tool_calls = []
            if tool_calls_aggregator:
                for index in sorted(tool_calls_aggregator.keys()):
                    tc_data = tool_calls_aggregator[index]
                    # Ensure all parts are present before creating the SimpleNamespace
                    if (
                        tc_data.get("id")
                        and tc_data.get("type") == "function"
                        and tc_data["function"].get("name") is not None
                        and tc_data["function"].get("arguments") is not None
                    ):
                        final_tool_calls.append(
                            SimpleNamespace(
                                id=tc_data["id"],
                                type=tc_data["type"],
                                function=SimpleNamespace(
                                    name=tc_data["function"]["name"],
                                    arguments=tc_data["function"]["arguments"],
                                ),
                            )
                        )
                    else:
                        log.warn(
                            tag,
                            f"Incomplete tool call data aggregated for index {index}: {tc_data}",
                        )

            # Construct the final message object
            final_message = SimpleNamespace(
                role=role,
                content=full_response_content if full_response_content else None,
                tool_calls=final_tool_calls if final_tool_calls else None,
            )
            return final_message

        except Exception as e:
            # Check for cancellation again in case the exception was due to cancellation interrupting IO
            if task and task.cancelled:
                log.info(tag, "AI analysis cancelled during exception handling.")
                return None
            else:
                log.error(tag, f"Error processing AI stream or request: {str(e)}")
                if task:
                    task.progress = f"Error in AI service: {str(e)}"
                return None
        finally:
            # Ensure the stream is closed if it was opened
            if stream is not None:
                try:
                    stream.close()
                except Exception as e:
                    log.warn(tag, f"Error closing AI stream: {e}")

    def _parse_final_response(self, content: str, task: BackgroundTask):
        """
        Attempts to parse the final AI response content as JSON,
        extracting the last ```json block if present.
        """
        if not content:
            log.warn(tag, "Final AI response content is empty.")
            return {"error": "Empty response from AI."}

        extracted_json_str = None
        # Find the start of the last ```json block
        last_json_block_start = content.rfind("```json")
        if last_json_block_start != -1:
            # Find the end of this block (the next ``` after the start)
            end_marker = content.find(
                "```", last_json_block_start + 7
            )  # Start search after ```json
            if end_marker != -1:
                # Extract the content between ```json and ```
                extracted_json_str = content[
                    last_json_block_start + 7 : end_marker
                ].strip()
                log.debug(tag, "Extracted content from last ```json block.")
            else:
                # Malformed block (```json without closing ```), try using content after marker
                extracted_json_str = content[last_json_block_start + 7 :].strip()
                log.warn(
                    tag,
                    "Found ```json marker but no closing ```, attempting parse anyway.",
                )
        else:
            # Fallback: Check for generic ``` blocks if ```json wasn't found
            last_block_end = content.rfind("```")
            if last_block_end != -1:
                # Find the start of this last block (the ``` before the end marker)
                last_block_start = content.rfind("```", 0, last_block_end)
                if last_block_start != -1:
                    extracted_json_str = content[
                        last_block_start + 3 : last_block_end
                    ].strip()
                    log.debug(tag, "Extracted content from last generic ``` block.")
                else:
                    # Only one ``` found, might be the start, try using content after it
                    extracted_json_str = content[last_block_end + 3 :].strip()
                    log.warn(
                        tag,
                        "Found only one closing ``` marker, attempting parse content after it.",
                    )

        # If we extracted something, try parsing it. Otherwise, parse the original content.
        content_to_parse = (
            extracted_json_str if extracted_json_str is not None else content.strip()
        )

        if not content_to_parse:
            log.warn(tag, "After attempting extraction, content to parse is empty.")
            return {
                "error": "Failed to extract parsable content from AI response.",
                "raw_content": content,  # Return original content in error
            }

        try:
            parsed_json = json.loads(content_to_parse)
            log.info(tag, "Successfully parsed final AI response as JSON.")
            # If extraction happened, add original content for context if needed
            if extracted_json_str is not None:
                parsed_json["_raw_ai_response"] = content
            return parsed_json
        except json.JSONDecodeError as e:
            log.error(tag, f"Failed to parse final AI response as JSON: {e}")
            log.debug(tag, f"Content that failed parsing:\n{content_to_parse}")
            log.debug(tag, f"Original AI content was:\n{content}")
            if task:
                task.progress = "Error: Failed to parse AI response."
            # Return an error structure with the content that failed parsing
            return {
                "error": f"Failed to parse AI response JSON: {e}",
                "parsing_attempted_content": content_to_parse,
                "raw_ai_response": content,
            }
        except Exception as e:
            log.error(tag, f"An unexpected error occurred during JSON parsing: {e}")
            if task:
                task.progress = "Error: Unexpected error parsing AI response."
            return {
                "error": f"Unexpected error parsing AI response: {e}",
                "parsing_attempted_content": content_to_parse,
                "raw_ai_response": content,
            }

    def _analyse_in_background(self, binary_view: BinaryView, path: Path):
        """Run the AI analysis in a background thread."""
        task = self._current_task
        if not task:  # Should not happen if called via analyse()
            log.error(tag, "Analysis started without a valid task context.")
            return None
        task.progress = "Preparing path analysis data..."

        # Check for early cancellation
        if task.cancelled:
            log.info(tag, "AI analysis cancelled before starting.")
            task.progress = "Analysis cancelled."
            return None

        messages = [
            {"role": "system", "content": self.system_prompt},
        ]

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

        messages.append({"role": "user", "content": msg})

        turns = 0
        max_turns = 5  # Maximum number of conversation turns (requests)
        total_tool_calls_processed = 0  # Keep track across turns
        message = None  # Initialize message variable
        final_content = None  # Store the final content string

        log.info(tag, "Starting AI analysis conversation")

        while turns < max_turns:
            # Check for cancellation at the start of each loop iteration
            if task.cancelled:
                log.info(
                    tag, f"AI analysis cancelled before processing turn {turns + 1}"
                )
                # Progress updated by BackgroundTask cancellation handler
                return None  # Return None on cancellation

            request_num = turns + 1
            task.progress = f"Sending request {request_num}/{max_turns} to AI service (Turn {turns + 1})..."

            # Send messages and get streamed/aggregated response
            message = self._send_messages(messages, task)

            # Handle cancellation or error during _send_messages
            if message is None:
                if task.cancelled:
                    log.info(
                        tag, f"AI analysis cancelled during request {request_num}."
                    )
                    # Progress updated by BackgroundTask cancellation handler or _send_messages
                else:
                    log.error(tag, f"Failed to get response for request {request_num}.")
                    task.progress = f"Error during AI request {request_num}."
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
                log.info(
                    tag,
                    f"Request {request_num}/{max_turns}: Received {tool_count} tool calls",
                )
                task.progress = f"Processing {tool_count} tool calls (request {request_num}/{max_turns})..."

                tool_results = []  # Store results to append after processing all tools
                for tool_index, tool in enumerate(tool_calls):
                    # Check for cancellation before processing each tool
                    if task.cancelled:
                        log.info(
                            tag,
                            f"AI analysis cancelled before processing tool {tool_index + 1}/{tool_count} (turn {request_num}/{max_turns})",
                        )
                        # Progress updated by BackgroundTask cancellation handler
                        return None  # Return None on cancellation

                    # Update progress with current tool call info
                    task.progress = f"Processing tool call {tool_index + 1}/{tool_count} (turn {request_num}/{max_turns}): {tool.function.name}..."

                    if tool.type != "function":
                        log.warn(tag, f"Skipping non-function tool call: {tool.type}")
                        tool_results.append(
                            {
                                "role": "tool",
                                "tool_call_id": tool.id,
                                "content": "Error: Tool type not supported.",
                            }
                        )
                        continue

                    name = tool.function.name
                    arguments_str = tool.function.arguments
                    output = f"Error: Tool '{name}' execution failed."  # Default error message
                    try:
                        args = json.loads(arguments_str)
                        args["binary_view"] = binary_view  # Inject binary view context

                        log.info(
                            tag, f"Executing tool {tool.id}: {name}({arguments_str})"
                        )
                        # --- Potentially long operation ---
                        output_data = call_function(name, args)
                        # --- Check cancellation again after potentially long call ---
                        if task.cancelled:
                            log.info(
                                tag,
                                f"AI analysis cancelled after executing tool {name}",
                            )
                            return None  # Return None on cancellation

                        if output_data is None:
                            log.error(
                                tag, f"Tool call {tool.id} ({name}) returned None."
                            )
                            output = f"Error: Function '{name}' returned no output."
                        else:
                            # Ensure output is string for the API message
                            output = str(output_data)

                    except json.JSONDecodeError:
                        log.error(
                            tag,
                            f"Failed to decode JSON arguments for tool {tool.id}: {arguments_str}",
                        )
                        output = "Error: Invalid JSON arguments."
                    except Exception as e:
                        log.error(
                            tag, f"Error processing tool call {tool.id} ({name}): {e}"
                        )
                        output = f"Error: Exception during tool execution: {e}"
                        # Check cancellation again in case exception was due to interruption
                        if task.cancelled:
                            log.info(
                                tag,
                                f"AI analysis cancelled during tool exception handling for {name}",
                            )
                            return None  # Return None on cancellation

                    tool_results.append(
                        {"role": "tool", "tool_call_id": tool.id, "content": output}
                    )
                    total_tool_calls_processed += 1

                # Append all tool results to messages
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
                    task.progress = f"Analysis finished (max turns {max_turns} reached, {total_tool_calls_processed} tools processed)."
                    # Break the loop to parse the final content
                    break

                # Continue to the next turn (will send another request)

            else:
                # No tool calls in the response, analysis should be complete
                log.info(
                    tag,
                    f"AI analysis completed after {request_num} requests and {total_tool_calls_processed} tool calls. No further tool calls requested.",
                )
                final_content = (
                    message.content
                    if message and message.content
                    else "Analysis complete but no final content received."
                )
                task.progress = f"Analysis finished ({request_num} requests, {total_tool_calls_processed} tools)."
                log.info(tag, f"Final content received:\n{final_content}")
                # Break the loop to parse the final content
                break

        # --- End of while loop ---

        # If the loop finished, try to parse the final_content
        if final_content:
            parsed_result = self._parse_final_response(final_content, task)
            # Pretty-print the full JSON result for detailed logging
            log.debug(
                tag, f"Full AI analysis result:\n{json.dumps(parsed_result, indent=4)}"
            )

            # Generate and log a summary paragraph
            if "error" in parsed_result:
                summary = f"AI analysis failed: {parsed_result['error']}"
                log.error(tag, summary)
            elif parsed_result.get("is_false_positive"):
                summary = "AI analysis concluded the path is likely a false positive."
                log.info(tag, summary)
            else:
                vuln_type = parsed_result.get("vulnerability_type", "N/A")
                severity = parsed_result.get("severity_level", "N/A")
                explanation = parsed_result.get("explanation", "N/A")
                score = parsed_result.get("exploitability_score", "N/A")
                input_example = parsed_result.get("input_example", "N/A")
                summary = (
                    f"\nAI analysis confirms a potential '{vuln_type}' vulnerability "
                    f"with '{severity}' severity and an exploitability score of {score}.\n"
                    f"Explanation: {explanation}.\n"
                    f"Example input: {input_example}.\n"
                )
                log.info(tag, summary)
            return parsed_result
        elif task.cancelled:
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
            task.progress = f"Analysis finished (max turns {max_turns} reached, {total_tool_calls_processed} tools processed), but no final content."
            return {
                "error": "Analysis incomplete: maximum conversation turns reached or no final content received.",
                "raw_content": None,  # No content to provide
            }

    def analyse(self, binary_view: BinaryView, path: Path):
        """Analyze a potential vulnerability path in the binary in a background task."""
        if self._current_task and not self._current_task.finished:
            log.warn(tag, "Another AI analysis task is already running")
            return self._current_task  # Return existing task

        self._current_task = BackgroundTask(
            initial_progress_text="Starting AI analysis...",
            can_cancel=True,
            run=self._analyse_in_background,
            binary_view=binary_view,
            path=path,
        )
        self._current_task.start()
        return self._current_task
