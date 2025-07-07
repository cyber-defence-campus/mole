# Usage
This section provides some guidance on how to use *Mole*.
## Configuration
*Mole* is implemented as a *Binary Ninja* sidebar, with a dedicated **_Configure_** tab that contains all plugin settings. Within this tab, the *Sources* and *Sinks* sub-tabs allow you to enable or disable available source and sink functions, respectively. General settings can be configured in the *Settings* sub-tab.

<p align="center">
  <img src="https://i.postimg.cc/SsDV6vX7/configure-tab.png" alt="Mole Configure Tab"/>
</p>

Clicking the *Save* button stores the current configuration and writes it to the file `conf/000-mole.yml` (see the table below). These saved values are also applied when *Mole* is run in [headless mode](02-Usage.md#headless-mode), unless they are overwritten by command-line arguments. The *Reset* button restores all configuration options to their default values.

All configuration files are located in the [`conf/`](../mole/conf/) directory. The table below lists the purpose of each file:

| File                    | Description / Purpose                                               |
|-------------------------|---------------------------------------------------------------------|
| `conf/000-mole.yml`     | File storing the effective configuration of *Mole*                  |
| `conf/001-settings.yml` | Default values for general *Mole* settings                          |
| `conf/002-libc.yml`     | Example configuration file for common `libc` source/sink functions  |
| `conf/003-yourlib.yml`  | Custom configuration file(s) for user-defined source/sink functions |

You can add your own source and sink functions either by creating a custom YAML file (e.g., `conf/003-yourlib.yml`) or by adding them manually through Binary Ninja's UI. For more details on how to do this and the expected format, refer to the next subsection.

### Source and Sink Functions
#### Via YAML Files
To define your own source or sink functions - such as those belonging to a custom third-party library - you can use [`conf/002-libc.yml`](../mole/conf/002-libc.yml) as a starting point. Duplicate this file and rename it, for example, to `conf/003-yourlib.yml`. The expected format is described below:
```YAML
sources:                                             # Collection of function sources (or sinks)
  libc:                                              # Library identifier
    name: libc                                       # Human-readable name of the library
    categories:                                      # Collection of function categories
      Environment Accesses:                          # Category identifier
        name: Environment Accesses                   # Human-readable category name
        functions:                                   # Collection of functions
          getenv:                                    # Function identifier
            name: getenv                             # Human-readable function name
            symbols: [getenv, __builtin_getenv]      # List of symbols to match the function
            synopsis: char* getenv(const char* name) # Human-readable function signature for reference
            enabled: true                            # Whether the function is enabled by default
            par_cnt: i == 1                          # Expression to validate the correct number of parameters
            par_slice: 'False'                       # Expression specifying which parameter should be sliced
```
**Note**: The grammar and syntax for expressions such as `par_cnt` and `par_slice` is defined [here](../mole/common/parse.py#L14).

The `par_slice` expression specifies which function parameters should be included in the backward slice. The selection of parameters depends on your specific use case and analysis goals. For example, when trying to identify potential vulnerabilities, you should slice parameters of source functions that introduce untrusted input, as well as parameters of sink functions that could result in dangerous behavior. It is relevant to slice source function parameters because the backward slice from a sink might not always reach the source's call site directly - it may instead trace back to where the parameter is defined or used.

#### Via UI
In addition to defining source and sink functions in YAML files, *Mole* also lets you right-click a call instruction in Binary Ninja's UI to mark it as a source or sink for slicing:

<p align="center">
  <img src="https://i.postimg.cc/xTbn34mN/manual-01.png" alt="Mole Manual Source / Sink"/>
</p>

If the selected instruction can be mapped to a valid MLIL call instruction, the following configuration dialog will appear:

<p align="center">
  <img src="https://i.postimg.cc/ZRRhB7ZR/manual-02.png" alt="Mole Manual Source / Sink"/>
</p>

The settings are identical to those described above for the YAML files, with one additional option: the `all_code_xrefs` checkbox. When enabled, *Mole* will treat not only the selected call instruction as a source or sink, but also all code references to the same symbol (e.g., all calls to `getenv`).

Clicking the *Find* button starts the slicing process. If the selected instruction is a source, *Mole* uses it as the sole source and attempts to find paths to any sinks defined in the YAML files. Conversely, if the selected instruction is a sink, *Mole* performs backward slicing from that sink to all sources specified in the YAML configuration files.

Clicking the *Add* button adds the configured function to a special sub-tab named **_manual_**, where you can enable or disable it for future analyses.

<p align="center">
  <img src="https://i.postimg.cc/Th88sTbL/manual-03.png" alt="Mole Manual Source / Sink"/>
</p>

Saving your configuration permanently stores any source or sink functions added through the UI. These entries are saved in the standard YAML format in the file `conf/000-foobar.yml` (as described above).

### OpenAI API Endpoint
*Mole* includes an AI-assisted analysis mode designed to provide deeper insights into identified paths. This feature leverages *Large Language Models* (*LLMs*) to examine potential vulnerabilities, evaluate their severity, and suggest inputs that could trigger the corresponding code paths.

To enable AI-based analysis, you must first configure an OpenAI-compatible endpoint in the *Configure / Settings* sub-tab. The following settings are available:

| Setting               | Description                                                                        |
|-----------------------|------------------------------------------------------------------------------------|
| openai_base_url       | URL of OpenAI-compatible API endpoint (e.g., `https://api.openai.com/v1`)          |
| openai_api_key        | API key for authentication (leave empty for `MOCK` mode)                           |
| openai_model          | Model to use (e.g., `o4-mini`)                                                     |
| max_turns             | Maximum number of turns in a conversation                                          |
| max_completion_tokens | Maximum number of tokens in a completion                                           |
| temperature           | Sampling temperature (lower values make the output more focused and deterministic) |

Based on our initial testing, OpenAI’s `o4-mini` model offers a good balance between output quality and cost efficiency. However, you are free to use any model or provider that supports tool calling and structured output, depending on your preferences and requirements.

> **Cost Disclaimer:** The AI analysis feature may incur charges from your LLM provider, depending on their API pricing. Costs can vary based on the selected model, the complexity and length of each analysis, and the number of paths analyzed. Be sure to review your provider’s pricing structure before running bulk analyses.

> **Privacy Disclaimer**: When using the AI analysis feature, information from the current binary - such as code, symbols, strings, comments, and other contextual data - may be sent to the configured OpenAI-compatible endpoint for processing. **Do not use this feature on binaries containing sensitive, proprietary, or confidential information**, as the data may be transmitted to a third party. Use this functionality at your own discretion and in accordance with your organization’s security policies.

## Headless Mode
Use *Mole* with the `-h` flag to display detailed usage information. The example below demonstrates how to run *Mole* on one of the unit tests (make sure to build them first by running `cd test/ && make`):
```
mole bin/memcpy-01 > ./memcpy-01.log 2>&1
```

## Example
### Inspecting Paths
Below is an example log output as given by *Mole*. The listed path is identified on unit test [memcpy-01.c](../test/src/memcpy-01.c), when compiled for `linux-armv7`. At log level *INFO*, the following output is given:
```
[...]
Interesting path: 0x104c4 getenv() --> 0x104e8 memcpy(arg#3:r2#1) [L:7,P:0,B:1]!
[...]
```
This entry highlights a potential data flow from the source function `getenv` (at `0x104c4`) to the sink function `memcpy` (at `0x104e8`). Specifically, data returned by `getenv` influences the 3rd parameter of `memcpy` (synopsis: `void* memcpy(void* dest, const void* src, size_t n)`), which determines the number of bytes to copy.

The annotation `[L:7,P:0,B:1]` provides additional insights:
- `L:7` indicates the path spans 7 [MLIL](https://docs.binary.ninja/dev/bnil-mlil.html) instructions
- `P:0` means no [PHI](https://api.binary.ninja/binaryninja.mediumlevelil-module.html#binaryninja.mediumlevelil.MediumLevelILVarPhi) instructions are involved
- `B:1` shows that the path depends on a single branch condition

These metrics offer a rough estimate of the path's complexity, which can help assess the likelihood of it being a true positive.

At log level *DEBUG*, a full listing of the instructions along the path is shown, starting from the sink (*backward slicing*):
```
[...]
--- Backward Slice  ---
- FUN: 'main', BB: 0x104d4
0x104e8 mem#5 = memcpy(r0#5, r1#1, r2#1) @ mem#4 (MediumLevelILCallSsa)
0x104e8 r2#1 (MediumLevelILVarSsa)
0x104e0 r2#1 = n#4 (MediumLevelILSetVarSsa)
0x104e0 n#4 (MediumLevelILVarSsa)
0x104d4 n#4, mem#4 = atoi(str#1) @ mem#2 (MediumLevelILCallSsa)
0x104d4 str#1 (MediumLevelILVarSsa)
- FUN: 'main', BB: 0x104b4
0x104c4 str#1, mem#2 = getenv("MEMCPY_SIZE") @ mem#1 (MediumLevelILCallSsa)
-----------------------
[...]
```

Instructions are grouped by *function* (*FUN*) and *basic block* (*BB*). For instance, instructions 1-6 belong to the basic block starting at address `0x104d4` within the `main` function, while instruction 7 belongs to the basic block at `0x104b4`, also within `main`. This grouping is particularly useful for following the path in *Binary Ninja*'s graph view.

Beyond the textual log output, *Mole* also summarizes identified paths in the *Paths* tab when used within *Binary Ninja*'s UI. Right-clicking on a path opens a context menu with several actions such as:
- Viewing detailed path information
- Highlighting instructions in the path
- Visualizing the call flow as a graph
- Analyzing a path with AI

These features help users better inspect and validate identified paths during analysis.

<p align="center">
  <img src="https://i.postimg.cc/Z59c2J7M/interesting-paths.png" alt="Mole UI Paths"/>
</p>

### Analyzing Paths with AI
Once [configured](02-Usage.md#openai-api-endpoint), you can initiate AI analysis by right-clicking on any path (or a group of selected paths) in the *Paths* tab and choosing *Run AI analysis* from the context menu.

The analysis may take some time, depending on the complexity of the paths and the model in use. Once complete, an AI-generated severity level will appear in the path tree view.

<p align="center">
  <img src="https://i.postimg.cc/WpWRw9g4/ai-results.png" alt="Mole AI Settings Configuration"/>
</p>

For more detailed insights, right-click on a path and select *Show AI report* from the context menu. The report includes the following information:
- True positive status
- Severity level (Low, Medium, High, Critical)
- Vulnerability type
- Explanation of the issue
- Example of a potential triggering input
- Additional context from the AI analysis

<p align="center">
  <img src="https://i.postimg.cc/dQm2bX4q/ai-result-details.png" alt="Mole AI Analysis Results"/>
</p>

----------------------------------------------------------------------------------------------------
[Back-To-README](../README.md#documentation)
