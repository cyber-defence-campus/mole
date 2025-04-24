# Usage
This section provides some guidance on how to use *Mole*.
## Configuration
*Mole* is implemented as a *Binary Ninja* sidebar, with a dedicated **_Configure_** tab that contains all plugin settings. Within this tab, the *Sources* and *Sinks* sub-tabs allow you to enable or disable available source and sink functions, respectively. General settings can be configured in the *Settings* sub-tab.

<p align="center">
  <img src="https://github.com/user-attachments/assets/b79e089d-fc3f-4f75-bc13-59410e17c437" style="width: auto; max-width: 100%; height: auto" alt="Mole Configure Tab"/>
</p>

Clicking the *Save* button stores the current configuration and writes it to the file `conf/000-mole.yml` (see the table below). These saved values are also applied when *Mole* is run in [headless mode](02-Usage.md#headless-mode), unless they are overwritten by command-line arguments. The *Reset* button restores all configuration options to their default values.

All configuration files are located in the [`conf/`](../conf/) directory. The table below lists the purpose of each file:

| File                    | Description / Purpose                                               |
|-------------------------|---------------------------------------------------------------------|
| `conf/000-mole.yml`     | File storing the effective configuration of *Mole*                  |
| `conf/001-settings.yml` | Default values for general *Mole* settings                          |
| `conf/002-libc.yml`     | Example configuration file for common `libc` source/sink functions  |
| `conf/003-yourlib.yml`  | Custom configuration file(s) for user-defined source/sink functions |

To add your own source and sink functions, create a custom file like `conf/003-yourlib.yml`. *Mole* will automatically load and show them in its *Configure* tab. For details on the expected format, refer to the next subsection.

### Definition of Source and Sink Functions
To define your own source or sink functions - such as those belonging to a custom third-party library - you can use [`conf/002-libc.yml`](../conf/002-libc.yml) as a starting point. Duplicate this file and rename it, for example, to `conf/003-yourlib.yml`. The expected format is described below:
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

## Headless Mode
Use *Mole* with the `-h` flag to display detailed usage information. The example below demonstrates how to run *Mole* on one of the unit tests (make sure to build them first by running `cd test/ && make`):
```
mole bin/memcpy-01 > ./memcpy-01.log 2>&1
```
## Example
Below is an example log output as given by *Mole*. The listed path is identified on unit test [memcpy-01.c](../test/src/memcpy-01.c), when compiled for `linux-armv7`. At log level *INFO*, the following output is given:
```
[...]
Interesting path: 0x104c4 getenv(arg#1:"MEMCPY_SIZE") --> 0x104e8 memcpy(arg#3:r2#1) [L:7,P:0,B:1]!
[...]
```
The entry indicates a potential data flow path from the source function `getenv` (located at `0x104c4`) to the sink function `memcpy` (at `0x104e8`). Specifically, the 1st parameter of `getenv` (synopsis: `char* getenv(const char* name)`) and the 3rd parameter of `memcpy` (synopsis: `void* memcpy(void* dest, const void* src, size_t n)`) are identified as relevant for this path.

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

Instructions are grouped by *basic block* (*BB*) and *function* (*FUN*). For instance, instructions 1-6 belong to the basic block starting at address `0x104d4` within the `main` function, while instruction 7 belongs to the basic block at `0x104b4`, also within `main`. This grouping is particularly useful for following the path in *Binary Ninja*'s graph view.

Beyond the textual log output, *Mole* also summarizes identified paths in the *Run* tab when used within *Binary Ninja*'s UI. Right-clicking on a path opens a context menu with several actions such as:
- Viewing detailed path information
- Highlighting instructions in the path
- Visualizing the call flow as a graph
These features help users better inspect and validate identified paths during analysis.

<p align="center">
  <img src="https://github.com/user-attachments/assets/dcc97248-af2e-46d9-9d46-f3e257434882" style="width: auto; max-width: 100%; height: auto" alt="Mole UI Interesting Path"/>
</p>

----------------------------------------------------------------------------------------------------
[Back-To-README](../README.md#documentation)
