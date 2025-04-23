# Usage
## Configuration
*Mole* is implemented as a *Binary Ninja* sidebar, with a dedicated **_Configure_** tab that contains all plugin settings. Within this tab, the *Sources* and *Sinks* sub-tabs allow you to enable or disable available source and sink functions, respectively. General settings can be configured in the *Settings* sub-tab.

<p align="center">
  <img src="https://github.com/user-attachments/assets/b79e089d-fc3f-4f75-bc13-59410e17c437" style="width: auto; max-width: 100%; height: auto" alt="Mole Configure Tab"/>
</p>

Clicking the *Save* button stores the current configuration and writes it to the file `conf/000-mole.yml` (see the table below). These saved values are also applied when *Mole* is run in headless mode, unless they are overwritten by command-line arguments. The *Reset* button restores all configuration options to their default values.

All configuration files are located in the [`conf/`](../conf/) directory. The table below lists the purpose of each file:

| File                    | Description / Purpose                                         |
|-------------------------|---------------------------------------------------------------|
| `conf/000-mole.yml`     | File storing the effective configuration of *Mole*            |
| `conf/001-settings.yml` | Default values for general *Mole* settings                    |
| `conf/002-libc.yml`     | Example configuration for common `libc` source/sink functions |
| `conf/003-xxx.yml`      | Custom file(s) for user-defined source/sink functions         |

To add your own source and sink functions, create a custom file like `conf/003-xxx.yml`. These will be automatically loaded and shown in *Mole*'s *Configure* tab. For details on the expected format, see the next section.

### Definition of Source/Sink Functions
```YAML
sources:
  libc:
    name: libc
    categories:
      Environment Accesses:
        name: Environment Accesses
        functions:
          getenv:
            name: getenv
            symbols: [getenv, __builtin_getenv]
            synopsis: char* getenv(const char* name)
            enabled: true
            par_cnt: i == 1
            par_slice: 'False'
[...CUT...]
sinks:
  libc:
    name: libc
    categories:
      Memory Copy:
        name: Memory Copy
        functions:
          memcpy:
            name: memcpy
            symbols: [memcpy, __builtin_memcpy]
            synopsis: void* memcpy(void* dest, const void* src, size_t n)
            enabled: true
            par_cnt: i == 3
            par_slice: 'True'
```
## Example
In the following we show an example log output as given by *Mole*. The listed path is identified when compiling unittest [memcpy-01.c](./test/src/memcpy-01.c) for `linux-armv7` and analyzing the resulting binary with *Mole*. At log level *INFO* we get the following entry:
```
[...]
Interesting path: 0x4c4 getenv --> 0x4e8 memcpy(arg#3:r2#1) [L:7,P:0,B:1]!
[...]
```
The entry indicates that a potential path exists between source function `getenv` (at address `0x4c4`) and sink function `memcpy` (at address `0x4e8`). In addition, the entry tells us that the 3rd argument of `memcpy` (synopsis: `void* memcpy(void* dest, const void* src, size_t n)`) is the one being influenced by the source. Also we may learn that the path consists of 7 [MLIL](https://docs.binary.ninja/dev/bnil-mlil.html) instructions (`L:7`), contains 0 [PHI](https://api.binary.ninja/binaryninja.mediumlevelil-module.html#binaryninja.mediumlevelil.MediumLevelILVarPhi) instructions (`P:0`), and depends on 1 branch (`B:1`). These three metrics can give us a first intuition of how complex the identified path might be and in consequence some indication whether it is more or less likely to be a true positive.

At log level *DEBUG*, we get a list of all the instructions in the identified path (starting at the sink - *backward slicing*):
```
[...]
--- Backward Slice  ---
- FUN: 'main', BB: 0x4d4
0x4e8 mem#5 = 0x430(r0#5, r1#1, r2#1) @ mem#4 (MediumLevelILCallSsa)
0x4e8 r2#1 (MediumLevelILVarSsa)
0x4e0 r2#1 = n#4 (MediumLevelILSetVarSsa)
0x4e0 n#4 (MediumLevelILVarSsa)
0x4d4 n#4, mem#4 = 0x478(str#1) @ mem#2 (MediumLevelILCallSsa)
0x4d4 str#1 (MediumLevelILVarSsa)
--- Source Function ---
- FUN: 'main', BB: 0x4b4
0x4c4 str#1, mem#2 = 0x424("MEMCPY_SIZE") @ mem#1 (MediumLevelILCallSsa)
-----------------------
[...]
```
Note also that the output groups the instructions by basic blocks (*BB*). For example, the instructions 1-6 belong to the basic block starting at adddress `0x4d4` and to the function (*FUN*) named `main`. Instruction 7 to the BB at `0x4b4` and FUN `main`, and so on. This grouping especially helps when following along an identified path in *Binary Ninja*'s graph view.

In addition to the previously mentioned log entries, *Mole* summarizes the identified paths in its *Run* tab (when used within the *Binary Ninja UI*). Right-clicking a path opens a context menu with various actions, such as displaying path details or highlighting a path's instructions. Alternatively, double-clicking a path highlights its instructions, while a second double-click removes the highlights. This visualization helps users better understand and verify paths.

![Mole UI Interesting Paths](https://github.com/user-attachments/assets/dcc97248-af2e-46d9-9d46-f3e257434882)
----------------------------------------------------------------------------------------------------
[Go-Back](../README.md#documentation)
