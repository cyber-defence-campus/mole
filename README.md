[![Publish Release](https://github.com/pdamian/mole/actions/workflows/release.yml/badge.svg)](https://github.com/pdamian/mole/actions/workflows/release.yml)
# Mole

<p align="center">
  <img src="https://drive.google.com/uc?export=view&id=1oToYEJyJOJtT9fgl7Pm4DuVloZGod5MO" style="width: 256px; max-width: 100%; height: auto" alt="Mole Logo"/>
</p>

*Mole* is a *Binary Ninja* plugin that tries to identify **interesting paths** (from untrusted sources to sensitive sinks) using **static backward slicing**. The plugin can be run both in the *Binary Ninja UI* and in headless mode.

## Installation
In the following, we assume that the variables `$BINJA_BIN` and `$BINJA_USR` point to your *Binary Ninja*'s [binary path](https://docs.binary.ninja/guide/index.html#binary-path) and [user folder](https://docs.binary.ninja/guide/index.html#user-folder), respectively. Use the following steps to install *Mole*:

- Clone the plugin to your *Binary Ninja*'s user folder:
  ```shell
  cd $BINJA_USR/plugins/
  git clone https://github.com/pdamian/mole.git && cd mole/
  ```
- Create and activate a new Python virtual environment for *Mole* (optional, but recommended):
  ```shell
  python3 -m venv venv/mole
  source venv/mole/bin/activate
  ```
- Install *Binary Ninja*'s Python [API](https://docs.binary.ninja/dev/batch.html#install-the-api):
  ```shell
  python $BINJA_BIN/scripts/install_api.py
  ```
- Install *Mole* either in standard or development mode:
  ```shell
  # Standard
  pip install .

  # Development
  pip install -e .[develop]
  ```
- Lauch *Binary Ninja* outside the virtual environment:
  ```shell
  $BINJA_BIN/binaryninja &
  ```
**Note**: In *Binary Ninja*, consider setting the site-package directory to the one used by your virtual environment (`venv/mole/lib/python3.XX/site-packages`).

## Path Identification
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

## Extending Path Grouping

To implement a custom path grouping strategy:

1. Create a new subclass of `PathGrouper` in the grouping package.
2. Your strategy name will be dynamically detected, so no need to manually add it to the `003-settings.yml` file.
3. Define your key tuple by specifying the following values:
  - `display_name`: A `str` that users will see in the tree view.
  - `internal_id`: A key for uniquely identifying each group.
  - `level`: Determines the group's depth level in the tree view hierarchy.

> You can inherit from existing strategies (see `CallgraphPathGrouper` for an example).
