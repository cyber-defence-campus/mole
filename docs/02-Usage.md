# Usage
## Configuration
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
[Go-Back](../README.md)