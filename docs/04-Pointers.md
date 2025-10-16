# Pointer Analysis
## Array Indexing
The following is an excerpt from the unit-test source code in `load-02.c`:
```
[...]
argv[1] = getenv("CMD");    <-- Source
system(argv[1]);            <-- Sink
[...]
```
**Note**: Note: Yes, assigning to argv[1] is intentional. It's just a stand-in for arbitrary array indexing. 😉

The corresponding MLIL representation in SSA form is shown below:
```
[...]
 0 @ 0040117d  var_1c#1 = argc#0
 1 @ 00401180  var_28#1 = argv#0
 2 @ 00401188  if (var_1c#1 s<= 1) then 3 else 4 @ 0x40118a
 3 @ 00401188  goto 14 @ 0x4011b7
 4 @ 0040118a  rax_1#1 = var_28#1
 5 @ 0040118e  rbx_1#1 = rax_1#1 + 8
 6 @ 0040119c  rax_2#2, mem#1 = getenv(name: "CMD") @ mem#0
 7 @ 004011a1  [rbx_1#1].q = rax_2#2 @ mem#1 -> mem#2       <-- MLIL_STORE: Write quadword to the memory address stored in variable `rbx_1#1`
 8 @ 004011a4  rax_3#3 = var_28#1
 9 @ 004011a8  rax_4#4 = rax_3#3 + 8
10 @ 004011ac  rax_5#5 = [rax_4#4].q @ mem#2                <-- MLIL_LOAD : Read quadword from the memory address stored in variable `rax_4#4`
11 @ 004011af  rdi#1 = rax_5#5
12 @ 004011b2  mem#3 = system(line: rdi#1) @ mem#2
13 @ 004011b2  goto 14 @ 0x4011b7
[...]
```

What are `rax_4#4` and `rbx_1#1`?
```
rax_4#4 = rax_3#3 + 8 = var_28#1 + 8 = argv#0 + 8 --> argv[1]
rbx_1#1 = rax_1#1 + 8 = var_28#1 + 8 = argv#0 + 8 --> argv[1]
```

How do we know that `rax_4#4` and `rbx_1#1` point to the same memory location?

This relationship is difficult to infer at the MLIL, but the HLIL captures it. That's one of the many beauties of Binary Ninja's multi-level IL design!
```
# Load `argv[1]`
>>> mlil_load_inst
<MediumLevelILLoadSsa: [rax_4#4].q @ mem#2>

>>> mlil_load_inst.hlil
<HighLevelILArrayIndex: argv[1]>

>>> mlil_load_inst.hlil.src.var, mlil_load_inst.hlil.index.constant
(<var char** argv>, 1)                                      <-- argv[1]

# Store `argv[1]`
>>> mlil_store_inst
<MediumLevelILStoreSsa: [rbx_1#1].q = rax_2#2 @ mem#1 -> mem#2>

>>> mlil_store_inst.hlil
<HighLevelILAssign: argv[1] = getenv("CMD")>

>>> mlil_store_inst.hlil.dest
<HighLevelILArrayIndex: argv[1]>

>>> mlil_store_inst.hlil.dest.src.var, mlil_store_inst.hlil.dest.index.constant
(<var char** argv>, 1)                                      <-- argv[1]
```

When reaching `rax_5#5 = [rax_4#4].q @ mem#2` (MLIL_LOAD), Mole therefore knows it should continue slicing at `[rbx_1#1].q = rax_2#2 @ mem#1 -> mem#` (MLIL_STORE):
```
0x4011ac [rax_4#4].q @ mem#2 (MediumLevelILLoadSsa)

Follow store instruction '0x4011a1 [rbx_1#1].q = rax_2#2 @ mem#1 -> mem#2' since it writes the same array element ('argv#0[1]') as loaded by '0x4011ac [rax_4#4].q @ mem#2 (MediumLevelILLoadSsa)'

0x4011a1 [rbx_1#1].q = rax_2#2 @ mem#1 -> mem#2 (MediumLevelILStoreSsa)
```

**Note**: In addition to slicing variables, Mole can also perform backward slicing on memory versions. In the example above, this capability is used to link the MLIL_LOAD and MLIL_STORE instructions. When the slicer reaches the MLIL_LOAD instruction, the memory is at version 2 (`@ mem#2`). From there, Mole can identify the instruction that defines the previous memory version (`@ mem#1`), which in this case corresponds to the MLIL_STORE instruction of interest.