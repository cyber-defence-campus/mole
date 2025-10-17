# Pointer Analysis
## Pointer Dereferencing
See unit-tests `load-01.c` and `load-02.c`.
## Array Indexing
Consider the source code of unit-test `load-03.c`:
```c
#include <stdio.h>
#include <stdlib.h>

__attribute__ ((noinline, optimize("O0")))
int main(int argc, char *argv[]) {
    if(argc >= 2) {
        argv[1] = getenv("CMD");    // Source
        system(argv[1]);            // Sink
    }
    return 0;
}
```
**Note**: Yes, assigning to `argv[1]` is intentional. It's just a stand-in for arbitrary array indexing 😉.

The `main` function's MLIL representation in SSA form is shown below:
```
00401170    int32_t main(int argc, char** argv)

 0 @ 0040117d  var_1c#1 = argc#0
 1 @ 00401180  var_28#1 = argv#0
 2 @ 00401188  if (var_1c#1 s<= 1) then 3 else 4 @ 0x40118a
 
 3 @ 00401188  goto 14 @ 0x4011b7

 4 @ 0040118a  rax_1#1 = var_28#1
 5 @ 0040118e  rbx_1#1 = rax_1#1 + 8
 6 @ 0040119c  rax_2#2, mem#1 = getenv(name: "CMD") @ mem#0 // Source
 7 @ 004011a1  [rbx_1#1].q = rax_2#2 @ mem#1 -> mem#2       // MLIL_STORE: Write quadword to the memory address stored in variable rbx_1#1
 8 @ 004011a4  rax_3#3 = var_28#1
 9 @ 004011a8  rax_4#4 = rax_3#3 + 8
10 @ 004011ac  rax_5#5 = [rax_4#4].q @ mem#2                // MLIL_LOAD : Read quadword from the memory address stored in variable rax_4#4
11 @ 004011af  rdi#1 = rax_5#5
12 @ 004011b2  mem#3 = system(line: rdi#1) @ mem#2          // Sink
13 @ 004011b2  goto 14 @ 0x4011b7

14 @ 004011b7  rax_5#6 = ϕ(rax#0, rax_5#5)
15 @ 004011b7  rbx_1#2 = ϕ(rbx#0, rbx_1#1)
16 @ 004011b7  rdi#2 = ϕ(argc#0, rdi#1)
17 @ 004011b7  mem#4 = ϕ(mem#0, mem#3)
18 @ 004011b7  rax_6#7 = 0
19 @ 004011c1  return 0
```

If we begin backward slicing from the sink function's parameter `rdi#1`, we may eventually encounter the MLIL_LOAD instruction `[rax_4#4].q @ mem#2` (the use-site). This instruction reads a quadword from the memory address stored in the variable `rax_4#4`. To continue the slicing process, we need to locate the definition-site of `[rax_4#4].q @ mem#2`, that is, the instruction responsible for writing to the corresponding memory region.

To achieve this, we perform backward slicing on memory versions. The MLIL_LOAD instruction where we stopped has memory version 2 (`@ mem#2`). The instruction defining this memory version is the MLIL_STORE `[rbx_1#1].q = rax_2#2 @ mem#1 -> mem#2`, which writes a quadword to the memory address stored in the variable `rbx_1#1`.

The slicer should therefore jump from the MLIL_LOAD to the corresponding MLIL_STORE if `rax_4#4` and `rbx_1#1` refer to the same memory location. By manually inspecting the instructions, we can confirm that this is indeed the case, i.e. both point to `argv[1]`.
```
rax_4#4 = rax_3#3 + 8 = var_28#1 + 8 = argv#0 + 8 --> argv[1]
rbx_1#1 = rax_1#1 + 8 = var_28#1 + 8 = argv#0 + 8 --> argv[1]
```

The above relationship is however difficult to infer automatically at the MLIL, but interestingly, if we look at the HLIL, it caputers it. That's one of the many beauties of Binary Ninja's multi-level IL design!
```
# Load `argv[1]`
>>> mlil_load_inst
<MediumLevelILLoadSsa: [rax_4#4].q @ mem#2>

>>> mlil_load_inst.hlil.ssa_form
<HighLevelILArrayIndexSsa: argv#0[1] @ mem#2>

>>> mlil_load_inst.hlil.ssa_form.src.var, mlil_load_inst.hlil.ssa_form.index.constant
(<SSAVariable: argv version 0>, 1)  <-- argv[1]


# Store `argv[1]`
>>> mlil_store_inst
<MediumLevelILStoreSsa: [rbx_1#1].q = rax_2#2 @ mem#1 -> mem#2>

>>> mlil_store_inst.hlil.ssa_form
<HighLevelILAssignMemSsa: argv#0[1] @ mem#1 @ mem#2 = getenv("CMD") @ mem#0 -> mem#1 @ mem#1>

>>> mlil_store_inst.hlil.ssa_form.dest
<HighLevelILArrayIndexSsa: argv#0[1] @ mem#1>

>>> mlil_store_inst.hlil.ssa_form.dest.src.var, mlil_store_inst.hlil.ssa_form.dest.index.constant
(<SSAVariable: argv version 0>, 1)  <-- argv[1]
```

When reaching `rax_5#5 = [rax_4#4].q @ mem#2` (MLIL_LOAD - use-site), Mole therefore knows it should continue slicing at `[rbx_1#1].q = rax_2#2 @ mem#1 -> mem#` (MLIL_STORE - def-site):
```
0x4011ac [rax_4#4].q @ mem#2 (MediumLevelILLoadSsa)

Follow store instruction '0x4011a1 [rbx_1#1].q = rax_2#2 @ mem#1 -> mem#2' since it writes the same array element ('argv#0[1]') as load instruction '0x4011ac [rax_4#4].q @ mem#2 (MediumLevelILLoadSsa)'

0x4011a1 [rbx_1#1].q = rax_2#2 @ mem#1 -> mem#2 (MediumLevelILStoreSsa)
```