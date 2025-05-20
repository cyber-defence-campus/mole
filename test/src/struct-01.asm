; nasm -f elf64 -g -F dwarf src/struct-01.asm -o bin/struct-01.o
; ld bin/struct-01.o -o bin/struct-01.linux-x86_64
; rm bin/struct-01.o

section .data
    my_struct:                  ; Structure with three integers
        dd 0                    ; field_a (4 bytes)
        dd 0                    ; field_b (4 bytes)
        dd 0                    ; field_c (4 bytes)

section .text
global _start

_start:
    lea rdi, [rel my_struct]    ; Load address of my_struct into rdi
    mov dword [rdi+0], 1337     ; Write 1337 to field_a (offset 0)
    mov dword [rdi+4], 1338     ; Write 1338 to field_b (offset 4)
    mov dword [rdi+8], 1339     ; Write 1339 to field_b (offset 4)

    mov eax, 60                 ; syscall: exit
    xor edi, edi                ; status 0
    syscall                     ; Exit cleanly using Linux syscall