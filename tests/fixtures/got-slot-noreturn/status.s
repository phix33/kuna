/* Fixed argument and binding controls for memory-indirect ELF calls. */
.text
.macro function name
    .globl \name
    .type \name, @function
\name:
    sub $8, %rsp
.endm
.macro finish name, result
    mov $\result, %eax
    add $8, %rsp
    ret
    .size \name, .-\name
.endm
.macro report
    xor %esi, %esi
    lea message(%rip), %rdx
    xor %eax, %eax
    call *error@GOTPCREL(%rip)
.endm

function joined
    mov %edi, %ecx
    xor %edi, %edi
    test %ecx, %ecx
    jz 1f
    mov $1, %edi
1:  report
    finish joined, 41

function wide_zero
    movabs $0x100000000, %rdi
    report
    finish wide_zero, 42

function atomic_status
    mov $1, %edi
    lock xadd %edi, count(%rip)
    report
    finish atomic_status, 43

function underscored
    mov $7, %edi
    call *__error@GOTPCREL(%rip)
    finish underscored, 44

function definite
    mov $7, %edi
    report
    finish definite, 45

.section .rodata
message: .asciz "status"
.bss
.balign 4
count: .zero 4
.section .note.GNU-stack,"",@progbits
