.text
.ifdef PROVIDER
.globl error
.type error,@function
error:
    ret
.else
.globl check
.type check,@function
check:
    push %edi
    push $message
    push $0
    push $0
    mov $7,%edi
    call *error@GOT
    add $12,%esp
    pop %edi
    mov $47,%eax
    ret
.size check,.-check
.globl _start
.type _start,@function
_start:
    call check
    mov %eax,%ebx
    mov $1,%eax
    int $0x80
.section .rodata
message: .asciz "stack status"
.endif
.section .note.GNU-stack,"",@progbits
