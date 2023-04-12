---
title: NASM (Netwide Assembler) notes
---

## Registers

```text
rax (64-bit), eax (lower 32-bit), ah (higher 16-bit), al (lower 16-bit)

Same pattern: rax, rbx, rcx, rdx

rsp - stack pointer, points to the top of the stack.
rbp - stack base pointer, points to the base of the current stack frame.
rip - instruction pointer, points to the next instruction to be executed.
```

## Operations

```nasm
mov rax, rbx        ; rax = rbx
mov rax, [rbx]      ; rax = *rbx (rbx is a pointer)
mov rax, 1          ; rax = 1

int 0x80            ; Call OS interrupt
```

## Bit operations

```nasm
or  rax, rbx        ; rax = rax | rbx
and rax, rbx        ; rax = rax & rbx
xor rax, rbx        ; rax = rax ^ rbx
not rax             ; rax = ~rax

shl rax, 31         ; rax = rax << 31
shr rax, 2          ; rax = rax >> 2
```

## Tricks & shortcuts

```nasm
xor rax, rax        ; rax = 0

; Clear 57 bit (counting from 0) in rbx register
and rbx, ~(1 << 57)

; Set 57 bit (counting from 0) in rbx register
or  rbx, 

; Toggle 57 bit (counting from 0) in rbx register
xor rbx, (1 << 57)
```
