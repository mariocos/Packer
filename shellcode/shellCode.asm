global start


section .text
_start:

mov rax, 1
mov rdi, 1				;stdout
lea rsi, [rel + msg]	;adress
mov rdx, 1				;size 1

syscall

mov rax, [rel + oldEntry]
jmp rax

msg:
db 'a'

oldEntry:
dq 0xffffffffffffffff
