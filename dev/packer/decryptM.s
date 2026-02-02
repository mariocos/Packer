section .text
    global decrypt_data


decrypt_data:
    ; mov     rdi, 0x571c064ab300    ; data address
    mov     rsi, 263            ; data length
    mov     rdx, 1080613555473033452    ; key

    cmp    rsi, 0
    je      .done

    mov     r8, rdx            ; state = key
    xor     r10, r10           ; r10 = i 

.loop:
    test    r10, 7
    jne     .use_state

    ; --- xorshift64 ---
    mov     r9, r8
    shr     r9, 12
    xor     r8, r9
    mov     r9, r8
    shl     r9, 25
    xor     r8, r9
    mov     r9, r8
    shr     r9, 27
    xor     r8, r9
    mov     r9, 0x2545F4914F6CDD1D ; xor64 hardcoded value
    imul    r8, r9             ; r8 = updated state

.use_state:
    ; Calculate shift: (i % 8) * 8
    mov     rax, r10
    and     rax, 7
    shl     rax, 3
    mov     rcx, rax           

    mov     rdx, r8            
    shr     rdx, cl            ; Shift state by (i%8)*8

    xor     byte [rdi + r10], dl

    inc     r10
    cmp     r10, rsi
    jne     .loop


.get_msg_addr:
    call .do_print          ; Pushes the address of the string below, i believe this is okay because the stack use is minimal 
    db "....WOODY.....", 0x0A

.do_print:
    pop     rsi
    mov     rax, 1
    mov     rdi, 1
    mov     rdx, 15
    syscall

.done:
    ret