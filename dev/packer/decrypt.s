decrypt_data:
    cmp    rsi, 0
    je      .done

    mov     r8, rdx            ; state = key
    xor     r10, r10           ; r10 = i (Use r10 to keep rcx free for shifts)

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
    mov     r9, 0x2545F4914F6CDD1D
    imul    r8, r9             ; r8 = updated state

.use_state:
    ; Calculate shift: (i % 8) * 8
    mov     rax, r10
    and     rax, 7
    shl     rax, 3
    mov     rcx, rax           ; Use rcx safely here for the shift

    mov     rdx, r8            ; Copy state
    shr     rdx, cl            ; Shift state by (i%8)*8

    xor     byte [rdi + r10], dl

    inc     r10
    cmp     r10, rsi
    jne     .loop

.done:
    ret