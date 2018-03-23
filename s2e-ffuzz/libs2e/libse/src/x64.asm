; Copyright (c) 2010, Dependable Systems Laboratory, EPFL
; Copyright (c) 2016, Cyberhaven, Inc
; All rights reserved.
;
; Redistribution and use in source and binary forms, with or without
; modification, are permitted provided that the following conditions are met:
;
;    * Redistributions of source code must retain the above copyright
;      notice, this list of conditions and the following disclaimer.
;
;    * Redistributions in binary form must reproduce the above copyright
;      notice, this list of conditions and the following disclaimer in the
;      documentation and/or other materials provided with the distribution.
;
;    * Neither the name of the copyright holders, nor the
;      names of its contributors may be used to endorse or promote products
;      derived from this software without specific prior written permission.
;
; THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
; ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
; WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
; DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDERS OR CONTRIBUTORS BE LIABLE
; FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
; (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
; ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
; (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
; SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.


segment .text
global bit_scan_forward_64
global bit_scan_forward_64_posix
global fast_setjmp_win32
global fast_longjmp_win32
global fast_setjmp_posix
global fast_longjmp_posix
global _fast_setjmp_posix
global _fast_longjmp_posix


[bits 64]

;int bit_scan_forward_64(uint64_t *SetIndex, uint64_t Mask);
;RCX first parameter, RDX second parameter
bit_scan_forward_64:
    xor rax, rax
    bsf rdx, rdx
    mov [rcx], rdx
    setnz al
    ret


bit_scan_forward_64_posix:
    xor rax, rax
    bsf rsi, rsi
    mov [rdi], rsi
    setnz al
    ret


struc fast_jmpbuf
    ._rax:  resq 1
    ._rbx:  resq 1
    ._rcx:  resq 1
    ._rdx:  resq 1
    ._rsi:  resq 1
    ._rdi:  resq 1
    ._rbp:  resq 1
    ._rsp:  resq 1

    ._r8:  resq 1
    ._r9:  resq 1
    ._r10:  resq 1
    ._r11:  resq 1
    ._r12:  resq 1
    ._r13:  resq 1
    ._r14:  resq 1
    ._r15:  resq 1
    ._rip:  resq 1
endstruc

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

;rcx: pointer to jmp_buf
fast_setjmp_win32:
    mov [rcx + fast_jmpbuf._rax], rax
    mov [rcx + fast_jmpbuf._rbx], rbx
    mov [rcx + fast_jmpbuf._rcx], rcx
    mov [rcx + fast_jmpbuf._rdx], rdx
    mov [rcx + fast_jmpbuf._rsi], rsi
    mov [rcx + fast_jmpbuf._rdi], rdi
    mov [rcx + fast_jmpbuf._rbp], rbp
    mov [rcx + fast_jmpbuf._rsp], rsp
    mov [rcx + fast_jmpbuf._r8], r8
    mov [rcx + fast_jmpbuf._r9], r9
    mov [rcx + fast_jmpbuf._r10], r10
    mov [rcx + fast_jmpbuf._r11], r11
    mov [rcx + fast_jmpbuf._r12], r12
    mov [rcx + fast_jmpbuf._r13], r13
    mov [rcx + fast_jmpbuf._r14], r14
    mov [rcx + fast_jmpbuf._r15], r15
    mov rax, [rsp]
    mov [rcx + fast_jmpbuf._rip], rax
    xor rax, rax
    ret

;rcx: pointer to jmp_buf
;rdx: value
fast_longjmp_win32:
    mov rax, [rcx + fast_jmpbuf._rax]
    mov rbx, [rcx + fast_jmpbuf._rbx]
    mov rcx, [rcx + fast_jmpbuf._rcx]
    ;mov rdx, [rcx + fast_jmpbuf._rdx]
    mov rsi, [rcx + fast_jmpbuf._rsi]
    mov rdi, [rcx + fast_jmpbuf._rdi]
    mov rbp, [rcx + fast_jmpbuf._rbp]
    mov rsp, [rcx + fast_jmpbuf._rsp]
    mov r8, [rcx + fast_jmpbuf._r8]
    mov r9, [rcx + fast_jmpbuf._r9]
    mov r10, [rcx + fast_jmpbuf._r10]
    mov r11, [rcx + fast_jmpbuf._r11]
    mov r12, [rcx + fast_jmpbuf._r12]
    mov r13, [rcx + fast_jmpbuf._r13]
    mov r14, [rcx + fast_jmpbuf._r14]
    mov r15, [rcx + fast_jmpbuf._r15]
    mov rax, [rcx + fast_jmpbuf._rip]
    mov [rsp], rax
    mov rax, 1
    cmp rdx, 0
    cmovnz rax, rdx
    ret

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;


;rdi: pointer to jmp_buf
fast_setjmp_posix:
    mov [rdi + fast_jmpbuf._rax], rax
    mov [rdi + fast_jmpbuf._rbx], rbx
    mov [rdi + fast_jmpbuf._rcx], rcx
    mov [rdi + fast_jmpbuf._rdx], rdx
    mov [rdi + fast_jmpbuf._rsi], rsi
    mov [rdi + fast_jmpbuf._rdi], rdi
    mov [rdi + fast_jmpbuf._rbp], rbp
    mov [rdi + fast_jmpbuf._rsp], rsp
    mov [rdi + fast_jmpbuf._r8], r8
    mov [rdi + fast_jmpbuf._r9], r9
    mov [rdi + fast_jmpbuf._r10], r10
    mov [rdi + fast_jmpbuf._r11], r11
    mov [rdi + fast_jmpbuf._r12], r12
    mov [rdi + fast_jmpbuf._r13], r13
    mov [rdi + fast_jmpbuf._r14], r14
    mov [rdi + fast_jmpbuf._r15], r15
    mov rax, [rsp]
    mov [rdi + fast_jmpbuf._rip], rax
    xor rax, rax
    ret

;rdi: pointer to jmp_buf
;rsi: value
fast_longjmp_posix:
    mov rax, [rdi + fast_jmpbuf._rax]
    mov rbx, [rdi + fast_jmpbuf._rbx]
    mov rcx, [rdi + fast_jmpbuf._rcx]
    mov rdx, [rdi + fast_jmpbuf._rdx]
    ;mov rsi, [rdi + fast_jmpbuf._rsi]
    mov rdi, [rdi + fast_jmpbuf._rdi]
    mov rbp, [rdi + fast_jmpbuf._rbp]
    mov rsp, [rdi + fast_jmpbuf._rsp]
    mov r8, [rdi + fast_jmpbuf._r8]
    mov r9, [rdi + fast_jmpbuf._r9]
    mov r10, [rdi + fast_jmpbuf._r10]
    mov r11, [rdi + fast_jmpbuf._r11]
    mov r12, [rdi + fast_jmpbuf._r12]
    mov r13, [rdi + fast_jmpbuf._r13]
    mov r14, [rdi + fast_jmpbuf._r14]
    mov r15, [rdi + fast_jmpbuf._r15]
    mov rax, [rdi + fast_jmpbuf._rip]
    mov [rsp], rax
    mov rax, 1
    cmp rsi, 0
    cmovnz rax, rsi
    ret

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;


;rdi: pointer to jmp_buf
_fast_setjmp_posix:
    mov [rdi + fast_jmpbuf._rax], rax
    mov [rdi + fast_jmpbuf._rbx], rbx
    mov [rdi + fast_jmpbuf._rcx], rcx
    mov [rdi + fast_jmpbuf._rdx], rdx
    mov [rdi + fast_jmpbuf._rsi], rsi
    mov [rdi + fast_jmpbuf._rdi], rdi
    mov [rdi + fast_jmpbuf._rbp], rbp
    mov [rdi + fast_jmpbuf._rsp], rsp
    mov [rdi + fast_jmpbuf._r8], r8
    mov [rdi + fast_jmpbuf._r9], r9
    mov [rdi + fast_jmpbuf._r10], r10
    mov [rdi + fast_jmpbuf._r11], r11
    mov [rdi + fast_jmpbuf._r12], r12
    mov [rdi + fast_jmpbuf._r13], r13
    mov [rdi + fast_jmpbuf._r14], r14
    mov [rdi + fast_jmpbuf._r15], r15
    mov rax, [rsp]
    mov [rdi + fast_jmpbuf._rip], rax
    xor rax, rax
    ret

;rdi: pointer to jmp_buf
;rsi: value
_fast_longjmp_posix:
    mov rax, [rdi + fast_jmpbuf._rax]
    mov rbx, [rdi + fast_jmpbuf._rbx]
    mov rcx, [rdi + fast_jmpbuf._rcx]
    mov rdx, [rdi + fast_jmpbuf._rdx]
    ;mov rsi, [rdi + fast_jmpbuf._rsi]
    mov rdi, [rdi + fast_jmpbuf._rdi]
    mov rbp, [rdi + fast_jmpbuf._rbp]
    mov rsp, [rdi + fast_jmpbuf._rsp]
    mov r8, [rdi + fast_jmpbuf._r8]
    mov r9, [rdi + fast_jmpbuf._r9]
    mov r10, [rdi + fast_jmpbuf._r10]
    mov r11, [rdi + fast_jmpbuf._r11]
    mov r12, [rdi + fast_jmpbuf._r12]
    mov r13, [rdi + fast_jmpbuf._r13]
    mov r14, [rdi + fast_jmpbuf._r14]
    mov r15, [rdi + fast_jmpbuf._r15]
    mov rax, [rdi + fast_jmpbuf._rip]
    mov [rsp], rax
    mov rax, 1
    cmp rsi, 0
    cmovnz rax, rsi
    ret


