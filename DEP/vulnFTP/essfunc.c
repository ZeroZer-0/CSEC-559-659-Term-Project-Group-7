#include <stdio.h>
#include <string.h>

#define VERSION "1.00"

void EssentialFunc1(void) {
    printf("Called essential function dll version %s\n", VERSION);
}


void EssentialFunc2(void) {
    __asm__("jmp *%esp\n\t"
            "jmp *%eax\n\t"
            "pop %eax\n\t"
            "pop %eax\n\t"
            "ret");
}

void EssentialFunc3(void) {
    __asm__("jmp *%esp\n\t"
            "jmp *%ecx\n\t"
            "pop %ebx\n\t"
            "pop %ebx\n\t"
            "ret");
}

void EssentialFunc4(void) {
    __asm__("jmp *%esp\n\t"
            "jmp *%ebx\n\t"
            "pop %ebp\n\t"
            "pop %ebp\n\t"
            "ret");
}

void EssentialFunc5(void) {
    __asm__("jmp *%esp\n\t"
            "jmp *%edi\n\t"
            "pop %ebx\n\t"
            "pop %ebx\n\t"
            "ret");
}

void EssentialFunc6(void) {
    __asm__("jmp *%esp\n\t"
            "jmp *%edx\n\t"
            "pop %ecx\n\t"
            "pop %edx\n\t"
            "ret");
}

void EssentialFunc7(void) {
    __asm__("jmp *%esp\n\t"
            "jmp *%esi\n\t"
            "pop %ecx\n\t"
            "pop %eax\n\t"
            "ret");
}

void EssentialFunc8(void) {
    __asm__("jmp *%esp\n\t"
            "jmp *%ebp\n\t"
            "pop %eax\n\t"
            "pop %edx\n\t"
            "ret");
}

void EssentialFunc9(void) {
    __asm__("jmp *%esp\n\t"
            "jmp *%esp\n\t"
            "jmp *-12(%esp)\n\t"
            "pop %ecx\n\t"
            "pop %ecx\n\t"
            "ret");
}


void DEP_xchg(void) {
    __asm__("xchgl %eax, %esi\n\t"
            "ret");
}

void DEP_call(void) {
    __asm__("call *%esp\n\t"
            "ret");
}

void DEP_inc(void) {
    __asm__("inc %edx\n\t"
            "ret");
}

void DEP_xor(void) {
    __asm__("xor %eax, %edx\n\t"
            "ret");
}

void DEP_neg(void) {
    __asm__("neg %eax\n\t"
            "ret");
}

void DEP_mov(void) {
    __asm__("movl %eax, %ebx\n\t"
            "ret");
}

void DEP_pushad(void) {
    __asm__("pushal\n\t"
            "ret");
}

void DEP_deref(void) {
    __asm__("movl (%eax), %eax\n\t"
            "ret");
    __asm__("mov (%ebx), %ebx\n\t"
            "ret");
    __asm__("movl (%ecx), %ecx\n\t"
            "ret");
}

void DEP_push(void) {
    __asm__("push %eax\n\t" "ret");
    __asm__("push %ebx\n\t" "ret");
    __asm__("push %ecx\n\t" "ret");
    __asm__("push %edx\n\t" "ret");
    __asm__("push %edi\n\t" "ret");
    __asm__("push %esi\n\t" "ret");
    __asm__("push %ebp\n\t" "ret");
    __asm__("push %esp\n\t" "ret");
}

void DEP_pop(void) {
    __asm__("pop %eax\n\t" "ret");
    __asm__("pop %ebx\n\t" "ret");
    __asm__("pop %ecx\n\t" "ret");
    __asm__("pop %edx\n\t" "ret");
    __asm__("pop %edi\n\t" "ret");
    __asm__("pop %esi\n\t" "ret");
    __asm__("pop %ebp\n\t" "ret");
    __asm__("pop %esp\n\t" "ret");
}

void EssentialFunc10(char *Input) { char b[140];  strcpy(b, Input); }
void EssentialFunc11(char *Input) { char b[60];   strcpy(b, Input); }
void EssentialFunc13(char *Input) { char b[2000]; strcpy(b, Input); }
void EssentialFunc14(char *Input) { char b[1000]; strcpy(b, Input); }
