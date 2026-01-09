#include <linux/linkage.h>
#include <asm/asm.h>

.global __get_user_hyp64
__get_user_hyp64:
	push %rbx

	mov %cr3, %rax
	mov %rax, %rbx

	stac
	mov %rdi, %cr3

	.Ltry_read:
	mov (%rsi), %rax	/* Read from target vaddr to RAX */
	mov %rax, (%rdx)	/* Store result to destination pointer */
	xor %rax, %rax		/* Success return code 0 */
	jmp .Lrestore_cr3

.Lrestore_cr3:
	mov %rbx, %cr3

	clac

	pop %rbx
	RET

.Lfault_handler:
	mov $-14, %rax		/* -EFAULT */
	jmp .Lrestore_cr3

	/*
	 * Define exception table entry. If a fault occurs at address .Ltry_read,
	 * resume execution at .Lfault_handler.
	 */
	_ASM_EXTABLE(.Ltry_read, .Lfault_handler)
