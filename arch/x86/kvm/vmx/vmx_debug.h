/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __KVM_X86_VMX_DEBUG_H
#define __KVM_X86_VMX_DEBUG_H

#ifdef CONFIG_DEBUG_KERNEL
char *debug_dump_vmcs(void);
char *debug_dump_vmx_msr_state(void);
void debug_validate_vmcs_registers(void);

#if !defined(CONFIG_PKVM_INTEL_DEBUG) && defined(__PKVM_HYP__)
#define debug_validate_vmcs(...) do {} while (0)
#else
#define debug_validate_vmcs debug_validate_vmcs_registers
#endif

#else
static inline char *debug_dump_vmcs(void) { return NULL; }
static inline char *debug_dump_vmx_msr_state(void) { return NULL; }
static inline debug_validate_vmcs_registers(void) { }

#define debug_validate_vmcs(...) do {} while (0)
#endif

#endif /* __KVM_X86_VMX_DEBUG_H */
