/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _ASM_X86_PKVM_GUEST_H
#define _ASM_X86_PKVM_GUEST_H

#include <linux/errno.h>
#include <linux/types.h>

#ifdef CONFIG_PKVM_X86_GUEST

void pkvm_guest_init_coco(void);
int pkvm_set_mem_host_visibility(unsigned long addr, int numpages, bool enc);
int pkvm_guest_iommu_get_iova_bits(void);
int pkvm_guest_iommu_map(unsigned long iova, phys_addr_t gpa, size_t size,
			 int prot, size_t *mapped);
int pkvm_guest_iommu_unmap(unsigned long iova, size_t size, size_t *unmapped);

DECLARE_STATIC_KEY_FALSE(pkvm_guest_detected);

static inline bool pkvm_is_protected_guest(void)
{
	return static_branch_likely(&pkvm_guest_detected);
}

#else /* CONFIG_PKVM_X86_GUEST */

static inline void pkvm_guest_init_coco(void) {}
static inline int pkvm_set_mem_host_visibility(unsigned long addr,
					       int numpages, bool enc)
{
	return 0;
}

static inline int pkvm_guest_iommu_get_iova_bits(void)
{
	return -EOPNOTSUPP;
}

static inline int pkvm_guest_iommu_map(unsigned long iova, phys_addr_t gpa,
				       size_t size, int prot, size_t *mapped)
{
	*mapped = 0;
	return -EOPNOTSUPP;
}

static inline int pkvm_guest_iommu_unmap(unsigned long iova, size_t size,
					 size_t *unmapped)
{
	*unmapped = 0;
	return -EOPNOTSUPP;
}

static inline bool pkvm_is_protected_guest(void) { return false; }

#endif /* CONFIG_PKVM_X86_GUEST */

#if defined(CONFIG_PKVM_X86_GUEST) && defined(CONFIG_ACPI)
void pkvm_acpi_init(void);
#else
static inline void pkvm_acpi_init(void)
{
}
#endif

#endif /* _ASM_X86_PKVM_GUEST_H */
