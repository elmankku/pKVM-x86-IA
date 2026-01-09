/*
 * SPDX-License-Identifier: GPL-2.0
 */
#include <pkvm.h>
#include <asm/apicdef.h>
#include <asm/pkvm.h>
#include <asm/pgtable_types.h>
#include <capabilities.h>
#include <vmx/vmx_debug.h>
#include <linux/ramlog.h>
#include <linux/types.h>
#include <linux/pagewalk.h>
#include <linux/mm.h>
#include <asm/tlbflush.h>
#include <asm/pgtable.h>

#include "pkvm_hyp.h"
#include "bug.h"
#include "nested.h"
#include "cpu.h"
#include "ept.h"
#include "debug.h"
#include "mem_protect.h"

#define PAGE_PRESENT_MASK	0x1ULL
#define PAGE_HUGE_MASK		0x80ULL
#define PAGE_SIZE_MASK		0x0000000000000FFFULL
#define PAGE_SIZE_2MB_MASK	0x00000000001FFFFFULL
#define PAGE_SIZE_1GB_MASK	0x000000003FFFFFFFULL
#define PAGE_PFN_MASK		0x000FFFFFFFFFF000ULL
#define PAGE_PFN_MASK_2MB	0x000FFFFFFFE00000ULL
#define PAGE_PFN_MASK_1GB	0x000FFFFFC0000000ULL

#define EPT_ENTRY_READ_MASK	(1ULL << 0)
#define EPT_ENTRY_WRITE_MASK	(1ULL << 1)
#define EPT_ENTRY_EXECUTE_MASK	(1ULL << 2)
#define EPT_ENTRY_LARGE_PAGE_MASK (1ULL << 7)
#define EPTP_PHYS_ADDR_WIDTH_MASK  0x7ULL
#define EPTP_PHYS_ADDR_WIDTH_48BIT 0x6ULL
#define SHADOW_VCPU_ARRAY(vm) \
        ((struct shadow_vcpu_array *)((void *)(vm) + sizeof(struct pkvm_shadow_vm)))
#define SPTE_VMID_MASK (0xFULL << 12)

extern u64 __read_mostly shadow_mmio_value;
extern u64 __read_mostly shadow_mmio_mask;
extern pkvm_spinlock_t _host_ept_lock;

static unsigned long virt_to_phys_user(struct mm_struct *mm, unsigned long vaddr)
{
	pgd_t *pgd;
	p4d_t *p4d;
	pud_t *pud;
	pmd_t *pmd;
	pte_t *ptep;
	unsigned long pfn;
	unsigned long phys = INVALID_PAGE;

	rcu_read_lock();

	pgd = pgd_offset(mm, vaddr);
	if (pgd_none(*pgd) || pgd_bad(*pgd))
		goto out;

	p4d = p4d_offset(pgd, vaddr);
	if (p4d_none(*p4d) || p4d_bad(*p4d))
		goto out;

	pud = pud_offset(p4d, vaddr);
	if (pud_none(*pud) || pud_bad(*pud))
		goto out;

	pmd = pmd_offset(pud, vaddr);
	if (pmd_none(*pmd) || pmd_bad(*pmd))
		goto out;

	if (pmd_val(*pmd) & _PAGE_PSE) {
		phys = (pmd_val(*pmd) & PMD_MASK) | (vaddr & ~PMD_MASK);
		goto out;
	}

	ptep = pte_offset_kernel(pmd, vaddr);
	if (!ptep || !pte_present(*ptep))
		goto out;

	pfn = pte_pfn(*ptep);
	phys = (pfn << PAGE_SHIFT) | (vaddr & (PAGE_SIZE - 1));

out:
	rcu_read_unlock();
	return phys;
}

static u64 read_guest_phys(struct kvm_vcpu *vcpu, u64 phys, int stage)
{
	u64 vir;
	unsigned long hpa;
	struct pkvm_shadow_vm *vm;

	if ((vcpu->kvm->arch.pkvm.shadow_vm_handle == PKVM_HOST_HANDLE) ||
	    (stage == 1)) {
		vir = (u64)pkvm_phys_to_virt(phys);
		if (vir == ~0)
			return ~0ULL;
		return *(u64 *)vir;
	}

	vir = gfn_to_hva(vcpu->kvm, phys >> PAGE_SHIFT);
	if (kvm_is_error_hva(vir))
		return ~0ULL;

	vm = get_shadow_vm(vcpu->kvm->arch.pkvm.shadow_vm_handle);
	if (!vm || !vm->mm) {
		if (vm) put_shadow_vm(vm->shadow_vm_handle);
		return ~0ULL;
	}

	hpa = virt_to_phys_user(vm->mm, vir);
	put_shadow_vm(vm->shadow_vm_handle);

	if (hpa == INVALID_PAGE)
		return ~0ULL;

	vir = (u64)pkvm_phys_to_virt(hpa);
	if (vir == ~0)
		return ~0ULL;

	return *(u64 *)vir;
}

static inline bool is_mmio_spte(u64 spte)
{
	return (spte & shadow_mmio_mask) == shadow_mmio_value;
}

#if IS_ENABLED(CONFIG_PKVM_INTEL_VMXROOT_MMIO)

#include "q35.h"

static void __hyp_write_cr3(u64 cr3)
{
	asm volatile("mov %0,%%cr3": : "r" (cr3) : "memory");
}

static unsigned long __hyp_read_cr3(void)
{
	unsigned long cr3;

	asm volatile("mov %%cr3, %0" : "=r" (cr3));
	return cr3;
}

bool in_hyp_mode(void)
{
	if (__hyp_read_cr3() == pkvm_hyp->mmu->root_pa)
		return true;
	return false;
}

void init_guest_smm_dma(void *ptr)
{
	struct pkvm_shadow_vm *vm = ptr;

	mmget(current->mm);
	vm->mm = current->mm;
	memcpy(&vm->shares, &q35_dma_memmap, sizeof(q35_dma_memmap));
}

int check_donation_whitelist(u64 addr, size_t size)
{
	int i = 0;

	while (q35_dma_memmap[i].size != 0x0) {
		if ((addr >= q35_dma_memmap[i].gpa) &&
		   ((addr + size - 1) < (q35_dma_memmap[i].gpa +
					 q35_dma_memmap[i].size)))
			return 1;
		i++;
	}
	return 0;
}

int is_guest_ro(u64 addr, size_t size)
{
	int i = 0;

	while (q35_guest_ro[i].size != 0x0) {
                if ((addr >= q35_guest_ro[i].gpa) &&
                   ((addr + size - 1) < (q35_guest_ro[i].gpa +
					 q35_guest_ro[i].size)))
                        return 1;
                i++;
        }
	return 0;
}

unsigned long guest_virt_to_phys(struct kvm_vcpu *vcpu, u64 cr3, u64 virt_addr, u64 *ptep, int *l)
{
	u64 pml4i = (virt_addr >> 39) & 0x1FF;
	u64 pdpti = (virt_addr >> 30) & 0x1FF;
	u64 pdi   = (virt_addr >> 21) & 0x1FF;
	u64 pti   = (virt_addr >> 12) & 0x1FF;
	u64 pml4e, pdpte, pde, pte;

	/*
	 * We support only 64bit 4 level walks, for now. See the capabilities.h
	 */
	if (*l)
		*l = 4;
	pml4e = read_guest_phys(vcpu, (cr3 & PAGE_PFN_MASK) + pml4i * sizeof(u64), 0);
	*ptep = pml4e;
	if ((pml4e == ~0) || !(pml4e & PAGE_PRESENT_MASK))
		return ~0;

	if (*l)
		*l= 3;
	pdpte = read_guest_phys(vcpu, (pml4e & PAGE_PFN_MASK) + pdpti * sizeof(u64), 0);
	*ptep = pdpte;
	if ((pdpte == ~0) || !(pdpte & PAGE_PRESENT_MASK))
		return ~0;
	if (pdpte & PAGE_HUGE_MASK)
		return ((pdpte & PAGE_PFN_MASK_1GB) + (virt_addr & PAGE_SIZE_1GB_MASK));

	if (*l)
		*l = 2;
	pde = read_guest_phys(vcpu, (pdpte & PAGE_PFN_MASK) + pdi * sizeof(u64), 0);
	*ptep = pde;
	if ((pde == ~0) || !(pde & PAGE_PRESENT_MASK))
		return ~0;
	if (pde & PAGE_HUGE_MASK)
		return ((pde & PAGE_PFN_MASK_2MB) + (virt_addr & PAGE_SIZE_2MB_MASK));

	if (*l)
		*l = 1;
	pte = read_guest_phys(vcpu, (pde & PAGE_PFN_MASK) + pti * sizeof(u64), 0);
	*ptep = pte;
	if ((pte == ~0) || !(pte & PAGE_PRESENT_MASK))
		return ~0;

	return (pte & PAGE_PFN_MASK) + (virt_addr & PAGE_SIZE_MASK);
}

unsigned long pkvm_user_to_phys(struct kvm_vcpu *vcpu, unsigned long vaddr)
{
	struct shadow_vcpu_state *shadow_vcpu;

	shadow_vcpu = get_shadow_vcpu(vcpu->pkvm_shadow_vcpu_handle);
	if (!shadow_vcpu)
		BUG();

	return guest_virt_to_phys(vcpu, shadow_vcpu->vm->mm->pgd->pgd, vaddr, NULL, NULL);
}

static int hyp_check_owner(struct shadow_vcpu_state *shadow_vcpu, unsigned long addr, int len)
{
	unsigned long phys;
	int id;

	if (pkvm_is_share(shadow_vcpu->vm, addr, len))
		return 0;

	phys = virt_to_phys_user(shadow_vcpu->vm->mm, addr);
	if (phys == ~0)
		return -EINVAL;

	id = pkvm_page_owner(phys);
	PKVM_ASSERT(id == to_shadow_vm_handle(shadow_vcpu->shadow_vcpu_handle));

	return 0;
}

/*
 * Before acting on a page, verify the page owner. Each vm can only
 * manipulate its own by using the hyp mode.
 */
int __hyp_read_guest_page(struct kvm_vcpu *vcpu, struct kvm_memory_slot *slot,
			  gfn_t gfn, void *data, int offset, int len)
{
	struct shadow_vcpu_state *shadow_vcpu;
	unsigned long addr;
	int res;

	shadow_vcpu = get_shadow_vcpu(vcpu->pkvm_shadow_vcpu_handle);
	if (!shadow_vcpu)
		BUG();

	addr = gfn_to_hva_memslot_prot(slot, gfn, NULL);
	if (kvm_is_error_hva(addr))
		return -EFAULT;

	addr += offset;
	res = hyp_check_owner(shadow_vcpu, addr, len);
	if (res)
		return -EFAULT;

	__hyp_write_cr3(pkvm_virt_to_phys(shadow_vcpu->vm->mm->pgd));
	asm volatile("stac" ::: "memory");
	while (len--)
		*(u8 *)data++ = *(u8 *)addr++;
	asm volatile("clac" ::: "memory");
	__hyp_write_cr3(pkvm_hyp->mmu->root_pa);

	return 0;
}

int __hyp_vcpu_write_guest_page(struct kvm_vcpu *vcpu,
				struct kvm_memory_slot *slot, gfn_t gfn,
				const void *data, int offset, int len)
{
	struct shadow_vcpu_state *shadow_vcpu;
	unsigned long addr;
	int res;

	shadow_vcpu = get_shadow_vcpu(vcpu->pkvm_shadow_vcpu_handle);
	if (!shadow_vcpu)
		BUG();

	addr = gfn_to_hva_memslot(slot, gfn);
	if (kvm_is_error_hva(addr))
		return -EFAULT;

	addr += offset;
	res = hyp_check_owner(shadow_vcpu, addr, len);
	if (res)
		return -EFAULT;

	__hyp_write_cr3(pkvm_virt_to_phys(shadow_vcpu->vm->mm->pgd));
	asm volatile("stac" ::: "memory");
	while (len--)
		*(u8 *)addr++ = *(u8 *)data++;
	asm volatile("clac" ::: "memory");
	__hyp_write_cr3(pkvm_hyp->mmu->root_pa);

	mark_page_dirty_in_slot(vcpu->kvm, slot, gfn);
	return 0;
}

struct x86_emulate_ctxt *get_emulate_ctxt(struct kvm_vcpu *vcpu)
{
	struct shadow_vcpu_state *shadow_vcpu;

	shadow_vcpu = get_shadow_vcpu(vcpu->pkvm_shadow_vcpu_handle);
	return &shadow_vcpu->ctxt;
}
#else

struct x86_emulate_ctxt *get_emulate_ctxt(struct kvm_vcpu *vcpu)
{
	return vcpu->arch.emulate_ctxt;
}

#endif

/* KISS, minimal dependencies version of the EPT walk */

unsigned long guest_ept_lookup(struct kvm_vcpu *vcpu, u64 eptp, u64 gpa, u64 *spte, int *l)
{
	u64 pml4i = (gpa >> 39) & 0x1FF;
	u64 pdpti = (gpa >> 30) & 0x1FF;
	u64 pdi   = (gpa >> 21) & 0x1FF;
	u64 pti   = (gpa >> 12) & 0x1FF;
	u64 pml4e, pdpte, pde, pte, paw;

	paw = eptp & EPTP_PHYS_ADDR_WIDTH_MASK;
	if ((paw != 0) && (paw != EPTP_PHYS_ADDR_WIDTH_48BIT))
		BUG();

	if (l)
		*l = 4;
	pml4e = read_guest_phys(vcpu, (eptp & PAGE_PFN_MASK) + pml4i * sizeof(u64), 1);
	if (spte)
		*spte = pml4e;
	if ((pml4e == ~0) || !(pml4e & EPT_ENTRY_READ_MASK))
		return ~0;

	if (l)
		*l = 3;
	pdpte = read_guest_phys(vcpu, (pml4e & PAGE_PFN_MASK) + pdpti * sizeof(u64), 1);
	if (spte)
		*spte = pdpte;
	if ((pdpte == ~0) || !(pdpte & EPT_ENTRY_READ_MASK))
		return ~0;
	if (pdpte & EPT_ENTRY_LARGE_PAGE_MASK)
		return ((pdpte & PAGE_PFN_MASK_1GB) + (gpa & PAGE_SIZE_1GB_MASK));

	if (l)
		*l = 2;
	pde = read_guest_phys(vcpu, (pdpte & PAGE_PFN_MASK) + pdi * sizeof(u64), 1);
	if (spte)
		*spte = pde;
	if ((pde == ~0) || !(pde & EPT_ENTRY_READ_MASK))
		return ~0;
	if (pde & EPT_ENTRY_LARGE_PAGE_MASK)
		return ((pde & PAGE_PFN_MASK_2MB) + (gpa & PAGE_SIZE_2MB_MASK));

	if (l)
		*l = 1;
	pte = read_guest_phys(vcpu, (pde & PAGE_PFN_MASK) + pti * sizeof(u64), 1);
	if (spte)
		*spte = pte;
	if ((pte == ~0) || !(pte & EPT_ENTRY_READ_MASK))
		return ~0;
	return ((pte & PAGE_PFN_MASK) + (gpa & PAGE_SIZE_MASK));
}

/* The original pkvm walk. I prefer the for-dummies version above ^ */

unsigned long guest_pgt_lookup(struct kvm_vcpu *vcpu, unsigned long vaddr)
{
	struct shadow_vcpu_state *shadow_vcpu;
	struct pkvm_shadow_vm *vm;
	struct shadow_ept_desc *desc;
	struct pkvm_pgtable *sept;
	unsigned long phys;
	u64 gprot;
	int level;

	if (vaddr % PAGE_SIZE)
		return ~0;

	shadow_vcpu = get_shadow_vcpu(vcpu->pkvm_shadow_vcpu_handle);
	if (!shadow_vcpu)
		BUG();

	vm = shadow_vcpu->vm;
	desc = &vm->sept_desc;
	sept = &desc->sept;

	pkvm_pgtable_lookup(sept, vaddr, &phys, &gprot, &level);
	return phys;
}

/*
 * DEBUGGER EXTENSIONS BELOW - NOT FOR CODE USE
 */
#if IS_ENABLED(CONFIG_PKVM_INTEL_DEBUG)

struct ept_dump_state {
	u64 gpa_start;
	u64 hpa_start; /* INVALID_PAGE if unmapped */
	u64 size;
	u64 spte;
	u64 last_hpa;
	bool active;
};

/*
 * Helper to find the PTE/PMD/PUD for the current stack address in hypervisor
 * page tables and clear the NX bit. This allows GDB to call functions
 * by pushing a return address onto the stack.
 *
 */
int pkvm_gdb_enable_stack_exec(void)
{
	unsigned long vaddr;
	pgd_t *pgd;
	p4d_t *p4d;
	pud_t *pud;
	pmd_t *pmd;
	pte_t *ptep;
	int err = 0;

	asm volatile("mov %%rsp, %0" : "=r" (vaddr));

	pgd = (pgd_t *)__va(read_cr3_pa()) + pgd_index(vaddr);

	if (pgd_none(*pgd) || pgd_bad(*pgd)) goto fault;
	p4d = p4d_offset(pgd, vaddr);
	if (p4d_none(*p4d) || p4d_bad(*p4d)) goto fault;
	pud = pud_offset(p4d, vaddr);

	if (pud_val(*pud) & _PAGE_PSE) {
		pud_t new_pud;

		if (!(pud_val(*pud) & _PAGE_NX))
			goto out_success;

		new_pud = pud_clear_flags(*pud, _PAGE_NX);
		set_pud(pud, new_pud);
		goto flush_tlb;
	}

	if (pud_none(*pud) || pud_bad(*pud)) goto fault;
	pmd = pmd_offset(pud, vaddr);

	if (pmd_val(*pmd) & _PAGE_PSE) {
		pmd_t new_pmd;

		if (!(pmd_val(*pmd) & _PAGE_NX))
			goto out_success;

		new_pmd = pmd_clear_flags(*pmd, _PAGE_NX);
		set_pmd(pmd, new_pmd);
		goto flush_tlb;
	}

	if (pmd_none(*pmd) || pmd_bad(*pmd)) goto fault;

	ptep = pte_offset_kernel(pmd, vaddr);
	if (!ptep || !pte_present(*ptep)) goto fault;

	if (!(pte_val(*ptep) & _PAGE_NX))
		goto out_success;

	set_pte(ptep, pte_clear_flags(*ptep, _PAGE_NX));

flush_tlb:
	flush_tlb_one_kernel(vaddr);

out_success:
	pr_err("pkvm debug: WARNING - NX IS NOW DISABLED FOR DEBUGGING\n");
	return 0;

fault:
	err = -EFAULT;
	pr_err("pkvm debug: Failed to make stack executable at vaddr 0x%lx (err=%d)\n",
	       vaddr, err);
	return err;
}

static bool mapped_attrs_match(u64 spte1, u64 spte2)
{
	const u64 mask = 0x7ULL | SUPPRESS_VE;

	if ((spte1 & mask) != (spte2 & mask))
		return false;
	if (is_mmio_spte(spte1) != is_mmio_spte(spte2))
		return false;
	return true;
}

static bool unmapped_attrs_match(u64 spte1, u64 spte2)
{
	return (spte1 & SPTE_VMID_MASK) == (spte2 & SPTE_VMID_MASK);
}

static void dump_region(struct ept_dump_state *state)
{
	if (!state->active || state->size == 0)
		return;

	if (state->hpa_start != INVALID_PAGE) {
		/* Mapped Region */
		u64 perms = state->spte & 0x7;
		bool mmio = is_mmio_spte(state->spte);
		bool sve = state->spte & SUPPRESS_VE;

		pkvm_info("0x%016llx -> 0x%016llx %llu %llx %s %s\n",
			  state->gpa_start, state->hpa_start, state->size, perms,
			  sve ? "SVE" : "VE", mmio ? "MMIO" : "MEMORY");
	} else {
		int vmid = (int)(state->spte >> 12) & 0xF;

		if (vmid > 0) {
			pkvm_info("0x%016llx unmapped, %llu bytes migrated to vmid: %d\n",
				  state->gpa_start, state->size, vmid);
		}
	}

	state->active = false;
	state->size = 0;
}

static int __print_guest_maps(struct kvm_vcpu *vcpu, dtype_t table)
{
	struct kvm_memslots *slots;
	struct kvm_memory_slot *slot;
	struct pkvm_shadow_vm *vm = NULL;
	int bkt, mapped_count = 0;
	struct ept_dump_state state = { 0 };
	u64 eptp = 0;

	if (vcpu->kvm->arch.pkvm.shadow_vm_handle != PKVM_HOST_HANDLE) {
		vm = get_shadow_vm(vcpu->kvm->arch.pkvm.shadow_vm_handle);
		if (!vm) {
			pkvm_err("No such vm 0x%x\n",
				 vcpu->kvm->arch.pkvm.shadow_vm_handle);
			return -ENOENT;
		}
	}

	switch (table) {
	case d_s:
		if (vcpu->kvm->arch.pkvm.shadow_vm_handle == PKVM_HOST_HANDLE)
			eptp = pkvm_hyp->host_vm.ept->root_pa;
		else
			eptp = vm->sept_desc.sept.root_pa;
		pkvm_info("VCPU 0x%llx EPTP 0x%llx shadow mappings:\n",
			  (u64)vcpu, eptp);
		break;
	case d_k:
		if (vcpu->arch.mmu) {
			eptp = vcpu->arch.mmu->root.hpa;
			pkvm_info("VCPU 0x%llx EPTP 0x%llx kvm mappings:\n",
				  (u64)vcpu, eptp);
		}
		break;
	case d_p:
		if (vm) {
			eptp = vm->pgstate_pgt.root_pa;
			pkvm_info("VCPU 0x%llx EPTP 0x%llx pgstate mappings:\n",
				  (u64)vcpu, eptp);
		}
		break;
	default:
		break;
	}

	if (vm)
		put_shadow_vm(vm->shadow_vm_handle);

	if (!eptp) {
		pkvm_err("VCPU 0x%llx ept not set for requested table type\n", (u64)vcpu);
		return -EINVAL;
	}

	slots = kvm_memslots(vcpu->kvm);

	kvm_for_each_memslot(slot, bkt, slots) {
		u64 gpa_iter, slot_end;

		if (!slot->npages)
			continue;

		gpa_iter = slot->base_gfn << PAGE_SHIFT;
		slot_end = gpa_iter + (slot->npages * PAGE_SIZE);

		pr_info("Guest slot 0x%llx - 0x%llx\n", gpa_iter, slot_end - 1);

		dump_region(&state);

		while (gpa_iter < slot_end) {
			u64 base_hpa, spte, current_4k_hpa;
			int level;
			bool mergeable = false;
			bool is_mapped;

			base_hpa = guest_ept_lookup(vcpu, eptp, gpa_iter, &spte, &level);
			is_mapped = (base_hpa != INVALID_PAGE);

			if (is_mapped) mapped_count++;

			if (!is_mapped) {
				current_4k_hpa = INVALID_PAGE;
			} else if (level == 1) {
				current_4k_hpa = base_hpa;
			} else if (level > 1 && level <= 3) {
				u64 mask = (level == 2) ? (PMD_SIZE - 1) : (PUD_SIZE - 1);
				current_4k_hpa = (base_hpa & ~mask) | (gpa_iter & mask);
			} else {
				WARN_ONCE(1, "Invalid EPT level %d at GPA %llx", level, gpa_iter);
				current_4k_hpa = INVALID_PAGE;
				is_mapped = false;
			}

			if (state.active) {
				bool was_mapped = (state.hpa_start != INVALID_PAGE);

				if (!was_mapped && !is_mapped) {
					/* Merge two unmapped if VMID markers match */
					if (unmapped_attrs_match(state.spte, spte))
						mergeable = true;
				} else if (was_mapped && is_mapped) {
					/* Merge two mapped if attrs match AND physically contiguous */
					if (mapped_attrs_match(state.spte, spte) &&
					    current_4k_hpa == state.last_hpa + PAGE_SIZE)
						mergeable = true;
				}
			}

			if (mergeable) {
				state.size += PAGE_SIZE;
			} else {
				dump_region(&state);
				state.active = true;
				state.gpa_start = gpa_iter;
				state.hpa_start = current_4k_hpa;
				state.spte = spte;
				state.size = PAGE_SIZE;
			}

			state.last_hpa = current_4k_hpa;
			gpa_iter += PAGE_SIZE;
		}
		dump_region(&state);
	}

	return mapped_count;
}

__maybe_unused int print_guest_maps(struct kvm_vcpu *vcpu, dtype_t dt)
{
	if (dt == d_a) {
		__print_guest_maps(vcpu, d_s);
		__print_guest_maps(vcpu, d_k);
		__print_guest_maps(vcpu, d_p);
		return 0;
	}
	return __print_guest_maps(vcpu, dt);
}

__maybe_unused int print_host_maps(void)
{
	return print_guest_maps(&pkvm_hyp->host_vm.host_vcpus[0]->vmx.vcpu, d_s);
}

__maybe_unused int print_guest_maps_by_handle(int shadow_vm_handle)
{
	struct pkvm_shadow_vm *vm = get_shadow_vm(shadow_vm_handle);
	struct shadow_vcpu_ref *vcpu_ref;
	int m1, m2, m3;

	if (!vm) {
		pkvm_err("No such vm 0x%x\n", shadow_vm_handle);
		return -ENOENT;
	}

	vcpu_ref = &SHADOW_VCPU_ARRAY(vm)->ref[0];
	if (!vcpu_ref || !vcpu_ref->vcpu) {
		pkvm_err("VM has no attached vcpus\n");
		put_shadow_vm(vm->shadow_vm_handle);
		return -EINVAL;
	}

	m1 = print_guest_maps(vcpu_ref->vcpu->gvcpu, d_s);
	m2 = print_guest_maps(vcpu_ref->vcpu->gvcpu, d_k);
	m3 = print_guest_maps(vcpu_ref->vcpu->gvcpu, d_p);
	pr_info("Total %d shadow, %d kvm and %d pgstate mappings\n", m1, m2, m3);

	put_shadow_vm(vm->shadow_vm_handle);
	return 0;
}

#endif // CONFIG_PKVM_INTEL_DEBUG
