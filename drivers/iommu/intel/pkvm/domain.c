// SPDX-License-Identifier: GPL-2.0
/* Copyright(c) 2026 Google. */


#include "pkvm_iommu.h"
#include <linux/hashtable.h>
#include <asm/pkvm_spinlock.h>
#include "pkvm.h"
#include "pkvm/debug.h"
#include "pkvm/memory.h"
#include "pkvm/vmx/ept.h"
#include "../iommu.h"

/*
 * TODO: Make this a dynamic value.
 */
#define MAX_IOMMU_DOMAIN_NUM	128
static DEFINE_HASHTABLE(iommu_domain_hasht, 8);
static DECLARE_BITMAP(iommu_domains_bitmap, MAX_IOMMU_DOMAIN_NUM);
static struct dmar_domain iommu_domains[MAX_IOMMU_DOMAIN_NUM];
static DEFINE_PKVM_SPINLOCK(iommu_domain_lock);

/*
 * Passthrough domain for implementing passthrough (identity) mode for the host,
 * signified by the default DID (FLPT_DEFAULT_DID). A real passthrough mode
 * (no translation) would allow devices to access all physical memory. So model
 * passthrough mode as a second-stage domain backed by the host EPT instead.
 */
struct dmar_domain pt_domain;

void init_pt_domain(void)
{
	INIT_LIST_HEAD(&pt_domain.cache_tags);
	pkvm_spin_lock_init(&pt_domain.cache_lock);
	pt_domain.qi_batch = &pt_domain._qi_batch;
	pt_domain.pgd = __pkvm_va(pkvm_host_ept_root());
	pt_domain.agaw = level_to_agaw(pkvm_host_ept_level());
}

static struct dmar_domain *__pkvm_get_iommu_domain_locked(void *pgd, bool inc_ref)
{
	struct dmar_domain *domain;

	hash_for_each_possible(iommu_domain_hasht, domain, hnode, (u64)pgd) {
		if (domain->pgd != pgd)
			continue;

		if (inc_ref && WARN_ON_ONCE(!atomic_inc_not_zero(&domain->refcount)))
			return NULL;

		return domain;
	}

	return NULL;
}

static struct dmar_domain *__pkvm_get_iommu_domain(void *pgd)
{
	struct dmar_domain *domain;

	pkvm_spin_lock(&iommu_domain_lock);
	domain = __pkvm_get_iommu_domain_locked(pgd, true);
	pkvm_spin_unlock(&iommu_domain_lock);

	return domain;
}

/* Domain operations requested by the host must not access a VM's tables. */
static struct dmar_domain *get_host_iommu_domain(void *pgd)
{
	struct dmar_domain *domain = __pkvm_get_iommu_domain(pgd);

	if (domain && domain->owner_vm) {
		pkvm_put_iommu_domain(domain);
		return NULL;
	}
	return domain;
}

/*
 * Retrieve the domain without incrementing refcount.
 * This is useful when there is a refcount on the domain which is guaranteed
 * to be >1 (at least one reference).
 */
static struct dmar_domain *__pkvm_get_iommu_domain_noref(void *pgd)
{
	struct dmar_domain *domain;

	pkvm_spin_lock(&iommu_domain_lock);
	domain = __pkvm_get_iommu_domain_locked(pgd, false);
	/*
	 * pgd passed in here is derived from a valid context/pasid entry.
	 * Hence it's a pKVM bug if this pgd can't resolve to a domain.
	 */
	BUG_ON(!domain || atomic_read(&domain->refcount) <= 1);
	pkvm_spin_unlock(&iommu_domain_lock);

	return domain;
}

/*
 * Check the domain properties that affect how an IOMMU walks and caches the
 * domain page tables. A domain may be shared by multiple IOMMUs, but only if
 * each IOMMU is compatible with the properties selected at allocation time.
 */
static bool iommu_domain_compatible(struct intel_iommu *iommu,
				    struct dmar_domain *domain)
{
	int addr_width;

	if (domain->agaw < 0 || domain->agaw > level_to_agaw(5))
		return false;

	if (domain->use_first_level) {
		if (!sm_supported(iommu) || !ecap_flts(iommu->ecap))
			return false;

		if ((domain->domain.type == IOMMU_DOMAIN_NESTED) !=
		    pkvm_nested_enabled(iommu))
			return false;

		if (domain->agaw > iommu->agaw)
			return false;
		addr_width = agaw_to_width(iommu->agaw);
	} else {
		addr_width = agaw_to_width(domain->agaw);
		/* A larger supported depth does not imply support for this depth. */
		if (!(cap_sagaw(iommu->cap) & BIT(domain->agaw)))
			return false;
		if (sm_supported(iommu) && !ecap_slts(iommu->ecap))
			return false;

		if (cap_caching_mode(iommu->cap) && !domain->iotlb_sync_map)
			return false;
	}

	if (domain->iommu_superpage >
	    iommu_superpage_capability(iommu, domain->use_first_level))
		return false;

	/* A domain that always flushes also works with a coherent walker. */
	if (domain->iommu_coherency &&
	    !iommu_paging_structure_coherency(iommu))
		return false;

	if (addr_width > cap_mgaw(iommu->cap))
		addr_width = cap_mgaw(iommu->cap);
	if (domain->gaw > addr_width)
		return false;

	return true;
}

struct dmar_domain *pkvm_get_iommu_domain(void *pgd, u16 did,
					  struct intel_iommu *iommu)
{
	struct dmar_domain *domain;

	if (did == FLPT_DEFAULT_DID)
		return &pt_domain;

	domain = get_host_iommu_domain(pgd);

	if (domain && (!pkvm_iommu_is_valid_did(iommu, domain, did) ||
		       !iommu_domain_compatible(iommu, domain))) {
		pkvm_err("%s: invalid DID %u or incompatible domain[pgd:%p] for iommu%d\n",
			 __func__, did, pgd, iommu->seq_id);
		pkvm_put_iommu_domain(domain);
		domain = NULL;
	}

	return domain;
}

struct dmar_domain *pkvm_get_iommu_domain_noref(void *pgd, u16 did)
{
	if (did == FLPT_DEFAULT_DID)
		return &pt_domain;

	return __pkvm_get_iommu_domain_noref(pgd);
}

void pkvm_put_iommu_domain(struct dmar_domain *domain)
{
	if (domain == &pt_domain)
		return;

	WARN_ON_ONCE(atomic_dec_if_positive(&domain->refcount) <= 0);
}

static int refill_domain_memcache(struct dmar_domain *domain,
				  struct pkvm_memcache *host_mc)
{
	struct pkvm_memcache *mc = &domain->mc;
	unsigned long min_pages;

	/*
	 * The host expects pKVM to drain the memcache fully and use it until
	 * the domain is freed, as the host itself doesn't store the memcache
	 * in any persistent data structure. This will not result in the
	 * hypervisor's memcache growing endlessly, since the host only
	 * provides a memcache if the hypervisor's memcache doesn't already
	 * have enough pages.
	 */
	min_pages = mc->count + READ_ONCE(host_mc->count);
	return pkvm_refill_memcache(mc, min_pages, host_mc);
}

static void free_domain_memcache(struct dmar_domain *domain,
				 struct pkvm_memcache *teardown_mc)
{
	struct pkvm_memcache *mc = &domain->mc;

	while (mc->count) {
		void *addr = pop_pkvm_memcache_page(mc, pkvm_phys_to_virt);

		push_pkvm_memcache_page(teardown_mc, addr, pkvm_virt_to_host_gpa);
		pkvm_hyp_donate_host(__pkvm_pa(addr), VTD_PAGE_SIZE, false);
	}
}

int pkvm_free_iommu_domain(u64 pgd_gpa, struct pkvm_memcache *teardown_mc,
			   struct pkvm_vm *owner)
{
	void *pgd = pkvm_host_gpa_to_virt(pgd_gpa);
	struct dmar_domain *domain;

	pkvm_spin_lock(&iommu_domain_lock);

	domain = __pkvm_get_iommu_domain_locked(pgd, false);
	if (!domain) {
		pkvm_spin_unlock(&iommu_domain_lock);
		pkvm_err("%s: no domain exist for pgd: %p\n", __func__, pgd);
		return -EINVAL;
	}

	if (domain->owner_vm != owner) {
		pkvm_spin_unlock(&iommu_domain_lock);
		return -EPERM;
	}

	if (atomic_cmpxchg(&domain->refcount, 1, 0) != 1) {
		pkvm_err("%s: domain[pgd:%p] has users, refcount %d\n",
			 __func__, domain->pgd, atomic_read(&domain->refcount));
		pkvm_spin_unlock(&iommu_domain_lock);
		return -EBUSY;
	}

	/*
	 * Remove the domain from the hash list while still holding the lock,
	 * to prevent someone else from getting this domain while freeing it.
	 */
	hash_del(&domain->hnode);

	pkvm_spin_unlock(&iommu_domain_lock);

	if (domain->domain.type != IOMMU_DOMAIN_NESTED) {
		/*
		 * Cover every root entry's full span so the unmap walker also frees
		 * child tables when GAW covers only part of a root entry.
		 */
		if (domain->agaw != -1)
			domain_unmap(domain, 0,
				     DOMAIN_MAX_PFN(agaw_to_width(domain->agaw)), NULL);

		free_domain_memcache(domain, teardown_mc);
		/*
		 * pgd was not allocated through memcache, but its safe to return to
		 * memcache as the teardown mc frees it the same way host driver frees
		 * the pages.
		 */
		push_pkvm_memcache_page(teardown_mc, domain->pgd, pkvm_virt_to_host_gpa);
		pkvm_hyp_donate_host(__pkvm_pa(domain->pgd), VTD_PAGE_SIZE, false);
	}

	pkvm_dbg("%s: freeing domain[pgd: %p], freed pages: %lu\n",
		 __func__, domain->pgd, teardown_mc->count);

	pkvm_spin_lock(&iommu_domain_lock);
	__clear_bit(domain->index, iommu_domains_bitmap);
	memset(domain, 0, sizeof(struct dmar_domain));
	pkvm_spin_unlock(&iommu_domain_lock);

	return 0;
}

struct dmar_domain *pkvm_alloc_iommu_domain(struct alloc_domain_data *data,
					    bool need_iotlb_sync_map,
					    struct pkvm_vm *owner_vm)
{
	void *pgd = pkvm_host_gpa_to_virt(data->pgd_gpa);
	struct dmar_domain *domain;
	unsigned long index;

	pkvm_spin_lock(&iommu_domain_lock);
	domain = __pkvm_get_iommu_domain_locked(pgd, false);
	if (unlikely(domain)) {
		pkvm_spin_unlock(&iommu_domain_lock);
		return ERR_PTR(-EEXIST);
	}

	index = find_first_zero_bit(iommu_domains_bitmap, MAX_IOMMU_DOMAIN_NUM);
	if (index < MAX_IOMMU_DOMAIN_NUM) {
		__set_bit(index, iommu_domains_bitmap);
		domain = &iommu_domains[index];
		INIT_LIST_HEAD(&domain->cache_tags);
		domain->owner_vm = owner_vm;
		domain->pgd = pgd;
		domain->use_first_level = data->use_first_level;
		domain->iommu_superpage = data->iommu_superpage;
		domain->iommu_coherency = data->iommu_coherency;
		domain->iotlb_sync_map = need_iotlb_sync_map;
		domain->agaw = data->agaw;
		domain->gaw = data->gaw;
		domain->max_addr = data->max_addr;
		domain->index = index;
		domain->qi_batch = &domain->_qi_batch;
		if (data->pkvm_nested) {
			domain->domain.type = IOMMU_DOMAIN_NESTED;
			domain->s2_domain = &pt_domain;
			domain->s1_cfg.pgtbl_addr = pkvm_host_gpa_to_phys(data->pgd_gpa);
			domain->s1_cfg.addr_width = agaw_to_width(domain->agaw);
		}
		atomic_set(&domain->refcount, 1);
		pkvm_spin_lock_init(&domain->lock);
		pkvm_spin_lock_init(&domain->cache_lock);
		hash_add(iommu_domain_hasht, &domain->hnode, (u64)pgd);
		pkvm_dbg("%s: allocated domain pgd: %p\n", __func__, pgd);
	} else {
		domain = ERR_PTR(-ENOMEM);
	}
	pkvm_spin_unlock(&iommu_domain_lock);

	return domain;
}

static int iommu_domain_map(struct domain_map_data *data,
			    struct pkvm_vm *owner)
{
	struct dmar_domain *domain;
	u64 iova, phys, size, end;
	int ret;

	/* Check for possible overflows that may have security implications */
	if (check_shl_overflow(data->iov_pfn, VTD_PAGE_SHIFT, &iova))
		return -EINVAL;
	if (check_shl_overflow(data->phys_pfn, VTD_PAGE_SHIFT, &phys))
		return -EINVAL;
	if (check_mul_overflow(data->nr_pages, VTD_PAGE_SIZE, &size))
		return -EINVAL;
	if (check_add_overflow(iova, size, &end))
		return -EINVAL;
	if (check_add_overflow(phys, size, &end))
		return -EINVAL;

	domain = __pkvm_get_iommu_domain(pkvm_host_gpa_to_virt(data->pgd_gpa));
	if (!domain) {
		pkvm_err("%s: failed to get the domain [pgd:%llx]\n",
			 __func__, data->pgd_gpa);
		return -EINVAL;
	}

	if (domain->domain.type == IOMMU_DOMAIN_NESTED) {
		pkvm_err("%s: map not supported for nested domain [pgd:%llx]\n",
			 __func__, data->pgd_gpa);
		ret = -EINVAL;
		goto out_put_domain;
	}

	pkvm_spin_lock(&domain->lock);
	if (domain->owner_vm != owner) {
		ret = -EPERM;
		goto out_unlock;
	}
	if (domain->agaw < 0) {
		ret = -ENODEV;
		goto out_unlock;
	}
	/* AGAW describes the tree; GAW may impose a smaller DMA aperture. */
	if (owner && iova + size - 1 > __DOMAIN_MAX_ADDR(domain->gaw)) {
		ret = -EINVAL;
		goto out_unlock;
	}
	if (data->mc.count) {
		ret = refill_domain_memcache(domain, &data->mc);
		if (ret) {
			pkvm_err("%s: failed to refill memcache for domain[pgd: %p] (err=%d)\n",
				 __func__, domain->pgd, ret);
			goto out_unlock;
		}
	}
	if (domain->mc.count < __pkvm_pgtable_max_pages(data->nr_pages)) {
		ret = -ENOMEM;
		goto out_unlock;
	}

	ret = domain_map(domain, data->iov_pfn, data->phys_pfn,
			 data->nr_pages, data->prot, 0);

out_unlock:
	pkvm_spin_unlock(&domain->lock);
out_put_domain:
	pkvm_put_iommu_domain(domain);

	return ret;
}

int pkvm_iommu_domain_map(struct domain_map_data *in, struct domain_map_data *out)
{
	int ret = iommu_domain_map(in, NULL);

	*out = *in;
	return ret;
}

int pkvm_iommu_domain_unmap(u64 pgd_gpa, u64 start_pfn, u64 last_pfn)
{
	struct dmar_domain *domain;
	int ret = 0;

	domain = get_host_iommu_domain(pkvm_host_gpa_to_virt(pgd_gpa));
	if (!domain) {
		pkvm_err("%s, failed to get the domain [pgd:%llx]\n",
			 __func__, pgd_gpa);
		return -EINVAL;
	}

	if (domain->domain.type == IOMMU_DOMAIN_NESTED) {
		pkvm_err("%s: unmap not supported for nested domain [pgd:%llx]\n",
			 __func__, pgd_gpa);
		ret = -EINVAL;
		goto out_put_domain;
	}

	pkvm_spin_lock(&domain->lock);
	domain_unmap(domain, start_pfn, last_pfn, NULL);
	pkvm_spin_unlock(&domain->lock);

out_put_domain:
	pkvm_put_iommu_domain(domain);

	return ret;
}

/* Flush IOMMU caches for the domain identified by the given pgd_gpa. */
int pkvm_iommu_domain_flush(u64 pgd_gpa, u64 start, u64 last, bool ih)
{
	struct dmar_domain *domain;

	if (start > last) {
		pkvm_err("%s: invalid flush range [%llx, %llx]\n",
			 __func__, start, last);
		return -EINVAL;
	}

	domain = get_host_iommu_domain(pkvm_host_gpa_to_virt(pgd_gpa));
	if (!domain) {
		pkvm_err("%s, failed to get the domain [pgd:%llx]\n",
			 __func__, pgd_gpa);
		return -EINVAL;
	}

	/*
	 * Guard against integer overflow and shift-by-64 UB on huge ranges in
	 * calculate_psi_aligned_address() and qi_desc_piotlb(). With newer
	 * kernels this check is not needed anymore, since commits e36ee89679f4
	 * ("iommu/vt-d: Pass size_order to qi_desc_piotlb() not npages") and
	 * 9785df3fd670 ("iommu/vt-d: Simplify calculate_psi_aligned_address()").
	 */
	if (last > domain->max_addr && !(start == 0 && last == ULONG_MAX)) {
		pkvm_err("%s: invalid flush range [%llx, %llx] for domain [pgd:%llx, max_addr:%llx]\n",
			 __func__, start, last, pgd_gpa, domain->max_addr);
		pkvm_put_iommu_domain(domain);
		return -EINVAL;
	}

	cache_tag_flush_range(domain, start, last, ih);
	pkvm_put_iommu_domain(domain);

	return 0;
}

int pkvm_iommu_domain_alloc_did(u64 phys, u64 pgd_gpa)
{
	struct intel_iommu *iommu = iommu_from_phys(phys);
	struct dmar_domain *domain;
	int ret;

	pkvm_warn("%s: phys=%llx pgd_gpa=0x%llx\n", __func__, phys, pgd_gpa);

	if (!iommu) {
		pkvm_err("%s: failed to get the iommu [phys:%llx]\n", __func__,
			 phys);
		return -EINVAL;
	}

	domain = get_host_iommu_domain(pkvm_host_gpa_to_virt(pgd_gpa));
	if (!domain) {
		pkvm_err("%s: failed to get the domain [pgd:%llx]\n", __func__,
			 pgd_gpa);
		return -EINVAL;
	}

	if (!iommu_domain_compatible(iommu, domain)) {
		pkvm_err("%s: domain[pgd:%llx] is incompatible with iommu%d\n", __func__, pgd_gpa, iommu->seq_id);
		pkvm_put_iommu_domain(domain);
		return -EINVAL;
	}

	ret = pkvm_iommu_alloc_did(iommu, domain);
	if (ret < 0) {
		pkvm_put_iommu_domain(domain);
	}

	return ret;
}

/* Caller holds a VM reference throughout acquisition or release. */
static struct dmar_domain *get_guest_iommu_domain(struct pkvm_vm *vm)
{
	struct dmar_domain *domain;

	if (!pkvm_is_protected_vm(&vm->kvm))
		return ERR_PTR(-EPERM);
	if (!vm->dma_domain)
		return ERR_PTR(-ENODEV);

	domain = __pkvm_get_iommu_domain(vm->dma_domain->pgd);
	if (!domain)
		return ERR_PTR(-ENODEV);
	if (domain->owner_vm != vm) {
		pkvm_put_iommu_domain(domain);
		return ERR_PTR(-EPERM);
	}
	return domain;
}

/* Caller holds devices_lock across attachment and assignment publication. */
int pkvm_guest_iommu_attach_device(struct pkvm_vm *vm,
				   struct intel_iommu *iommu, u16 did, u16 bdf)
{
	struct dmar_domain *domain = get_guest_iommu_domain(vm);
	int ret;

	if (IS_ERR(domain))
		return PTR_ERR(domain);

	pkvm_spin_lock(&domain->lock);
	if (!iommu_domain_compatible(iommu, domain))
		ret = -EINVAL;
	else
		ret = pkvm_iommu_replace_lm_context(domain, iommu, did, bdf);
	pkvm_spin_unlock(&domain->lock);
	if (ret)
		pkvm_put_iommu_domain(domain);
	/* Success transfers this reference to the hardware binding. */
	return ret;
}

/* Caller holds devices_lock; host context changes cannot race this sequence. */
int pkvm_guest_iommu_detach_device(struct pkvm_vm *vm,
				   struct intel_iommu *iommu, u16 did, u16 bdf)
{
	struct device_domain_info info = {
		.iommu = iommu, .bus = PCI_BUS_NUM(bdf), .devfn = bdf & 0xff,
	};
	struct dmar_domain *domain = get_guest_iommu_domain(vm);
	struct dmar_domain *binding;
	struct context_entry *context;
	int ret = 0;

	if (IS_ERR(domain))
		return PTR_ERR(domain);
	if (sm_supported(iommu)) {
		ret = -EOPNOTSUPP;
		goto put_domain;
	}

	pkvm_spin_lock(&domain->lock);
	pkvm_spin_lock(&iommu->lock);
	context = iommu_context_addr(iommu, info.bus, info.devfn, 0);
	/* Allow a teardown retry after the context was already cleared. */
	if (context && context_present(context) &&
	    (context_domain_id(context) != did ||
	     (context->lo & VTD_PAGE_MASK) != __pkvm_pa(domain->pgd)))
		ret = -EPERM;
	pkvm_spin_unlock(&iommu->lock);

	if (!ret) {
		domain_context_clear_one(&info, info.bus, info.devfn, &binding);
		if (binding)
			pkvm_put_iommu_domain(binding);
	}
	pkvm_spin_unlock(&domain->lock);
put_domain:
	pkvm_put_iommu_domain(domain);
	return ret;
}

/* Reserve one device's use of a DID; this does not program hardware. */
int pkvm_guest_iommu_get_did(struct pkvm_vm *vm, struct intel_iommu *iommu)
{
	struct dmar_domain *domain = get_guest_iommu_domain(vm);
	int ret;

	if (IS_ERR(domain))
		return PTR_ERR(domain);

	ret = pkvm_iommu_get_did(iommu, domain);
	if (ret < 0)
		pkvm_put_iommu_domain(domain);
	return ret;
}

int pkvm_guest_iommu_put_did(struct pkvm_vm *vm, struct intel_iommu *iommu,
			   u16 did)
{
	struct dmar_domain *domain = get_guest_iommu_domain(vm);
	int ret;

	if (IS_ERR(domain))
		return PTR_ERR(domain);

	ret = pkvm_iommu_free_did(iommu, domain, did);
	pkvm_put_iommu_domain(domain);
	/* Other devices may still hold this DID; releasing our use succeeded. */
	return ret < 0 ? ret : 0;
}

/*
 * Caller holds a VM reference. Configure the format once; later assignments
 * must fit that format. This does not allocate a DID or program device entries.
 */
int pkvm_guest_iommu_configure_domain(struct pkvm_vm *vm,
				    struct intel_iommu *iommu)
{
	struct dmar_domain *domain;
	int agaw, gaw, ret = 0;

	if (!iommu || !vm->dma_domain)
		return -ENODEV;
	if (!pkvm_is_protected_vm(&vm->kvm))
		return -EPERM;

	domain = __pkvm_get_iommu_domain(vm->dma_domain->pgd);
	if (!domain)
		return -ENODEV;

	pkvm_spin_lock(&domain->lock);
	if (domain->owner_vm != vm) {
		ret = -EPERM;
		goto unlock;
	}
	if (domain->agaw >= 0) {
		if (!iommu_domain_compatible(iommu, domain))
			ret = -EOPNOTSUPP;
		goto unlock;
	}

	/* Use the host EPT depth selected from CPU and common IOMMU support. */
	agaw = level_to_agaw(pkvm_host_ept_level());
	if (agaw < level_to_agaw(4) || agaw > level_to_agaw(5) ||
	    !(cap_sagaw(iommu->cap) & BIT(agaw)) ||
	    (sm_supported(iommu) && !ecap_slts(iommu->ecap))) {
		ret = -EOPNOTSUPP;
		goto unlock;
	}
	gaw = min_t(int, agaw_to_width(agaw), cap_mgaw(iommu->cap));
	if (gaw < VTD_PAGE_SHIFT) {
		ret = -EOPNOTSUPP;
		goto unlock;
	}

	domain->use_first_level = false;
	domain->iommu_superpage = 0;
	/* Keep these conservative policies fixed as more devices are added. */
	domain->iommu_coherency = false;
	domain->iotlb_sync_map = true;
	domain->gaw = gaw;
	domain->max_addr = __DOMAIN_MAX_ADDR(gaw);
	domain_flush_cache(domain, domain->pgd, VTD_PAGE_SIZE);
	/* Publish readiness under the same lock used by map/unmap. */
	domain->agaw = agaw;
unlock:
	pkvm_spin_unlock(&domain->lock);
	pkvm_put_iommu_domain(domain);
	return ret;
}

int pkvm_guest_iommu_init_domain(struct pkvm_vm *vm, phys_addr_t pgd_pa)
{
	struct dmar_domain *domain;
	struct alloc_domain_data data;
	int ret;

	if (!vm)
		return -EINVAL;

	if (!pkvm_is_protected_vm(&vm->kvm)) {
		/* Per-VM domain is only used by pVMs */
		return 0;
	}

	if (!pgd_pa)
		return -EINVAL;

	ret = pkvm_host_donate_hyp(pgd_pa, PAGE_SIZE, true);
	if (ret)
		return ret;

	memset(&data, 0, sizeof(data));
	data.pgd_gpa = pgd_pa;
	data.use_first_level = false;

	domain = pkvm_alloc_iommu_domain(&data, true, vm);
	if (IS_ERR(domain)) {
		pkvm_err("%s: domain alloc failed for protected VM (err=%ld)\n",
			 __func__, PTR_ERR(domain));
		pkvm_hyp_donate_host(pgd_pa, PAGE_SIZE, false);
		return PTR_ERR(domain);
	}
	domain->agaw = -1;
	vm->dma_domain = domain;

	return 0;
}

int pkvm_guest_iommu_free_domain(struct pkvm_vm *vm, struct pkvm_memcache *mc)
{
	struct pkvm_memcache dummy = {};
	int ret;

	if (!vm) {
		return -EINVAL;
	}

	if (!pkvm_is_protected_vm(&vm->kvm)) {
		/* Per-VM domain is only used by pVMs */
		return 0;
	}

	if (!mc) {
		mc = &dummy;
	}

	ret = pkvm_free_iommu_domain(pkvm_virt_to_host_gpa(vm->dma_domain->pgd), mc, vm);
	if (!ret)
		vm->dma_domain = NULL;

	return ret;
}

int pkvm_iommu_domain_free_did(u64 phys, u64 pgd_gpa, u16 did)
{
	struct intel_iommu *iommu = iommu_from_phys(phys);
	struct dmar_domain *domain;
	int ret;

	pkvm_warn("%s: phys=%llx pgd_gpa=0x%llx did=%d\n", __func__, phys, pgd_gpa, did);

	if (!iommu) {
		pkvm_err("%s: failed to get the iommu [phys:%llx]\n", __func__,
			 phys);
		return -EINVAL;
	}

	domain = get_host_iommu_domain(pkvm_host_gpa_to_virt(pgd_gpa));
	if (!domain) {
		pkvm_err("%s: failed to get the domain [pgd:%llx]\n", __func__,
			 pgd_gpa);
		return -EINVAL;
	}

	if (!iommu_domain_compatible(iommu, domain)) {
		pkvm_err("%s: domain[pgd:%llx] is incompatible with iommu%d\n", __func__, pgd_gpa, iommu->seq_id);
		pkvm_put_iommu_domain(domain);
		return -EINVAL;
	}

	ret = pkvm_iommu_free_did(iommu, domain, did);
	pkvm_put_iommu_domain(domain);
	if (ret > 0) {
		/* did is still attached, this is a bug */
		pkvm_err("%s: failed to free did, still users: %d\n", __func__, ret);
		return -EBUSY;
	}

	return ret;
}
