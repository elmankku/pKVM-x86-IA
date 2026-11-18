/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (C) 2023 Google LLC
 * Copyright (C) 2026 Technology Innovation Institute
 *
 * Maple tree helpers based on drivers/iommu/pkvm-pviommu.c in Android kernel.
 */

#include "linux/maple_tree.h"
#include <linux/dma-map-ops.h>
#include <linux/dma-mapping.h>
#include <linux/err.h>
#include <linux/init.h>
#include <linux/iommu.h>
#include <linux/module.h>
#include <linux/pci.h>
#include <linux/sizes.h>
#include <linux/slab.h>
#include <linux/string.h>

#include <asm/pkvm_guest.h>

static struct iommu_device pkvm_guest_iommu;

// FIXME: a better mechanism to supply the IOMMU association from host to guest.
static char *pkvm_guest_iommu_devices[32];
static unsigned int pkvm_guest_iommu_num_devices;
module_param_array_named(devices, pkvm_guest_iommu_devices, charp,
			 &pkvm_guest_iommu_num_devices, 0444);
MODULE_PARM_DESC(
	devices,
	"Protected guest PCI BDFs managed by pKVM, e.g. 0000:00:05.0,0000:00:06.0");

struct pkvm_guest_domain {
	struct iommu_domain domain;
	struct maple_tree mappings;
};

static struct iommu_device *pkvm_guest_iommu_probe_device(struct device *dev)
{
	struct pci_dev *pdev;
	unsigned int i;

	if (!dev_is_pci(dev))
		return ERR_PTR(-ENODEV);

	pdev = to_pci_dev(dev);
	if (pci_is_bridge(pdev))
		return ERR_PTR(-ENODEV);

	for (i = 0; i < pkvm_guest_iommu_num_devices; i++) {
		if (!strcmp(pci_name(pdev), pkvm_guest_iommu_devices[i])) {
			dev_info(pkvm_guest_iommu.dev,
				 "Associating device %s\n", pci_name(pdev));
			return &pkvm_guest_iommu;
		}
	}

	return ERR_PTR(-ENODEV);
}

static bool pkvm_guest_iommu_capable(struct device *dev, enum iommu_cap cap)
{
	/* Ordinary x86 DMA is coherent; forced snooping is not supported. */
	return cap == IOMMU_CAP_CACHE_COHERENCY;
}

static int pkvm_guest_iommu_def_domain_type(struct device *dev)
{
	return IOMMU_DOMAIN_DMA;
}

static int pkvm_guest_iommu_attach_dev(struct iommu_domain *domain,
				       struct device *dev)
{
	struct iommu_group *group = dev->iommu_group;

	/* Hyp must bind the device to the VM's DMA domain during assignment. */
	if (!group || domain->type != IOMMU_DOMAIN_DMA ||
	    domain != iommu_group_default_domain(group))
		return -EINVAL;

	return 0;
}

static int pkvm_guest_domain_insert_map(struct pkvm_guest_domain *domain,
					u64 start, u64 end, u64 val, gfp_t gfp)
{
	MA_STATE(mas, &domain->mappings, start, end);
	unsigned long flags;
	int ret;

	if (end < start) {
		return -EINVAL;
	}

	spin_lock_irqsave(&domain->mappings.ma_lock, flags);
	/* Prevent mas_nomem() from dropping the lock and sleeping. */
	ret = mas_store_gfp(&mas, xa_mk_value(val),
			    gfp & ~__GFP_DIRECT_RECLAIM);
	spin_unlock_irqrestore(&domain->mappings.ma_lock, flags);

	return ret;
}

static int pkvm_guest_domain_remove_map(struct pkvm_guest_domain *domain,
					u64 start, u64 end)
{
	unsigned long flags;
	int ret = 0;

	spin_lock_irqsave(&domain->mappings.ma_lock, flags);
	/* Keep lookup, erase and restoration atomic with respect to readers. */
	while (start <= end) {
		MA_STATE(mas, &domain->mappings, start, end);
		void *entry = mas_find(&mas, end);
		u64 old_start, old_end, val;

		if (!xa_is_value(entry))
			break;

		old_start = mas.index;
		old_end = mas.last;
		val = xa_to_value(entry);
		/* mas_erase() may sleep; erase the located range explicitly. */
		ret = mas_store_gfp(&mas, NULL, GFP_ATOMIC);
		if (ret)
			break;

		/* Insert the rest if not removed. */
		if (start > old_start) {
			mas_set_range(&mas, old_start, start - 1);
			ret = mas_store_gfp(&mas, xa_mk_value(val), GFP_ATOMIC);
			if (ret)
				break;
		}

		if (old_end > end) {
			mas_set_range(&mas, end + 1, old_end);
			ret = mas_store_gfp(
				&mas, xa_mk_value(val + end - old_start + 1),
				GFP_ATOMIC);
			if (ret)
				break;
		}

		if (old_end >= end)
			break;
		start = old_end + 1;
	}
	spin_unlock_irqrestore(&domain->mappings.ma_lock, flags);

	return ret;
}

static u64 pkvm_guest_domain_find(struct pkvm_guest_domain *domain, u64 key)
{
	MA_STATE(mas, &domain->mappings, key, key);
	unsigned long flags;
	void *entry;
	u64 phys = 0;

	spin_lock_irqsave(&domain->mappings.ma_lock, flags);
	entry = mas_find(&mas, key);
	if (xa_is_value(entry))
		phys = (key - mas.index) + (u64)xa_to_value(entry);
	spin_unlock_irqrestore(&domain->mappings.ma_lock, flags);

	return phys;
}

static struct iommu_domain *
pkvm_guest_iommu_domain_alloc_paging(struct device *dev)
{
	struct pkvm_guest_domain *guest_domain;
	int bits;

	/* The hypercall ABI provides only the VM's default DMA domain. */
	if (iommu_group_default_domain(dev->iommu_group))
		return ERR_PTR(-EOPNOTSUPP);

	bits = pkvm_guest_iommu_get_iova_bits();
	if (bits < 0)
		return ERR_PTR(bits);
	if (bits < PAGE_SHIFT || bits > 64)
		return ERR_PTR(-EINVAL);

	guest_domain = kzalloc(sizeof(*guest_domain), GFP_KERNEL);
	if (!guest_domain)
		return ERR_PTR(-ENOMEM);

	mt_init(&guest_domain->mappings);

	guest_domain->domain.pgsize_bitmap = SZ_4K;
	guest_domain->domain.geometry.aperture_start = 0;
	guest_domain->domain.geometry.aperture_end =
		DMA_BIT_MASK(min_t(unsigned int, bits, BITS_PER_LONG));
	guest_domain->domain.geometry.force_aperture = true;

	return &guest_domain->domain;
}

static void pkvm_guest_iommu_domain_free(struct iommu_domain *domain)
{
	struct pkvm_guest_domain *guest_domain =
		container_of(domain, struct pkvm_guest_domain, domain);

	WARN_ON(!mtree_empty(&guest_domain->mappings));

	mtree_destroy(&guest_domain->mappings);
	kfree(domain);
}

static int pkvm_guest_iommu_map_pages(struct iommu_domain *domain,
				      unsigned long iova, phys_addr_t paddr,
				      size_t pgsize, size_t pgcount, int prot,
				      gfp_t gfp, size_t *mapped)
{
	struct pkvm_guest_domain *guest_domain =
		container_of(domain, struct pkvm_guest_domain, domain);
	size_t requested_size = pgsize * pgcount, cur_mapped;
	int ret = 0;

	dev_dbg(pkvm_guest_iommu.dev,
		"map: iova=%#lx gpa=%pa size=%#zx prot=%#x\n", iova, &paddr,
		requested_size, prot);

	*mapped = 0;
	/* Unattached unmanaged domains must not modify the VM's DMA domain. */
	if (domain->type != IOMMU_DOMAIN_DMA || (prot & IOMMU_MMIO))
		return -EOPNOTSUPP;

	while (*mapped < requested_size) {
		ret = pkvm_guest_iommu_map(iova, paddr,
					   requested_size - *mapped, prot,
					   &cur_mapped);
		*mapped += cur_mapped;
		if (ret)
			break;
		iova += cur_mapped;
		paddr += cur_mapped;
	}

	if (*mapped) {
		WARN_ON(pkvm_guest_domain_insert_map(guest_domain,
						     iova - *mapped, iova - 1,
						     paddr - *mapped, gfp));
	}

	dev_dbg(pkvm_guest_iommu.dev, "map: mapped=%#zx ret=%d\n", *mapped,
		ret);

	return ret;
}

static size_t pkvm_guest_iommu_unmap_pages(struct iommu_domain *domain,
					   unsigned long iova, size_t pgsize,
					   size_t pgcount,
					   struct iommu_iotlb_gather *gather)
{
	struct pkvm_guest_domain *guest_domain =
		container_of(domain, struct pkvm_guest_domain, domain);
	size_t total_unmapped = 0, unmapped, requested_size = pgsize * pgcount;
	int ret = 0;

	dev_dbg(pkvm_guest_iommu.dev, "unmap: iova=%#lx size=%#zx\n", iova,
		requested_size);

	if (domain->type != IOMMU_DOMAIN_DMA)
		return 0;

	while (total_unmapped < requested_size) {
		ret = pkvm_guest_iommu_unmap(
			iova, requested_size - total_unmapped, &unmapped);

		total_unmapped += unmapped;
		if (ret)
			break;
		iova += unmapped;
	}

	if (total_unmapped) {
		WARN_ON(pkvm_guest_domain_remove_map(
			guest_domain, iova - total_unmapped, iova - 1));
	}

	dev_dbg(pkvm_guest_iommu.dev, "unmap: unmapped=%#zx ret=%d\n",
		total_unmapped, ret);

	return total_unmapped;
}

static phys_addr_t pkvm_guest_iommu_iova_to_phys(struct iommu_domain *domain,
						 dma_addr_t iova)
{
	struct pkvm_guest_domain *guest_domain =
		container_of(domain, struct pkvm_guest_domain, domain);

	return pkvm_guest_domain_find(guest_domain, iova);
}

static const struct iommu_domain_ops pkvm_guest_iommu_domain_ops = {
	.attach_dev = pkvm_guest_iommu_attach_dev,
	.map_pages = pkvm_guest_iommu_map_pages,
	.unmap_pages = pkvm_guest_iommu_unmap_pages,
	.iova_to_phys = pkvm_guest_iommu_iova_to_phys,
	.free = pkvm_guest_iommu_domain_free,
};

static void pkvm_guest_iommu_get_resv_regions(struct device *dev,
					    struct list_head *head)
{
	struct iommu_resv_region *region;

	/* DMA writes in the MSI aperture are decoded as interrupts. */
	region = iommu_alloc_resv_region(0xfee00000, SZ_1M, 0,
					IOMMU_RESV_MSI, GFP_KERNEL);
	if (region)
		list_add_tail(&region->list, head);
}

static const struct iommu_ops pkvm_guest_iommu_ops = {
	.capable = pkvm_guest_iommu_capable,
	.domain_alloc_paging = pkvm_guest_iommu_domain_alloc_paging,
	.default_domain_ops = &pkvm_guest_iommu_domain_ops,
	.probe_device = pkvm_guest_iommu_probe_device,
	.device_group = generic_single_device_group,
	.def_domain_type = pkvm_guest_iommu_def_domain_type,
	.get_resv_regions = pkvm_guest_iommu_get_resv_regions,
	.owner = THIS_MODULE,
};

static int __init pkvm_guest_iommu_init(void)
{
	int ret;

	if (!pkvm_is_protected_guest())
		return 0;

	ret = iommu_device_sysfs_add(&pkvm_guest_iommu, NULL, NULL,
				     "pkvm-guest-iommu");
	if (ret)
		return ret;

	ret = iommu_device_register(&pkvm_guest_iommu, &pkvm_guest_iommu_ops,
				    NULL);
	if (ret)
		iommu_device_sysfs_remove(&pkvm_guest_iommu);

	dev_info(pkvm_guest_iommu.dev,
		 "pKVM-x86 protected guest IOMMU initialized\n");

	return ret;
}
device_initcall(pkvm_guest_iommu_init);
