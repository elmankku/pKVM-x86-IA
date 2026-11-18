// SPDX-License-Identifier: GPL-2.0
/* Copyright (C) 2026 Technology Innovation Institute */

#include <linux/types.h>
#include <linux/bitops.h>
#include <linux/limits.h>
#include <asm/pkvm_spinlock.h>

#include "pkvm_iommu.h"
#include "pkvm/debug.h"
#include "../iommu.h"

static int pkvm_iommu_alloc_did_locked(struct pkvm_domain_ids *domain_ids)
{
	unsigned long did;

	did = find_first_zero_bit(domain_ids->used, domain_ids->nr_dids);
	if (did >= domain_ids->nr_dids) {
		pkvm_err("%s: no available domain ids %ld\n", __func__, did);

		return -ENOSPC;
	}

	/* This is internal error */
	BUG_ON(did < IDA_START_DID);

	__set_bit(did, domain_ids->used);

	return did;
}

static bool did_in_use(struct pkvm_domain_ids *domain_ids, u16 did)
{
	if (did < IDA_START_DID || did >= domain_ids->nr_dids ||
	    !test_bit(did, domain_ids->used)) {
		return false;
	}

	return true;
}

static int pkvm_iommu_free_did_locked(struct pkvm_domain_ids *domain_ids, u16 did)
{
	if (!did_in_use(domain_ids, did)) {
		pkvm_err("%s: invalid did %d\n", __func__, did);
		return -EINVAL;
	}

	__clear_bit(did, domain_ids->used);

	return 0;
}

void pkvm_iommu_init_did(struct intel_iommu *iommu)
{
	iommu->domain_ids.nr_dids = cap_ndoms(iommu->cap);
	bitmap_zero(iommu->domain_ids.used, PKVM_MAX_DIDS);

	/* Set reserved DIDs */
	__set_bit(0, iommu->domain_ids.used);
	__set_bit(FLPT_DEFAULT_DID, iommu->domain_ids.used);
}

/*
 * Success consumes one caller-held domain reference. A new association keeps
 * it until its final put; reuse drops it because the association already holds
 * a reference. Errors leave the caller's reference untouched.
 */
static int __pkvm_iommu_alloc_did(struct intel_iommu *iommu,
				  struct dmar_domain *domain, bool reuse)
{
	struct iommu_domain_info *info;
	int did;

	if (!iommu || !domain) {
		return -EINVAL;
	}

	/* The caller has checked domain ownership. */
	pkvm_spin_lock(&iommu->lock);

	info = &domain->iommu_array[iommu->seq_id];
	if (info->did) {
		did = -EEXIST;
		if (!reuse)
			goto out_unlock;
		/* free_did() returns the remaining user count as an int. */
		if (info->refcnt >= INT_MAX) {
			did = -EOVERFLOW;
			goto out_unlock;
		}
		info->refcnt++;
		did = info->did;
		pkvm_put_iommu_domain(domain);
		goto out_unlock;
	}

	did = pkvm_iommu_alloc_did_locked(&iommu->domain_ids);
	if (did < 0) {
		goto out_unlock;
	}

	info->iommu = iommu;
	info->refcnt = 1;
	info->did = did;

out_unlock:
	pkvm_spin_unlock(&iommu->lock);

	return did;
}

/* Host allocation preserves the existing duplicate-allocation error. */
int pkvm_iommu_alloc_did(struct intel_iommu *iommu, struct dmar_domain *domain)
{
	return __pkvm_iommu_alloc_did(iommu, domain, false);
}

int pkvm_iommu_get_did(struct intel_iommu *iommu, struct dmar_domain *domain)
{
	return __pkvm_iommu_alloc_did(iommu, domain, true);
}

/*
 * Caller holds iommu->lock. Legacy context installation adds its cache tag
 * under that lock, and removal drops the tag only after invalidation.
 */
static bool pkvm_iommu_did_has_bindings(struct intel_iommu *iommu,
					struct dmar_domain *domain, u16 did)
{
	struct cache_tag *tag;
	bool busy = false;

	pkvm_spin_lock(&domain->cache_lock);
	list_for_each_entry(tag, &domain->cache_tags, node) {
		if (tag->iommu == iommu && tag->domain_id == did) {
			busy = true;
			break;
		}
	}
	pkvm_spin_unlock(&domain->cache_lock);

	return busy;
}

/* The final DID put must not recycle a DID with hardware bindings. */
int pkvm_iommu_free_did(struct intel_iommu *iommu, struct dmar_domain *domain, u16 did)
{
	struct iommu_domain_info *info;
	int ret = 0;

	if (!iommu || !domain) {
		return -EINVAL;
	}

	pkvm_spin_lock(&iommu->lock);

	info = &domain->iommu_array[iommu->seq_id];
	if (info->iommu != iommu || info->did != did || !info->refcnt ||
	    !did_in_use(&iommu->domain_ids, did)) {
		/* Reject invalid puts before changing the user count. */
		pkvm_spin_unlock(&iommu->lock);
		return -EINVAL;
	}

	if (info->refcnt > 1) {
		/* did is still in use, return number of users */
		ret = --info->refcnt;
		pkvm_spin_unlock(&iommu->lock);

		return ret;
	}

	if (pkvm_iommu_did_has_bindings(iommu, domain, did)) {
		pkvm_spin_unlock(&iommu->lock);
		return -EBUSY;
	}

	ret = pkvm_iommu_free_did_locked(&iommu->domain_ids, did);
	if (ret < 0) {
		pkvm_spin_unlock(&iommu->lock);
		return ret;
	}

	info->iommu = NULL;
	info->refcnt = 0;
	info->did = 0;

	/* Release the one domain reference held by this association. */
	pkvm_put_iommu_domain(domain);

	pkvm_spin_unlock(&iommu->lock);

	return ret;
}

/* Caller holds iommu->lock; registered IOMMUs have a validated seq_id. */
bool pkvm_iommu_is_valid_did_locked(struct intel_iommu *iommu,
				    struct dmar_domain *domain, u16 did)
{
	struct iommu_domain_info *info;

	/* The host EPT domain uses a permanently reserved DID. */
	if (domain == &pt_domain)
		return did == FLPT_DEFAULT_DID;

	info = &domain->iommu_array[iommu->seq_id];
	return info->iommu == iommu && info->did == did && info->refcnt &&
	       did_in_use(&iommu->domain_ids, did);
}

bool pkvm_iommu_is_valid_did(struct intel_iommu *iommu,
			     struct dmar_domain *domain, u16 did)
{
	bool valid;

	if (!iommu || !domain)
		return false;

	pkvm_spin_lock(&iommu->lock);
	valid = pkvm_iommu_is_valid_did_locked(iommu, domain, did);
	pkvm_spin_unlock(&iommu->lock);

	return valid;
}
