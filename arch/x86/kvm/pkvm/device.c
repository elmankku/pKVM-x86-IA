// SPDX-License-Identifier: GPL-2.0

#include <asm/pkvm_spinlock.h>
#include <linux/bitmap.h>

#include "pkvm.h"
#include "device.h"
#include "debug.h"
#include "init.h"
#include "iommu.h"

static DEFINE_PKVM_SPINLOCK(devices_lock);

/* The maximum number of assigned devices. */
#define MAX_PKVM_DEVICES	32
static DECLARE_BITMAP(devices_bitmap, MAX_PKVM_DEVICES);

struct pkvm_assigned_device {
	struct pkvm_vm *vm;
	atomic_t refcount;
	// FIXME: we probably shouldn't store it here, we could just have a
	// function returning the index regardless of how the device is stored.
	u32 index;
	u32 group_id;
	struct intel_iommu *iommu;
	u16 did;
	u16 bdf;
} pkvm_devices[MAX_PKVM_DEVICES];

static struct pkvm_assigned_device *find_by_bdf_locked(u16 bdf)
{
	unsigned int index;
	struct pkvm_assigned_device *dev = NULL;

	for_each_set_bit(index, devices_bitmap, MAX_PKVM_DEVICES) {
		dev = &pkvm_devices[index];
		if (dev->bdf == bdf) {
			return dev;
		}
	}

	return NULL;
}

/* Serialize host context changes with assignment and teardown. */
int pkvm_device_host_access_begin(u16 bdf)
{
	pkvm_spin_lock(&devices_lock);
	if (find_by_bdf_locked(bdf)) {
		pkvm_spin_unlock(&devices_lock);
		return -EBUSY;
	}
	return 0;
}

void pkvm_device_host_access_end(void)
{
	pkvm_spin_unlock(&devices_lock);
}

int pkvm_assign_device(int vm_handle, u16 bdf, u32 group_id, u64 iommu_phys)
{
	struct intel_iommu *iommu;
	struct pkvm_vm *pkvm_vm;
	struct pkvm_assigned_device *dev;

	unsigned int index;
	int did, ret = 0;

	/* Require the registered IOMMU's MMIO base address. */
	iommu = iommu_from_phys(iommu_phys);
	if (!iommu || iommu->reg_phys != iommu_phys)
		return -EINVAL;
	if (sm_supported(iommu))
		return -EOPNOTSUPP;

	pkvm_vm = pkvm_get_vm(vm_handle);
	if (!pkvm_vm)
		return -EINVAL;

	if (!pkvm_is_protected_vm(&pkvm_vm->kvm)) {
		pkvm_put_vm(pkvm_vm);
		return -EPERM;
	}

	pkvm_spin_lock(&devices_lock);

	if (find_by_bdf_locked(bdf)) {
		ret = -EBUSY;
		goto unlock;
	}

	/* TODO: reset & disable bus master here */

	index = find_first_zero_bit(devices_bitmap, MAX_PKVM_DEVICES);
	if (index >= MAX_PKVM_DEVICES) {
		ret = -ENOMEM;
		goto unlock;
	}

	did = pkvm_guest_iommu_get_did(pkvm_vm, iommu);
	if (did < 0) {
		ret = did;
		goto unlock;
	}

	ret = pkvm_guest_iommu_configure_domain(pkvm_vm, iommu);
	if (!ret)
		ret = pkvm_guest_iommu_attach_device(pkvm_vm, iommu, did, bdf);
	if (ret) {
		/* Attach failure leaves the previous hardware binding intact. */
		WARN_ON(pkvm_guest_iommu_put_did(pkvm_vm, iommu, did));
		goto unlock;
	}

	dev = &pkvm_devices[index];

	dev->vm = pkvm_vm;
	dev->bdf = bdf;
	dev->group_id = group_id;
	dev->iommu = iommu;
	dev->did = did;

	dev->index = index;
	atomic_set(&dev->refcount, 1);
	__set_bit(index, devices_bitmap);

unlock:
	pkvm_spin_unlock(&devices_lock);

	if (ret)
		pkvm_put_vm(pkvm_vm);

	return ret;
}

static int pkvm_teardown_device_locked(struct pkvm_assigned_device *dev)
{
	int ret;

	if (atomic_cmpxchg(&dev->refcount, 1, 0) != 1) {
		pkvm_err("%s: device bdf=0x%x has users, refcount %d\n",
			 __func__, dev->bdf, atomic_read(&dev->refcount));
		return -EBUSY;
	}


	// TODO: reset & quiesence device here

	ret = pkvm_guest_iommu_detach_device(dev->vm, dev->iommu, dev->did,
					     dev->bdf);
	if (ret) {
		atomic_set(&dev->refcount, 1);
		return ret;
	}

	ret = pkvm_guest_iommu_put_did(dev->vm, dev->iommu, dev->did);
	if (WARN_ON(ret)) {
		atomic_set(&dev->refcount, 1);
		return ret;
	}

	pkvm_put_vm(dev->vm);
	dev->vm = NULL;
	dev->iommu = NULL;
	dev->did = 0;

	BUG_ON(dev->index >= MAX_PKVM_DEVICES);
	__clear_bit(dev->index, devices_bitmap);

	return 0;
}

int pkvm_reclaim_device(int vm_handle, u16 bdf)
{
	struct pkvm_vm *pkvm_vm;
	struct pkvm_assigned_device *dev;
	int ret = 0;

	pkvm_vm = pkvm_get_vm(vm_handle);
	if (!pkvm_vm)
		return -EINVAL;

	if (!pkvm_is_protected_vm(&pkvm_vm->kvm)) {
		pkvm_put_vm(pkvm_vm);
		return -EPERM;
	}

	pkvm_info("vm%d reclaim device bdf=%x\n", vm_handle, bdf);

	pkvm_spin_lock(&devices_lock);

	dev = find_by_bdf_locked(bdf);
	if (!dev) {
		ret = -ENODEV;
		goto unlock;
	}

	if (dev->vm != pkvm_vm) {
		ret = -EPERM;
		goto unlock;
	}

	ret = pkvm_teardown_device_locked(dev);
unlock:
	pkvm_spin_unlock(&devices_lock);

	pkvm_put_vm(pkvm_vm);

	return ret;
}

int pkvm_teardown_devices(int vm_handle)
{
	struct pkvm_vm *pkvm_vm;
	unsigned int index;
	struct pkvm_assigned_device *dev = NULL;
	int ret = 0;

	pkvm_vm = pkvm_get_vm(vm_handle);
	if (!pkvm_vm)
		return -EINVAL;

	if (pkvm_is_protected_vm(&pkvm_vm->kvm)) {
		pkvm_spin_lock(&devices_lock);
		for_each_set_bit(index, devices_bitmap, MAX_PKVM_DEVICES) {
			dev = &pkvm_devices[index];
			if (dev->vm != pkvm_vm) {
				continue;
			}

			pkvm_info("vm%d teardown device bdf=%x\n", vm_handle, dev->bdf);

			ret = pkvm_teardown_device_locked(dev);
			if (ret)
				break;
		}
		pkvm_spin_unlock(&devices_lock);
	}

	pkvm_put_vm(pkvm_vm);

	return ret;
}
