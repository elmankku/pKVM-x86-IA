/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __PKVM_X86_DEVICE_H
#define __PKVM_X86_DEVICE_H

#include <linux/types.h>

struct pkvm_vm;

int pkvm_assign_device(int vm_handle, u16 bdf, u32 group_id, u64 iommu_phys);
int pkvm_reclaim_device(int vm_handle, u16 bdf);
int pkvm_teardown_devices(int vm_handle);

/* Success holds devices_lock until pkvm_device_host_access_end(). */
int pkvm_device_host_access_begin(u16 bdf);
void pkvm_device_host_access_end(void);

#endif // __PKVM_X86_DEVICE_H
