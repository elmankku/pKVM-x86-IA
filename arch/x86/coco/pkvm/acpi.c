// SPDX-License-Identifier: GPL-2.0

#include <linux/acpi.h>
#include <linux/init.h>
#include <linux/kvm_para.h>
#include <linux/limits.h>
#include <linux/panic.h>

#include <asm/pkvm_guest.h>

static acpi_status pkvm_acpi_memory_handler(u32 function,
					    acpi_physical_address address,
					    u32 bit_width, u64 *value,
					    void *handler_context,
					    void *region_context)
{
	u32 size;
	u64 mask;

	switch (bit_width) {
	case 8:
		fallthrough;
	case 16:
		fallthrough;
	case 32:
		fallthrough;
	case 64:
		break;
	default:
		return AE_AML_OPERAND_VALUE;
	}

	size = bit_width / 8;
	if (size > sizeof(unsigned long))
		return AE_SUPPORT;
	if (address > ULONG_MAX - (size - 1))
		return AE_BAD_ADDRESS;

	mask = U64_MAX >> (64 - bit_width);

	/*
	 * AML is supplied by the host. Emulate all SystemMemory accesses
	 * without mapping or sharing the memory named by the AML.
	 */
	switch (function) {
	case ACPI_READ:
		*value = (unsigned long)kvm_hypercall2(PKVM_GHC_IOREAD, address,
						       size);
		*value &= mask;
		return AE_OK;
	case ACPI_WRITE:
		kvm_hypercall3(PKVM_GHC_IOWRITE, address, size, *value & mask);
		return AE_OK;
	default:
		return AE_BAD_PARAMETER;
	}
}

void __init pkvm_acpi_init(void)
{
	acpi_status status;

	status = acpi_install_address_space_handler_no_reg(
		ACPI_ROOT_OBJECT, ACPI_ADR_SPACE_SYSTEM_MEMORY,
		pkvm_acpi_memory_handler, NULL, NULL);
	if (ACPI_FAILURE(status)) {
		panic("pKVM: failed to install ACPI SystemMemory handler: %s\n",
		      acpi_format_exception(status));
	}
}
