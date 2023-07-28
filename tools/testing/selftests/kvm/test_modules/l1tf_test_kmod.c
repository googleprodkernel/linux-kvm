// SPDX-License-Identifier: GPL-2.0-only
/* l1tf_test_kmod.c: L1D load gadget.
 *
 */

#include <linux/kern_levels.h>
#include <linux/kprobes.h>
#include <linux/module.h>
#include <linux/printk.h>
#include <linux/kvm_host.h>
#include <asm/kvm_vcpu_regs.h>

#define KVM_HC_GTESTS_KVM_L1TF_TEST 0x42

static noinline u64 load_gadget(u64 hpa, u64 offset, int nloops)
{
	u8 *kaddr;
	u64 val;
	int i;

	offset = ALIGN_DOWN(offset, L1_CACHE_BYTES);

	kaddr = (u8 *)pfn_to_kaddr((unsigned long)hpa >> PAGE_SHIFT);

	/* Loading should cache (L1D) the data at address hpa. Repeating the
	 * access might delay the eviction of the cache line in case of cache
	 * activity in the same set (depending on the replacement policy). This
	 * is not guaranteed though, because the test execution conditions are
	 * not constant.
	 */
	for (i = 0; i < nloops; i++)
		val = READ_ONCE(*(u64 *)(kaddr + offset));

	return val;
}

static void __kprobes hypercall_probe_handler(struct kprobe *p,
					      struct pt_regs *regs,
					      unsigned long flags)
{
	unsigned long nr, hpa, offset, nloops;
	unsigned long ret;
	struct kvm_vcpu *vcpu;

	vcpu = (struct kvm_vcpu *)regs_get_kernel_argument(regs, 0);
	nr = vcpu->arch.regs[VCPU_REGS_RAX];
	hpa = vcpu->arch.regs[VCPU_REGS_RBX];
	offset = vcpu->arch.regs[VCPU_REGS_RCX];
	nloops = vcpu->arch.regs[VCPU_REGS_RDX];

	/* The vmcall must be executed by the L1TF test, otherwise return. */
	if (nr != KVM_HC_GTESTS_KVM_L1TF_TEST)
		return;

	ret = load_gadget(hpa, offset, nloops);
	READ_ONCE(ret);
}

static const char attach_func_symbol[] = "kvm_emulate_hypercall";

static struct kprobe hypercall_probe = {
	.symbol_name = attach_func_symbol,
};

static int __init l1tf_test_kmod_init(void)
{
	hypercall_probe.post_handler = hypercall_probe_handler;
	if (register_kprobe(&hypercall_probe) < 0) {
		pr_err("Failed to attach kprobe to %s\n", attach_func_symbol);
		return -1;
	}

	return 0;
}

static void l1tf_test_kmod_exit(void)
{
	unregister_kprobe(&hypercall_probe);
}

module_init(l1tf_test_kmod_init);
module_exit(l1tf_test_kmod_exit);

MODULE_LICENSE("GPL");
