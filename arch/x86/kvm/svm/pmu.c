// SPDX-License-Identifier: GPL-2.0-only
/*
 * KVM PMU support for AMD
 *
 * Copyright 2015, Red Hat, Inc. and/or its affiliates.
 *
 * Author:
 *   Wei Huang <wei@redhat.com>
 *
 * Implementation is based on pmu_intel.c file
 */
#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/types.h>
#include <linux/kvm_host.h>
#include <linux/perf_event.h>
#include "x86.h"
#include "cpuid.h"
#include "lapic.h"
#include "pmu.h"
#include "svm.h"

enum pmu_type {
	PMU_TYPE_COUNTER = 0,
	PMU_TYPE_EVNTSEL,
};

static struct kvm_pmc *amd_pmu_get_pmc(struct kvm_pmu *pmu, int pmc_idx)
{
	unsigned int num_counters = pmu->nr_arch_gp_counters;

	if (pmc_idx >= num_counters)
		return NULL;

	return &pmu->gp_counters[array_index_nospec(pmc_idx, num_counters)];
}

static inline struct kvm_pmc *get_gp_pmc_amd(struct kvm_pmu *pmu, u32 msr,
					     enum pmu_type type)
{
	struct kvm_vcpu *vcpu = pmu_to_vcpu(pmu);
	unsigned int idx;

	if (!vcpu->kvm->arch.enable_pmu)
		return NULL;

	switch (msr) {
	case MSR_F15H_PERF_CTL0 ... MSR_F15H_PERF_CTR5:
		if (!guest_cpuid_has(vcpu, X86_FEATURE_PERFCTR_CORE))
			return NULL;
		/*
		 * Each PMU counter has a pair of CTL and CTR MSRs. CTLn
		 * MSRs (accessed via EVNTSEL) are even, CTRn MSRs are odd.
		 */
		idx = (unsigned int)((msr - MSR_F15H_PERF_CTL0) / 2);
		if (!(msr & 0x1) != (type == PMU_TYPE_EVNTSEL))
			return NULL;
		break;
	case MSR_K7_EVNTSEL0 ... MSR_K7_EVNTSEL3:
		if (type != PMU_TYPE_EVNTSEL)
			return NULL;
		idx = msr - MSR_K7_EVNTSEL0;
		break;
	case MSR_K7_PERFCTR0 ... MSR_K7_PERFCTR3:
		if (type != PMU_TYPE_COUNTER)
			return NULL;
		idx = msr - MSR_K7_PERFCTR0;
		break;
	default:
		return NULL;
	}

	return amd_pmu_get_pmc(pmu, idx);
}

static int amd_check_rdpmc_early(struct kvm_vcpu *vcpu, unsigned int idx)
{
	struct kvm_pmu *pmu = vcpu_to_pmu(vcpu);

	if (idx >= pmu->nr_arch_gp_counters)
		return -EINVAL;

	return 0;
}

/* idx is the ECX register of RDPMC instruction */
static struct kvm_pmc *amd_rdpmc_ecx_to_pmc(struct kvm_vcpu *vcpu,
	unsigned int idx, u64 *mask)
{
	return amd_pmu_get_pmc(vcpu_to_pmu(vcpu), idx);
}

static struct kvm_pmc *amd_msr_idx_to_pmc(struct kvm_vcpu *vcpu, u32 msr)
{
	struct kvm_pmu *pmu = vcpu_to_pmu(vcpu);
	struct kvm_pmc *pmc;

	pmc = get_gp_pmc_amd(pmu, msr, PMU_TYPE_COUNTER);
	pmc = pmc ? pmc : get_gp_pmc_amd(pmu, msr, PMU_TYPE_EVNTSEL);

	return pmc;
}

static bool amd_is_valid_msr(struct kvm_vcpu *vcpu, u32 msr)
{
	struct kvm_pmu *pmu = vcpu_to_pmu(vcpu);

	switch (msr) {
	case MSR_K7_EVNTSEL0 ... MSR_K7_PERFCTR3:
		return pmu->version > 0;
	case MSR_F15H_PERF_CTL0 ... MSR_F15H_PERF_CTR5:
		return guest_cpuid_has(vcpu, X86_FEATURE_PERFCTR_CORE);
	case MSR_AMD64_PERF_CNTR_GLOBAL_STATUS:
	case MSR_AMD64_PERF_CNTR_GLOBAL_CTL:
	case MSR_AMD64_PERF_CNTR_GLOBAL_STATUS_CLR:
		return pmu->version > 1;
	default:
		if (msr > MSR_F15H_PERF_CTR5 &&
		    msr < MSR_F15H_PERF_CTL0 + 2 * pmu->nr_arch_gp_counters)
			return pmu->version > 1;
		break;
	}

	return amd_msr_idx_to_pmc(vcpu, msr);
}

static int amd_pmu_get_msr(struct kvm_vcpu *vcpu, struct msr_data *msr_info)
{
	struct kvm_pmu *pmu = vcpu_to_pmu(vcpu);
	struct kvm_pmc *pmc;
	u32 msr = msr_info->index;

	/* MSR_PERFCTRn */
	pmc = get_gp_pmc_amd(pmu, msr, PMU_TYPE_COUNTER);
	if (pmc) {
		msr_info->data = pmc_read_counter(pmc);
		return 0;
	}
	/* MSR_EVNTSELn */
	pmc = get_gp_pmc_amd(pmu, msr, PMU_TYPE_EVNTSEL);
	if (pmc) {
		msr_info->data = pmc->eventsel;
		return 0;
	}

	return 1;
}

static int amd_pmu_set_msr(struct kvm_vcpu *vcpu, struct msr_data *msr_info)
{
	struct kvm_pmu *pmu = vcpu_to_pmu(vcpu);
	struct kvm_pmc *pmc;
	u32 msr = msr_info->index;
	u64 data = msr_info->data;

	/* MSR_PERFCTRn */
	pmc = get_gp_pmc_amd(pmu, msr, PMU_TYPE_COUNTER);
	if (pmc) {
		pmc_write_counter(pmc, data);
		return 0;
	}
	/* MSR_EVNTSELn */
	pmc = get_gp_pmc_amd(pmu, msr, PMU_TYPE_EVNTSEL);
	if (pmc) {
		data &= ~pmu->reserved_bits;
		if (data != pmc->eventsel) {
			pmc->eventsel = data;
			if (is_passthrough_pmu_enabled(vcpu)) {
				if (!check_pmu_event_filter(pmc)) {
					/*
					 * When guest request an invalid event,
					 * stop the counter by clearing the
					 * event selector MSR.
					 */
					pmc->eventsel_hw = 0;
					return 0;
				}
				data &= ~AMD64_EVENTSEL_HOSTONLY;
				pmc->eventsel_hw = data | AMD64_EVENTSEL_GUESTONLY;
			} else {
				kvm_pmu_request_counter_reprogram(pmc);
			}
		}
		return 0;
	}

	return 1;
}

static void amd_pmu_refresh(struct kvm_vcpu *vcpu)
{
	struct kvm_pmu *pmu = vcpu_to_pmu(vcpu);
	union cpuid_0x80000022_ebx ebx;
	int i;

	pmu->version = 1;
	if (guest_cpuid_has(vcpu, X86_FEATURE_PERFMON_V2)) {
		pmu->version = 2;
		/*
		 * Note, PERFMON_V2 is also in 0x80000022.0x0, i.e. the guest
		 * CPUID entry is guaranteed to be non-NULL.
		 */
		BUILD_BUG_ON(x86_feature_cpuid(X86_FEATURE_PERFMON_V2).function != 0x80000022 ||
			     x86_feature_cpuid(X86_FEATURE_PERFMON_V2).index);
		ebx.full = kvm_find_cpuid_entry_index(vcpu, 0x80000022, 0)->ebx;
		pmu->nr_arch_gp_counters = ebx.split.num_core_pmc;
	} else if (guest_cpuid_has(vcpu, X86_FEATURE_PERFCTR_CORE)) {
		pmu->nr_arch_gp_counters = AMD64_NUM_COUNTERS_CORE;
	} else {
		pmu->nr_arch_gp_counters = AMD64_NUM_COUNTERS;
	}

	pmu->nr_arch_gp_counters = min_t(unsigned int, pmu->nr_arch_gp_counters,
					 kvm_pmu_cap.num_counters_gp);

	if (pmu->version > 1) {
		pmu->global_ctrl_mask = ~((1ull << pmu->nr_arch_gp_counters) - 1);
		pmu->global_status_mask = pmu->global_ctrl_mask;
	}

	pmu->counter_bitmask[KVM_PMC_GP] = ((u64)1 << 48) - 1;
	pmu->reserved_bits = 0xfffffff000280000ull;
	pmu->raw_event_mask = AMD64_RAW_EVENT_MASK;
	/* not applicable to AMD; but clean them to prevent any fall out */
	pmu->counter_bitmask[KVM_PMC_FIXED] = 0;
	pmu->nr_arch_fixed_counters = 0;
	bitmap_set(pmu->all_valid_pmc_idx, 0, pmu->nr_arch_gp_counters);
	pmu->passthrough = vcpu->kvm->arch.enable_passthrough_pmu &&
			   lapic_in_kernel(vcpu);

	if (pmu->version > 1 || guest_cpuid_has(vcpu, X86_FEATURE_PERFCTR_CORE)) {
		for (i = 0; i < pmu->nr_arch_gp_counters; i++) {
			pmu->gp_counters[i].msr_eventsel = MSR_F15H_PERF_CTL0 + 2 * i;
			pmu->gp_counters[i].msr_counter = MSR_F15H_PERF_CTR0 + 2 * i;
		}
	} else {
		for (i = 0; i < pmu->nr_arch_gp_counters; i++) {
			pmu->gp_counters[i].msr_eventsel = MSR_K7_EVNTSEL0 + i;
			pmu->gp_counters[i].msr_counter = MSR_K7_PERFCTR0 + i;
		}
	}
}

static void amd_pmu_init(struct kvm_vcpu *vcpu)
{
	struct kvm_pmu *pmu = vcpu_to_pmu(vcpu);
	int i;

	BUILD_BUG_ON(KVM_AMD_PMC_MAX_GENERIC > AMD64_NUM_COUNTERS_CORE);
	BUILD_BUG_ON(KVM_AMD_PMC_MAX_GENERIC > INTEL_PMC_MAX_GENERIC);

	for (i = 0; i < KVM_AMD_PMC_MAX_GENERIC ; i++) {
		pmu->gp_counters[i].type = KVM_PMC_GP;
		pmu->gp_counters[i].vcpu = vcpu;
		pmu->gp_counters[i].idx = i;
		pmu->gp_counters[i].current_config = 0;
	}
}

static bool amd_is_rdpmc_passthru_allowed(struct kvm_vcpu *vcpu)
{
	return true;
}

static void amd_passthrough_pmu_msrs(struct kvm_vcpu *vcpu)
{
	struct kvm_pmu *pmu = vcpu_to_pmu(vcpu);
	struct vcpu_svm *svm = to_svm(vcpu);
	int msr_clear = !!(is_passthrough_pmu_enabled(vcpu));
	int i;

	for (i = 0; i < min(pmu->nr_arch_gp_counters, AMD64_NUM_COUNTERS); i++) {
		/*
		 * Legacy counters are always available irrespective of any
		 * CPUID feature bits and when X86_FEATURE_PERFCTR_CORE is set,
		 * PERF_LEGACY_CTLx and PERF_LEGACY_CTRx registers are mirrored
		 * with PERF_CTLx and PERF_CTRx respectively.
		 */
		set_msr_interception(vcpu, svm->msrpm, MSR_K7_EVNTSEL0 + i, 0, 0);
		set_msr_interception(vcpu, svm->msrpm, MSR_K7_PERFCTR0 + i, msr_clear, msr_clear);
	}

	for (i = 0; i < kvm_pmu_cap.num_counters_gp; i++) {
		/*
		 * PERF_CTLx registers require interception in order to clear
		 * HostOnly bit and set GuestOnly bit. This is to prevent the
		 * PERF_CTRx registers from counting before VM entry and after
		 * VM exit.
		 */
		set_msr_interception(vcpu, svm->msrpm, MSR_F15H_PERF_CTL + 2 * i, 0, 0);

		/*
		 * Pass through counters exposed to the guest and intercept
		 * counters that are unexposed. Do this explicitly since this
		 * function may be set multiple times before vcpu runs.
		 */
		if (i >= pmu->nr_arch_gp_counters)
			msr_clear = 0;
		set_msr_interception(vcpu, svm->msrpm, MSR_F15H_PERF_CTR + 2 * i, msr_clear, msr_clear);
	}

	/*
	 * In mediated passthrough vPMU, intercept global PMU MSRs when guest
	 * PMU only owns a subset of counters provided in HW or its version is
	 * less than 2.
	 */
	if (is_passthrough_pmu_enabled(vcpu) && pmu->version > 1 &&
	    pmu->nr_arch_gp_counters == kvm_pmu_cap.num_counters_gp)
		msr_clear = 1;
	else
		msr_clear = 0;

	set_msr_interception(vcpu, svm->msrpm, MSR_AMD64_PERF_CNTR_GLOBAL_CTL, msr_clear, msr_clear);
	set_msr_interception(vcpu, svm->msrpm, MSR_AMD64_PERF_CNTR_GLOBAL_STATUS, msr_clear, msr_clear);
	set_msr_interception(vcpu, svm->msrpm, MSR_AMD64_PERF_CNTR_GLOBAL_STATUS_CLR, msr_clear, msr_clear);
	set_msr_interception(vcpu, svm->msrpm, MSR_AMD64_PERF_CNTR_GLOBAL_STATUS_SET, msr_clear, msr_clear);
}

static void amd_save_pmu_context(struct kvm_vcpu *vcpu)
{
	struct kvm_pmu *pmu = vcpu_to_pmu(vcpu);

	rdmsrl(MSR_AMD64_PERF_CNTR_GLOBAL_CTL, pmu->global_ctrl);
	wrmsrl(MSR_AMD64_PERF_CNTR_GLOBAL_CTL, 0);
	rdmsrl(MSR_AMD64_PERF_CNTR_GLOBAL_STATUS, pmu->global_status);

	/* Clear global status bits if non-zero */
	if (pmu->global_status)
		wrmsrl(MSR_AMD64_PERF_CNTR_GLOBAL_STATUS_CLR, pmu->global_status);
}

static void amd_restore_pmu_context(struct kvm_vcpu *vcpu)
{
	struct kvm_pmu *pmu = vcpu_to_pmu(vcpu);
	u64 global_status;

	wrmsrl(MSR_AMD64_PERF_CNTR_GLOBAL_CTL, 0);
	rdmsrl(MSR_AMD64_PERF_CNTR_GLOBAL_STATUS, global_status);

	/* Clear host global_status MSR if non-zero. */
	if (global_status)
		wrmsrl(MSR_AMD64_PERF_CNTR_GLOBAL_STATUS_CLR, global_status);

	wrmsrl(MSR_AMD64_PERF_CNTR_GLOBAL_STATUS_SET, pmu->global_status);

	wrmsrl(MSR_AMD64_PERF_CNTR_GLOBAL_CTL, pmu->global_ctrl);
}

struct kvm_pmu_ops amd_pmu_ops __initdata = {
	.rdpmc_ecx_to_pmc = amd_rdpmc_ecx_to_pmc,
	.msr_idx_to_pmc = amd_msr_idx_to_pmc,
	.check_rdpmc_early = amd_check_rdpmc_early,
	.is_valid_msr = amd_is_valid_msr,
	.get_msr = amd_pmu_get_msr,
	.set_msr = amd_pmu_set_msr,
	.refresh = amd_pmu_refresh,
	.init = amd_pmu_init,
	.is_rdpmc_passthru_allowed = amd_is_rdpmc_passthru_allowed,
	.passthrough_pmu_msrs = amd_passthrough_pmu_msrs,
	.save_pmu_context = amd_save_pmu_context,
	.restore_pmu_context = amd_restore_pmu_context,
	.EVENTSEL_EVENT = AMD64_EVENTSEL_EVENT,
	.MAX_NR_GP_COUNTERS = KVM_AMD_PMC_MAX_GENERIC,
	.MIN_NR_GP_COUNTERS = AMD64_NUM_COUNTERS,
};
