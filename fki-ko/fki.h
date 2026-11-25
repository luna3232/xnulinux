/* SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note */
/*
 * Foreign kernel interface (FKI), version 0.
 *
 * The only interface between Linux and a foreign-kernel module. It is
 * semantic and shaped like a hypervisor interface: plain integer types and
 * opaque handles, no Linux structure crosses it. A foreign module includes
 * this header only.
 */
#ifndef _LINUX_FKI_H
#define _LINUX_FKI_H

#define FKI_VERSION 0

#ifndef __KERNEL__
#include <stdint.h>
typedef uint64_t fki_u64;
#else
#include <linux/types.h>
typedef u64 fki_u64;
#endif

/* Physically contiguous memory, mapped contiguously and executable. */
struct fki_region {
	void *va;
	fki_u64 pa;
	fki_u64 size;
	void *handle;
};

/* Pointer authentication keys (each 128 bits: lo, hi). */
struct fki_pac_keys {
	fki_u64 ia[2], ib[2], da[2], db[2], ga[2];
	fki_u64 sctlr_en;	/* SCTLR_EL1 EnIA|EnIB|EnDA|EnDB bits */
};

#ifdef __cplusplus
extern "C" {
#endif
int fki_version(void);
void fki_log(const char *s, unsigned long len);
void fki_log_alert(const char *s, unsigned long len);	/* KERN_ALERT: on the console even when it is quiet */
int fki_region_alloc(unsigned long size, struct fki_region *r);
void fki_region_free(struct fki_region *r);
/* A named blob from the firmware search path. */
int fki_blob_get(const char *name, const void **data, unsigned long *size, void **handle);
void fki_blob_put(void *handle);
/* Enter and leave a foreign context on this CPU: no preemption, no interrupts, foreign PAC keys; the FP/SIMD registers are
 * the foreign kernel's to use (the current task's state saved first). */
unsigned long fki_enter(const struct fki_pac_keys *foreign, struct fki_pac_keys *saved);
void fki_leave(unsigned long cookie, const struct fki_pac_keys *saved);
/* Swap PAC keys only (caller already in a foreign context): save current into *save, load *load. */
void fki_pac_swap(const struct fki_pac_keys *load, struct fki_pac_keys *save);
/*
 * Host FEAT_PAuth from ID_AA64ISAR1_EL1 and ID_AA64ISAR2_EL1 only. Does not read or write PAC key
 * registers. Returns 1 when address or generic authentication is implemented (APA, API, GPA, GPI, APA3
 * or GPA3), 0 when none is. NULL pointers are skipped. *fields packs one nibble each: APA, API, GPA,
 * GPI, APA3, GPA3 (see fki_pauth.h).
 */
int fki_pauth_status(fki_u64 *isar1, fki_u64 *isar2, fki_u64 *sctlr_el1, fki_u64 *current_el, fki_u64 *fields);
fki_u64 fki_counter_frequency(void);
fki_u64 fki_counter(void);
void fki_random(void *buf, unsigned long len);
/* sleeps until Linux's generator is seeded (process context): 0, or -errno when a signal comes first */
int fki_random_wait(void);
/*
 * Physically contiguous memory with real physical addresses (for a foreign kernel whose own page tables
 * the hardware walks). va is a kernel linear-map address (RW, not executable). size rounds up to a power of two.
 */
int fki_contig_alloc(unsigned long size, struct fki_region *r);
void fki_contig_free(struct fki_region *r);
/*
 * The top foreign window: the L1 table that Linux's TTBR1 L0 entry for va points to. A foreign kernel may
 * own L1 entries Linux leaves empty in that table; fki_window_set installs one (then a full TLB flush).
 */
int fki_window_l1(unsigned long va, unsigned long long **l1_va, fki_u64 *l1_pa);
void fki_window_set(unsigned long long *slot, fki_u64 desc);
/*
 * Called from inside fki_enter() (preemption and IRQs off): let Linux run (IRQs and preemption on)
 * until the counter reaches deadline or max_ns pass, or fki_kick_cpu() is called for this CPU, then return with them off
 * again. Not at all if *wake (when given) is already nonzero: the kicker sets it before kicking.
 */
void fki_idle_until(fki_u64 counter_deadline, fki_u64 max_ns, const volatile unsigned int *wake);
/*
 * Called from inside fki_enter() while the hosted kernel is busy: let Linux take its pending interrupts and
 * reschedule if it must (RCU, other tasks on this CPU), then return with IRQs and preemption off again.
 */
void fki_yield(void);
/* The host's wall clock (UTC): seconds and nanoseconds since 1970. */
void fki_realtime(fki_u64 *sec, fki_u64 *nsec);
/*
 * A virtual Ethernet link to Linux (the netdev "xnu0"): send one frame (header included, no FCS); receive the next
 * frame Linux sent (its length, 0 when none waits); how many frames wait.
 */
long fki_net_send(const void *frame, unsigned long len);
long fki_net_recv(void *buf, unsigned long len);
long fki_net_pending(void);
/* Keep the calling task on one CPU (the hosted kernel sees that CPU's MPIDR). */
int fki_bind_cpu(int cpu);
/* CPUs: how many are online, and a CPU's MPIDR (from ordinary Linux context) */
int fki_num_cpus(void);
int fki_cpu_mpidr(int cpu, fki_u64 *mpidr);
/* Make the foreign kernel on a CPU look at its pending work: wake its idle call, or interrupt it (interrupts may be off) */
void fki_kick_cpu(int cpu);
/*
 * A helper kernel thread bound to one CPU: fn(arg) runs until it returns or fki_thread_stop() is called;
 * fn should loop on !fki_thread_should_stop() and sleep with fki_msleep().
 */
void *fki_thread_start(int (*fn)(void *), void *arg, int cpu, const char *name);
void fki_thread_stop(void *thread);
int fki_thread_should_stop(void);
/* In a helper thread: sleep until *flag is non-zero or the thread is told to stop; fki_thread_wake() wakes it (callable
 * with interrupts off, after setting the flag) */
void fki_thread_wait(const volatile unsigned long *flag);
void fki_thread_wake(void *thread);
void fki_msleep(unsigned int ms);
/*
 * Foreign kernel faults: a kernel-mode data or instruction abort whose address or faulting pc is in [lo, hi) is offered
 * to handler (far, esr, the faulting registers) before Linux's own handling; handler returns 0 when the exception should
 * return (the faulting instruction runs again, or wherever fki_regs_set_pc points it), nonzero to let Linux handle it as
 * usual. One registration at a time.
 */
unsigned long fki_regs_pc(void *regs);
unsigned long fki_regs_lr(void *regs);
unsigned long fki_regs_pstate(void *regs);	/* the interrupted PSTATE (SPSR) */
void fki_regs_set_pc(void *regs, unsigned long pc);
void fki_regs_set_reg(void *regs, unsigned int n, unsigned long v);	/* x0..x30 */
unsigned long fki_regs_reg(void *regs, unsigned int n);			/* x0..x30 */
int fki_fault_register(unsigned long lo, unsigned long hi, int (*handler)(unsigned long far, unsigned long esr, void *regs));
void fki_fault_unregister(void);
/* Read 8 bytes of RAM by physical address (debugging: walking a foreign page table). */
fki_u64 fki_phys_peek(fki_u64 pa);
/*
 * A host file as backing store (a foreign block device's image). fki_file_open is called from ordinary Linux context
 * and returns an opaque handle (NULL on failure) and the file's size. fki_file_rw is called from inside fki_enter():
 * it lets Linux run (IRQs and preemption on) for the I/O, copies through a Linux bounce buffer to or from buf
 * (with IRQs off again), and returns the bytes moved or a negative errno.
 */
void *fki_file_open(const char *path, int writable, fki_u64 *size);
long fki_file_rw(void *file, int write, void *buf, unsigned long len, fki_u64 off);
void fki_file_close(void *file);
/* Write to a host file from ordinary Linux context (a host thread, not inside fki_enter()); bytes written or -errno. */
long fki_file_pwrite(void *file, const void *buf, unsigned long len, fki_u64 off);
/*
 * A host call (from inside fki_enter()): len bytes at req to the Linux service reading /dev/xnu-hostcall, its reply into
 * reply (at most max bytes). Returns the reply's length or a negative errno (-ETIMEDOUT: no service answered).
 */
long fki_hostcall(const void *req, unsigned long len, void *reply, unsigned long max);
#ifdef __cplusplus
}
#endif
#endif
