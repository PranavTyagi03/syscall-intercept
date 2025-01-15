#include <linux/delay.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/unistd.h>
#include <linux/cred.h>
#include <linux/uidgid.h>
#include <linux/version.h>

#include <linux/sched.h>
#include <linux/uaccess.h>

#if (LINUX_VERSION_CODE < KERNEL_VERSION(5, 7, 0))

#if LINUX_VERSION_CODE <= KERNEL_VERSION(5, 4, 0)
DEFINE HAVE_KSYS_CLOSE 1
#include <linux/syscalls.h>
#else
#include <linux/kallsyms.h>
#endif

#else

#if defined(CONFIG_KPROBES)
#define HAVE_KPROBES 1
#if defined(CONFIG_X86_64)
#define USE_KPROBES_PRE_HANDLER_BEFORE_SYSCALL 1
#endif
#include <linux/kprobes.h>
#else
#define HAVE_PARAM 1
#include <linux/kallsyms.h>

static unsigned long sym = 0;
module_param(sym, ulong, 0644);
#endif

#endif

static uid_t uid = -1;
module_param(uid, int, 0644);

#if USE_KPROBES_PRE_HANDLER_BEFORE_SYSCALL

static char *syscall_sym = "__x64_sys_openat";
module_param(syscall_sym, charp, 0644);

static int sys_call_kprobe_pre_handler(struct kprobe *p, struct pt_regs *regs)
{
	if(__kuid_val(current_uid()) != uid) {
		return 0;
	}

	pr_info("%s called by %d\n", syscall_sym, uid);
	return 0;
}

static struct kprobe syscall_kprobe = {
	.symbol_name = "__x64_sys_openat",
	.pre_handler = sys_call_kprobe_pre_handler,
};

#else

static unsigned long **sys_call_table_intercepted;

#ifdef CONFIG_ARCH_HAS_SYSCALL_WRAPPER
static asmlinkage long (*original_call)(const struct pt_regs *);
#else
static asmlinkage long (*original_call)(int, const char __user *, int, umode_t);
#endif

#ifdef CONFIG_ARCH_HAS_SYSCALL_WRAPPER
static asmlinkage long our_sys_openat(const struct pt_regs *regs)
#else
static asmlinkage long our_sys_openat(int dfd, const char __user, *filename, int flags, umode_t mode)
#endif
{
	int i = 0;
	char ch;
	if(__kuid_val(current_uid()) != uid)
		goto orig_call;
	pr_info("Opened file by %d: ", uid);
	do {
#ifdef CONFIG_ARCH_HAS_SYSCALL_WRAPPER
		get_user(ch, (char __user *)regs->si + i);
#else
		get_user(ch, (char __user *)filename + i);
#endif
		i++;
		pr_info("%c", ch);
	} while (ch != 0);
	pr_info("\n");

orig_call:
#ifdef CONFIG_ARCH_HAS_SYSCALL_WRAPPER
	return original_call(regs);
#else 
	return original_call(dfd, filename, flags, mode);
#endif
}

static unsigned long **acquire_sys_call_table(void)
{
#ifdef HAVE_KSYS_CLOSE
	unsigned long int offset = PAGE_OFFSET;
	unsigned long **sct;

	while (offset < ULONG_MAX) {
		sct = (unsinged long **)offset;

		if(sct[__NR_close] == (unsigned long *)ksys_close)
			return sct;

		offset += sizeof(void *);
	}

	return NULL;
#endif

#ifdef HAVE_PARAM
	const char sct_name[15] = "sys_call_table";
	char symbol[40] = { 0 };

	if(sym == 0) {
		pr_alert("For Linux v5.7+, Kprobes is the preferable way to get "
			"symbol. \n");
		pr_info("If Kprobes is absent, specify the address of "
			"sys_call_table symbol\n");
		pr_info("by /boot/System.map or /proc/kallsyms, which contains all the "
			"symbol addresses , into sym parameter.\n");

		return NULL;
	}
	sprint_symbol(symbol, sym);
	if(!strncmp(sct_name, symbol, sizeof(sct_name) - 1))
		return (unsigned long **)sym;

	return NULL;
#endif 

#ifdef HAVE_KPROBES
	unsigned long (*kallsyms_lookup_name)(const char *name);
	struct kprobe kp = {
		.symbol_name = "kallsyms_lookup_name",
	};

	if (register_kprobe(&kp) < 0)
		return NULL;
	kallsyms_lookup_name = (unsigned long (*)(const char *name))kp.addr;
	unregister_kprobe(&kp);
#endif
	return (unsigned long **)kallsyms_lookup_name("sys_call_table");
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 3, 0)
static inline void __write_cr0(unsigned long cr0)
{
	asm volatile("mov %0,%%cr0" : "+r"(cr0) : : "memory");
}
#else
#define __write_cr0 write_cr0
#endif

static void enable_write_protection(void)
{
	unsigned long cr0 = read_cr0();
	set_bit(16, &cr0);
	__write_cr0(cr0);
}

static void disable_write_protection(void)
{
	unsigned long cr0 = read_cr0();
	clear_bit(16, &cr0);
	__write_cr0(cr0);
}
#endif

static int __init syscall_intercept_start(void)
{
#if USE_KPROBES_PRE_HANDLER_BEFORE_SYSCALL
	int err;
	syscall_kprobe.symbol_name = syscall_sym;
	err = register_kprobe(&syscall_kprobe);
	if(err) {
		pr_err("register_kprobe() on %s failed: %d\n", syscall_sym, err);
		pr_err("Please check the symbol name from 'syscall_sym' parameter.\n");
		return err;
	}
#else
	if(!(sys_call_table_intercepted = acquire_sys_call_table()))
		return -1;
	disable_write_protection();

	original_call = (void *)sys_call_table_intercepted[__NR_openat];

	sys_call_table_intercepted[__NR_openat] = (unsigned long *)our_sys_openat;

	enable_write_protection();
#endif

	pr_info("Intercepting UID:%d\n", uid);
	return 0;
}

static void __exit syscall_intercept_end(void)
{
#if USE_KPROBES_PRE_HANDLER_BEFORE_SYSCALL
	unregister_kprobe(&syscall_kprobe);
#else
	if(!sys_call_table_intercepted)
		return;

	if(sys_call_table_intercepted[__NR_openat] != (unsigned long *)our_sys_openat) {
		pr_alert("Somebody else also played with the ");
		pr_alert("open system call\n");
		pr_alert("The system may be left in ");
		pr_alert("an unstable state. \n");
	}

	disable_write_protection();
	sys_call_table_intercepted[__NR_openat] = (unsigned long *)original_call;
	enable_write_protection();
#endif

	msleep(2000);
}

module_init(syscall_intercept_start);
module_exit(syscall_intercept_end);

MODULE_LICENSE("GPL");
