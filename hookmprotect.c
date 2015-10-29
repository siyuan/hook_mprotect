#include <linux/init.h>
#include <asm/fcntl.h>
#include <asm/unistd.h>
#include <asm/ia32_unistd.h>
#include <asm/msr.h>

#include <linux/stackprotector.h>
#include <linux/cpu.h>
#include <linux/errno.h>
#include <linux/fs.h>
#include <linux/kernel.h>
#include <linux/mm.h>
#include <linux/elfcore.h>
#include <linux/smp.h>
#include <linux/user.h>
#include <linux/interrupt.h>
#include <linux/utsname.h>
#include <linux/delay.h>
#include <linux/module.h>
#include <linux/ptrace.h>
#include <linux/notifier.h>
#include <linux/kprobes.h>
#include <linux/kdebug.h>
#include <linux/tick.h>
#include <linux/prctl.h>
#include <linux/uaccess.h>
#include <linux/io.h>
#include <linux/ftrace.h>
#include <linux/dmi.h>
#include <linux/mman.h>

unsigned long *sys_table = NULL;
static void *memmem(const void *haystack, size_t haystack_len,
		    const void *needle, size_t needle_len);

asmlinkage long (* ori_sys_mprotect)(unsigned long start, size_t len,
				unsigned long prot);

asmlinkage long my_sys_mprotect(unsigned long start, size_t len,
				unsigned long prot)
{
	printk("my_sys_mprotect\n");
	return ori_sys_mprotect(start, len, prot & ~PROT_EXEC);
}

static unsigned long get_syscall_table_long(void)
{
#define OFFSET_SYSCALL 200
    unsigned long syscall_long, retval;
    char sc_asm[OFFSET_SYSCALL];
    rdmsrl(MSR_LSTAR, syscall_long);
    memcpy(sc_asm, (char *) syscall_long, OFFSET_SYSCALL);
    retval =
	(unsigned long) memmem(sc_asm, OFFSET_SYSCALL, "\xff\x14\xc5", 3);
    if (retval != 0) {
	retval = (unsigned long) (*(unsigned long *) (retval + 3));
    } else {
	printk("long mode : memmem found nothing, returning NULL:(");
	retval = 0;
    }
#undef OFFSET_SYSCALL
    return retval;
}

static void *memmem(const void *haystack, size_t haystack_len,
		    const void *needle, size_t needle_len)
{
    const char *begin;
    const char *const last_possible =
	(const char *) haystack + haystack_len - needle_len;
    if (needle_len == 0) {
	/* The first occurrence of the empty string is deemed to occur at 
	   the beginning of the string. */
	return (void *) haystack;
    }
    if (__builtin_expect(haystack_len < needle_len, 0)) {
	return NULL;
    }
    for (begin = (const char *) haystack; begin <= last_possible; ++begin) {
	if (begin[0] == ((const char *) needle)[0]
	    && !memcmp((const void *) &begin[1],
		       (const void *) ((const char *) needle + 1),
		       needle_len - 1)) {
	    return (void *) begin;
	}
    }
    return NULL;
}

unsigned int clear_and_return_cr0(void)
{
    unsigned long cr0 = 0;
    unsigned long ret;
    asm volatile ("movq %%cr0, %%rax":"=a" (cr0));
    ret = cr0;
    /* clear the 20 bit of CR0, a.k.a WP bit */
    cr0 &= 0xfffffffffffeffff;
    asm volatile ("movq %%rax, %%cr0"::"a" (cr0));
    return ret;
}

void setback_cr0(unsigned long val)
{
    asm volatile ("movq %%rax, %%cr0"::"a" (val));
}

static int init_sys_call_table(void)
{
    unsigned long orig_cr0 = clear_and_return_cr0();
    sys_table = (unsigned long *) get_syscall_table_long();
    sys_table = (unsigned long) sys_table | 0xffffffff00000000;
    if (sys_table == 0) {
	printk("sys_table == 0/n");
	return -1;
    }
    printk("sys_table addr 0x%p\n", sys_table);

    ori_sys_mprotect = (asmlinkage long (*)(unsigned long start, size_t len, unsigned long prot))sys_table[__NR_mprotect];
    sys_table[__NR_mprotect] = (unsigned long) my_sys_mprotect;

    setback_cr0(orig_cr0);
    return 0;
}

static void clean_sys_call_table(void)
{
    unsigned long orig_cr0 = clear_and_return_cr0();
    sys_table[__NR_mprotect] = (unsigned long) ori_sys_mprotect;
    setback_cr0(orig_cr0);
    return;
}

static int __init init_64mod(void)
{
    init_sys_call_table();
    return 0;
}

static void __exit exit_64mod(void)
{
    clean_sys_call_table();
}

module_init(init_64mod);
module_exit(exit_64mod);
MODULE_LICENSE("GPL");
