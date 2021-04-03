// SPDX-License-Identifier: GPL-2.0+

/*
 * tracer.c - Kretprobe-based kernel operations surveillant
 *
 * Author: Teodor-Stefan Dutu <teodor.dutu@gmail.com>
 */
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/module.h>
#include <linux/types.h>
#include <linux/hashtable.h>
#include <linux/kprobes.h>
#include <linux/sched.h>
#include <linux/miscdevice.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/slab.h>
#include <linux/rcupdate.h>

#include "tracer.h"

#define HT_BITS				10
#define PROC_TRACER			"tracer"
#define MAX_ACTIVE			32
#define KMALLOC_FUNC			"__kmalloc"
#define KFREE_FUNC			"kfree"
#define MUTEX_LOCK_NESTED_FUNC		"mutex_lock_nested"
#define MUTEX_UNLOCK_FUNC		"mutex_unlock"
#define SCHEDULE_FUNC			"schedule"
#define UP_FUNC				"up"
#define DOWN_INTR_FUNC			"down_interruptible"
#define DO_EXIT_FUNC			"do_exit"

#define HANDLE_SIMPLE_FUNC(field, ret)					\
	do {								\
		struct proc_info *pi = get_node(current->pid);		\
		if (!pi) {						\
			ret = -EINVAL;					\
			break;						\
		}							\
		++pi->field;						\
		ret = 0;						\
	} while (0)

#define hash_free(ht, idx, tmp, ptr, extra)				\
	do {								\
		hash_for_each_safe(ht, idx, tmp, ptr, node) {		\
			extra;						\
			hash_del(&ptr->node);				\
			kfree(ptr);					\
		}							\
	} while (0)


struct proc_info {
	pid_t pid;
	uint num_kmalloc;
	uint num_kfree;
	uint num_sched;
	uint num_up;
	uint num_down;
	uint num_lock;
	uint num_unlock;
	size_t kmalloc_mem;
	size_t kfree_mem;
	DECLARE_HASHTABLE(mem, 3);
	struct hlist_node node;
};

struct addr_info {
	size_t addr;
	size_t size;
	struct hlist_node node;
};


static DEFINE_HASHTABLE(procs, HT_BITS);
static DEFINE_SPINLOCK(lock);


static struct proc_info *get_node(pid_t pid)
{
	struct proc_info *pi;

	rcu_read_lock();
	hash_for_each_possible_rcu_notrace(procs, pi, node, pid)
		if (pi->pid == pid) {
			rcu_read_unlock();
			return pi;
		}
	rcu_read_unlock();

	return NULL;
}

static int remove_proc(pid_t pid)
{
	size_t i;
	struct addr_info *ai;
	struct hlist_node *tmp;
	struct proc_info *pi = get_node(pid);

	if (!pi)
		return -EINVAL;

	spin_lock(&lock);
	hash_del_rcu(&pi->node);
	spin_unlock(&lock);
	synchronize_rcu();

	/**
	 * With RCU, no other process references pi, so no locking is needed
	 * here, because there can be no race conditions.
	 * */
	hash_free(pi->mem, i, tmp, ai, ;);
	kfree(pi);

	return 0;
}


static int
kmalloc_entry_handler(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	*(size_t *)ri->data = regs->ax;
	return 0;
}

static struct addr_info *create_addr_node(size_t addr, size_t size)
{
	struct addr_info *node = kmalloc(sizeof(*node), GFP_ATOMIC);

	if (!node)
		return NULL;

	node->addr = addr;
	node->size = size;

	return node;
}

static int
kmalloc_exit_handler(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	struct addr_info *ai;
	size_t size = *(size_t *)ri->data;
	size_t addr = regs_return_value(regs);
	struct proc_info *pi = get_node(current->pid);

	if (!pi)
		return -EINVAL;

	ai = create_addr_node(addr, size);
	if (!ai)
		return -EINVAL;

	hash_add(pi->mem, &ai->node, addr);
	++pi->num_kmalloc;
	pi->kmalloc_mem += size;

	return 0;
}

static int kfree_handler(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	struct addr_info *ai;
	struct hlist_node *tmp;
	size_t addr = regs->ax;
	struct proc_info *pi = get_node(current->pid);

	if (!pi)
		return -EINVAL;

	hash_for_each_possible_safe(pi->mem, ai, tmp, node, addr)
		if (addr == ai->addr) {
			++pi->num_kfree;
			pi->kfree_mem += ai->size;

			return 0;
		}

	return -EINVAL;
}

static int schedule_handler(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	int ret;

	HANDLE_SIMPLE_FUNC(num_sched, ret);
	return ret;
}

static int
mutex_lock_nested_handler(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	int ret;

	HANDLE_SIMPLE_FUNC(num_lock, ret);
	return ret;
}

static int
mutex_unlock_handler(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	int ret;

	HANDLE_SIMPLE_FUNC(num_unlock, ret);
	return ret;
}

static int up_handler(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	int ret;

	HANDLE_SIMPLE_FUNC(num_up, ret);
	return ret;
}

static int
down_intr_handler(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	int ret;

	HANDLE_SIMPLE_FUNC(num_down, ret);
	return ret;
}

static int do_exit_handler(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	return remove_proc(current->pid);
}


static int tracer_print(struct seq_file *m, void *v)
{
	struct proc_info *pi;
	size_t i;

	seq_puts(
		m,
		"PID\tkmalloc\tkfree\tkmalloc_mem\tkfree_mem\tsched\tup\tdown\t"
			"lock\tunlock\n"
	);

	rcu_read_lock();
	hash_for_each_rcu(procs, i, pi, node)
		seq_printf(
			m,
			"%d\t%u\t%u\t%zu\t%zu\t%u\t%u\t%u\t%u\t%u\n",
			pi->pid,
			pi->num_kmalloc,
			pi->num_kfree,
			pi->kmalloc_mem,
			pi->kfree_mem,
			pi->num_sched,
			pi->num_up,
			pi->num_down,
			pi->num_lock,
			pi->num_unlock
		);
	rcu_read_unlock();

	return 0;
}

static int tracer_read_open(struct inode *inode, struct file *file)
{
	return single_open(file, tracer_print, NULL);
}


static int tracer_open(struct inode *inode, struct file *file)
{
	return 0;
}

static int tracer_release(struct inode *inode, struct file *file)
{
	return 0;
}

static struct proc_info *create_proc_node(pid_t pid)
{
	struct proc_info *pi = kcalloc(1, sizeof(*pi), GFP_KERNEL);

	if (!pi)
		return NULL;

	hash_init(pi->mem);
	pi->pid = pid;

	return pi;
}

static long tracer_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
	int ret;
	struct proc_info *pi;

	switch (cmd) {
	case TRACER_ADD_PROCESS:
		pi = create_proc_node(arg);
		if (!pi)
			return -ENOMEM;

		spin_lock(&lock);
		hash_add_rcu(procs, &pi->node, arg);
		spin_unlock(&lock);

		break;
	case TRACER_REMOVE_PROCESS:
		ret = remove_proc(arg);
		if (ret) {
			pr_err("PID %ld not found\n", arg);
			return ret;
		}
	
		break;
	default:
		pr_err("Undefined IOCTL command\n");
		return -EINVAL;
	}
	return 0;
}


static struct proc_dir_entry *tracer_read;

static const struct proc_ops pops = {
	.proc_open = tracer_read_open,
	.proc_read = seq_read,
	.proc_release = single_release
};


static const struct file_operations fops = {
	.owner = THIS_MODULE,
	.open = tracer_open,
	.release = tracer_release,
	.unlocked_ioctl = tracer_ioctl
};

static struct miscdevice tracer_dev = {
	.minor = TRACER_DEV_MINOR,
	.name = TRACER_DEV_NAME,
	.fops = &fops
};


static struct kretprobe kprobes[] = {
	{
		.entry_handler = kmalloc_entry_handler,
		.handler = kmalloc_exit_handler,
		.data_size = sizeof(size_t),
		.maxactive = MAX_ACTIVE,
		.kp.symbol_name = KMALLOC_FUNC
	},
	{
		.entry_handler = kfree_handler,
		.maxactive = MAX_ACTIVE,
		.kp.symbol_name = KFREE_FUNC
	},
	{
		.entry_handler = schedule_handler,
		.maxactive = MAX_ACTIVE,
		.kp.symbol_name = SCHEDULE_FUNC
	},
	{
		.entry_handler = mutex_lock_nested_handler,
		.maxactive = MAX_ACTIVE,
		.kp.symbol_name = MUTEX_LOCK_NESTED_FUNC
	},
	{
		.entry_handler = mutex_unlock_handler,
		.maxactive = MAX_ACTIVE,
		.kp.symbol_name = MUTEX_UNLOCK_FUNC
	},
	{
		.entry_handler = up_handler,
		.maxactive = MAX_ACTIVE,
		.kp.symbol_name = UP_FUNC
	},
	{
		.entry_handler = down_intr_handler,
		.maxactive = MAX_ACTIVE,
		.kp.symbol_name = DOWN_INTR_FUNC
	},
	/* Handler to remove processes from the hashtable when they exit. */
	{
		.entry_handler = do_exit_handler,
		.maxactive = MAX_ACTIVE,
		.kp.symbol_name = DO_EXIT_FUNC
	}
};


static void unregister_probes(size_t pos)
{
	size_t i;

	for (i = 0; i != pos; ++i)
		unregister_kretprobe(kprobes + i);
}

static int __init kretprobe_init(void)
{
	int ret;
	size_t i, num_probes = sizeof(kprobes) / sizeof(*kprobes);

	for (i = 0; i != num_probes; ++i) {
		ret = register_kretprobe(kprobes + i);
		if (ret) {
			pr_err(
				"Failed to register probe for function %s\n",
				kprobes[i].kp.symbol_name
			);
			goto err_unregister;
		}
	}

	ret = misc_register(&tracer_dev);
	if (ret) {
		pr_err("Failed to register device\n");
		goto err_unregister;
	}

	tracer_read = proc_create(PROC_TRACER, 0000, NULL, &pops);
	if (!tracer_read)
		goto err_proc;

	return 0;

err_proc:
	misc_deregister(&tracer_dev);

err_unregister:
	unregister_probes(i);

	return ret;
}

static void free_hash_tables(void)
{
	size_t i, j;
	struct proc_info *pi;
	struct addr_info *ai;
	struct hlist_node *tmp_procs, *tmp_addr;

	hash_free(
		procs, i, tmp_procs, pi,
		hash_free(pi->mem, j, tmp_addr, ai, ;)
	);
}

static void __exit kretprobe_exit(void)
{
	misc_deregister(&tracer_dev);
	proc_remove(tracer_read);
	unregister_probes(sizeof(kprobes) / sizeof(*kprobes) + 1);

	/**
	 * At this point, the hashtables can no longer be altered by any other
	 * process, rmmod being the only one who has access to the hashtables.
	 * Thus, no locking is needed.
	 */
	free_hash_tables();
}


module_init(kretprobe_init);
module_exit(kretprobe_exit);


MODULE_DESCRIPTION("Kretprobe-based kernel operations surveillant");
MODULE_AUTHOR("Teodor-Stefan Dutu <teodor.dutu@gmail.com>");
MODULE_LICENSE("GPL v2");
