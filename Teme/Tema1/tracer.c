// SPDX-License-Identifier: GPL-2.0+

/*
 * tracer.c - Kretprobe-based kernel operations surveillant
 *
 * Author: Teodor-Stefan Dutu <teodor.dutu@gmail.com>
 */
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/module.h>
#include <linux/kprobes.h>
#include <linux/sched.h>
#include <linux/miscdevice.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>

#include "tracer.h"

#define PROC_TRACER			"tracer"
#define MAX_ACTIVE			32
#define KMALLOC_FUNC			"__kmalloc"
#define KFREE_FUNC			"kfree"
#define MUTEX_LOCK_NESTED_FUNC		"mutex_lock_nested"
#define MUTEX_UNLOCK_FUNC		"mutex_unlock"
#define SCHEDULE_FUNC			"schedule"
#define UP_FUNC				"up"
#define DOWN_INTR_FUNC			"down_interruptible"


static int
kmalloc_entry_handler(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	// pr_info("Handling KMALLOC\n");
	return 0;
}

static int kmalloc_handler(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	// pr_info("Handling KMALLOC\n");
	return 0;
}

static int kfree_handler(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	// pr_info("Handling KFREE\n");
	return 0;
}

static int schedule_handler(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	// pr_info("Handling SCHEDULE\n");
	return 0;
}

static int
mutex_lock_nested_handler(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	// pr_info("Handling LOCK\n");
	return 0;
}

static int
mutex_unlock_handler(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	// pr_info("Handling UNLOCK\n");
	return 0;
}

static int up_handler(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	// pr_info("Handling UP\n");
	return 0;
}

static int
down_intr_handler(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	// pr_info("Handling DOWN\n");
	return 0;
}


static int tracer_print(struct seq_file *m, void *v)
{
	// TODO: implementeaza si spera ca seq_print sa nu aloce memorie
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

static long tracer_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
	// TODO: baga IOCTL
	switch (cmd)
	{
	case TRACER_ADD_PROCESS:
		pr_info("Cica adaug process... kek :)))\n");
		break;
	case TRACER_REMOVE_PROCESS:
		pr_info("Cica scot proces\n");
		break;
	default:
		pr_err("Undefined IOCTL command\n");
		return -EINVAL;
		break;
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


/* The positions of each probe in the probes array */
enum which_probe {
	KMALLOC = 0,
	KFREE,
	SCHEDULE,
	MUTEX_LOCK_NESTED,
	MUTEX_UNLOCK,
	UP,
	DOWN_INTR
};

static struct kretprobe probes[] = {
	{
		.entry_handler = kmalloc_entry_handler,
		.handler = kmalloc_handler,
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
	}
};


static void unregister_probes(size_t pos)
{
	size_t i;
	for (i = 0; i != pos; ++i)
		unregister_kretprobe(probes + i);
}

static int __init kretprobe_init(void)
{
	int ret;
	size_t i, num_probes = sizeof(probes) / sizeof(*probes);

	for (i = 0; i != num_probes; ++i) {
		ret = register_kretprobe(probes + i);
		if (ret) {
			pr_err(
				"Failed to register probe for function %s\n",
				probes[i].kp.symbol_name
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

static void __exit kretprobe_exit(void)
{
	misc_deregister(&tracer_dev);
	proc_remove(tracer_read);
	unregister_probes(sizeof(probes) / sizeof(*probes) + 1);
}


module_init(kretprobe_init);
module_exit(kretprobe_exit);


MODULE_DESCRIPTION("Kretprobe-based kernel operations surveillant");
MODULE_AUTHOR("Teodor-Stefan Dutu <teodor.dutu@gmail.com>");
MODULE_LICENSE("GPL v2");
