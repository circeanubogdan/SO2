// SPDX-License-Identifier: GPL-2.0+

/*
 * list.c - Linux kernel list API
 *
 * Author: Teodor-Stefan Dutu <teodor.dutu@gmail.com>
 */
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/list.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/uaccess.h>

#define PROCFS_MAX_SIZE		512

#define procfs_dir_name		"list"
#define procfs_file_read	"preview"
#define procfs_file_write	"management"

#define ADD_FIRST		"addf"
#define ADD_END			"adde"
#define DEL_FIRST		"delf"
#define DEL_ALL			"dela"

static struct proc_dir_entry *proc_list;
static struct proc_dir_entry *proc_list_read;
static struct proc_dir_entry *proc_list_write;

struct string_node {
	char *str;
	struct list_head node;
};

/* where to add/delete */
enum which_node {
	FIRST = 0,
	LAST,
	ALL
};

static LIST_HEAD(head);
static DEFINE_RWLOCK(lock);

static int list_proc_show(struct seq_file *m, void *v)
{
	struct list_head *p;
	struct string_node *string;

	read_lock(&lock);
	list_for_each(p, &head) {
		string = list_entry(p, struct string_node, node);
		seq_printf(m, "%s\n", string->str);
	}
	read_unlock(&lock);

	return 0;
}

static int list_read_open(struct inode *inode, struct file *file)
{
	return single_open(file, list_proc_show, NULL);
}

static int list_write_open(struct inode *inode, struct file *file)
{
	return single_open(file, list_proc_show, NULL);
}

static struct string_node *create_node(char *new_str)
{
	size_t len = strlen(new_str);
	struct string_node *new_node = kmalloc(sizeof(*new_node), GFP_KERNEL);

	if (!new_node)
		return NULL;

	new_node->str = kmalloc(len, GFP_KERNEL);
	if (!new_node->str) {
		kfree(new_node);
		return NULL;
	}

	new_node->str[len - 1] = '\0';
	memcpy(new_node->str, new_str, len - 1);

	return new_node;
}

static int add(char *new_str, enum which_node which)
{
	struct string_node *new_node;

	if (which == ALL)
		return 0;

	new_node = create_node(new_str);
	if (!new_node)
		return -ENOMEM;

	write_lock(&lock);
	if (which == FIRST)
		list_add(&new_node->node, &head);
	else
		list_add(&new_node->node, head.prev);
	write_unlock(&lock);

	return 0;
}

static void del(char *new_str, enum which_node which)
{
	struct list_head *p, *tmp;
	struct string_node *crt;
	size_t len;

	if (which == LAST)
		return;

	/* Remove the \n from 'echo'. */
	len = strlen(new_str) - 1;

	/**
	 * The write lock is only needed when removing a node.
	 * Otherwise, a read lock is sufficient.
	*/
	read_lock(&lock);
	list_for_each_safe(p, tmp, &head) {
		crt = list_entry(p, struct string_node, node);
		if (!memcmp(crt->str, new_str, len)) {
			read_unlock(&lock);
			write_lock(&lock);
			list_del(p);
			write_unlock(&lock);

			kfree(crt->str);
			kfree(crt);

			if (which == FIRST)
				return;

			read_lock(&lock);
		}
	}
	read_unlock(&lock);
}

static ssize_t list_write(struct file *file, const char __user *buffer,
			  size_t count, loff_t *offs)
{
	char local_buffer[PROCFS_MAX_SIZE + 1];  /* extra byte for \0 */
	unsigned long local_buffer_size = 0;
	int ret = 0;

	local_buffer_size = count;
	if (local_buffer_size > PROCFS_MAX_SIZE)
		local_buffer_size = PROCFS_MAX_SIZE;

	memset(local_buffer, 0, sizeof(local_buffer));
	if (copy_from_user(local_buffer, buffer, local_buffer_size))
		return -EFAULT;

	/* local_buffer contains the command written in /proc/list/management */
	if (!memcmp(local_buffer, ADD_FIRST, sizeof(ADD_FIRST) - 1))
		ret = add(local_buffer + sizeof(ADD_FIRST), FIRST);
	else if (!memcmp(local_buffer, ADD_END, sizeof(ADD_END) - 1))
		ret = add(local_buffer + sizeof(ADD_END), LAST);
	else if (!memcmp(local_buffer, DEL_FIRST, sizeof(DEL_FIRST) - 1))
		del(local_buffer + sizeof(DEL_FIRST), FIRST);
	else if (!memcmp(local_buffer, DEL_ALL, sizeof(DEL_ALL) - 1))
		del(local_buffer + sizeof(DEL_ALL), ALL);

	if (ret)
		return ret;

	return local_buffer_size;
}

static const struct proc_ops r_pops = {
	.proc_open	= list_read_open,
	.proc_read	= seq_read,
	.proc_release	= single_release,
};

static const struct proc_ops w_pops = {
	.proc_open	= list_write_open,
	.proc_write	= list_write,
	.proc_release	= single_release,
};

static int list_init(void)
{
	proc_list = proc_mkdir(procfs_dir_name, NULL);
	if (!proc_list)
		return -ENOMEM;

	proc_list_read = proc_create(procfs_file_read, 0000, proc_list,
				     &r_pops);
	if (!proc_list_read)
		goto proc_list_cleanup;

	proc_list_write = proc_create(procfs_file_write, 0000, proc_list,
				      &w_pops);
	if (!proc_list_write)
		goto proc_list_read_cleanup;

	return 0;

proc_list_read_cleanup:
	proc_remove(proc_list_read);
proc_list_cleanup:
	proc_remove(proc_list);
	return -ENOMEM;
}

static void list_exit(void)
{
	struct list_head *p, *tmp;
	struct string_node *crt;

	/**
	 * Purge the list.
	 * There isn't much to read, so a write lock is preferred.
	 */
	write_lock(&lock);
	list_for_each_safe(p, tmp, &head) {
		crt = list_entry(p, struct string_node, node);
		list_del(p);

		kfree(crt->str);
		kfree(crt);
	}
	write_unlock(&lock);

	proc_remove(proc_list);
}

module_init(list_init);
module_exit(list_exit);

MODULE_DESCRIPTION("Linux kernel list API");
MODULE_AUTHOR("Teodor-Stefan Dutu <teodor.dutu@gmail.com>");
MODULE_LICENSE("GPL v2");
