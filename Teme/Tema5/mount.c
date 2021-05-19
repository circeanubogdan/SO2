// SPDX-License-Identifier: GPL-2.0+

/*
 * pitix.c - PITIX-2 Filesystem
 *
 * Author: Teodor Dutu <teodor.dutu@gmail.com>
 */

#include <linux/buffer_head.h>
#include <linux/cred.h>
#include <linux/fs.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/pagemap.h>
#include <linux/sched.h>
#include <linux/slab.h>

#include "pitix.h"
#include "pitix_info.h"


static struct dentry *pitix_mount(struct file_system_type *fs_type,
		int flags, const char *dev_name, void *data)
{
	return mount_bdev(fs_type, flags, dev_name, data, pitix_fill_super);
}

static struct file_system_type pitix_fs_type = {
	.owner = THIS_MODULE,
	.name = PITIX_NAME,
	.mount = pitix_mount,
	.kill_sb = kill_block_super,  // TODO: trebuie schimbat?
	.fs_flags = FS_REQUIRES_DEV
};

static int __init pitix_init(void)
{
	return register_filesystem(&pitix_fs_type);
}

static void __exit pitix_exit(void)
{
	unregister_filesystem(&pitix_fs_type);
}

module_init(pitix_init);
module_exit(pitix_exit);


MODULE_DESCRIPTION("PITIX-2 Filesystem");
MODULE_AUTHOR("Teodor Dutu <teodor.dutu@gmail.com>");
MODULE_LICENSE("GPL v2");
