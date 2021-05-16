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


#define PITIX_NAME			"pitix"
#define PITIX_VERSION			2

#define PITIX_SUPER_BLOCK		0
#define PITIX_ROOT_INODE_OFFSET		0
#define PITIX_SUPER_BLOCK_SIZE		4096
#define POW2(bits)			(1 << (bits))


static int pitix_readdir(struct file *filp, struct dir_context *ctx)
{
	return 0;
}

static struct pitix_dir_entry *
pitix_find_entry(struct dentry *dentry, struct buffer_head **bhp)
{
	struct inode *dir = dentry->d_parent->d_inode;
	struct pitix_inode *pi = dir->i_private;
	struct super_block *sb = dir->i_sb;
	struct pitix_super_block *psb = pitix_sb(sb);
	int i, dentries_per_block = dir_entries_per_block(sb);
	const char *name = dentry->d_name.name;
	struct pitix_dir_entry *pde;
	struct buffer_head *bh;

	if (!(bh = sb_bread(sb, psb->dzone_block + pi->direct_data_blocks[0])))
		return ERR_PTR(-EINVAL);  // TODO: eroare mai buna
	*bhp = bh;

	for (i = 0; i != dentries_per_block; ++i) {
		pde = (struct pitix_dir_entry *)bh->b_data + i;
		if (pde->ino && !strcmp(name, pde->name))
			return pde;
	}

	return NULL;
}

static struct dentry *
pitix_lookup(struct inode *dir, struct dentry *dentry, unsigned int flags)
{
	struct super_block *sb = dir->i_sb;
	struct buffer_head *bh = NULL;
	struct pitix_dir_entry *pde = pitix_find_entry(dentry, &bh);
	struct inode *inode = NULL;

	dentry->d_op = sb->s_root->d_op;

	if (pde) {
		inode = pitix_iget(sb, pde->ino);
		if (IS_ERR(inode))
			return ERR_CAST(inode);
	}

	d_add(dentry, inode);
	brelse(bh);

	// TODO: sigur NULL?
	return NULL;
}

static int
pitix_create(struct inode *dir, struct dentry *dentry, umode_t mode, bool excl)
{
	return 0;
}

int pitix_get_block(struct inode *inode, sector_t block,
		struct buffer_head *bh_result, int create)
{
	// pr_info("ino = %ld; bl = %lld; bh_size = %d; create = %d",
	// 	inode->i_ino, block, bh_result->b_size, create);
	
	map_bh(bh_result, inode->i_sb, block);
	
	return 0;
}

static int pitix_writepage(struct page *page, struct writeback_control *wbc)
{
	return block_write_full_page(page, pitix_get_block, wbc);
}

static int pitix_readpage(struct file *file, struct page *page)
{
	return block_read_full_page(page, pitix_get_block);
}

static int
pitix_write_begin(struct file *file, struct address_space *mapping, loff_t pos,
		unsigned int len, unsigned int flags, struct page **pagep,
		void **fsdata)
{
	// int ret;

	return block_write_begin(mapping, pos, len, flags, pagep,
		pitix_get_block);
	// if (unlikely(ret))
	// 	minix_write_failed(mapping, pos + len);

	// return ret;
}

struct file_operations pitix_dir_operations = {
	.read = generic_read_dir,
	.iterate = pitix_readdir,
};

struct inode_operations pitix_dir_inode_operations = {
	.lookup = pitix_lookup,
	.create = pitix_create,
};

struct address_space_operations pitix_aops = {
	.readpage = pitix_readpage,
	.writepage = pitix_writepage,
	.write_begin = pitix_write_begin,
	.write_end = generic_write_end,
};

struct file_operations pitix_file_operations = {
	.read_iter = generic_file_read_iter,
	.write_iter = generic_file_write_iter,
	.mmap = generic_file_mmap,
	.llseek = generic_file_llseek,
	.fsync = generic_file_fsync,
	.splice_read = generic_file_splice_read
};

struct inode_operations pitix_file_inode_operations = {
	.getattr = simple_getattr,
	.setattr = simple_setattr
};


static void pitix_put_super(struct super_block *sb)
{
	struct pitix_super_block *psb = sb->s_fs_info;

	mark_buffer_dirty(psb->sb_bh);
	mark_buffer_dirty(psb->dmap_bh);
	mark_buffer_dirty(psb->imap_bh);

	brelse(psb->sb_bh);
	brelse(psb->dmap_bh);
	brelse(psb->imap_bh);
}

static const struct super_operations pitix_ops = {
	.statfs = simple_statfs,
	.put_super = pitix_put_super,
	// .alloc_inode	= minfs_alloc_inode,
	// .destroy_inode = minfs_destroy_inode,
	// .write_inode	= minfs_write_inode,
};

static struct pitix_inode *
read_inode_from_disk(struct super_block *s, ino_t ino, struct buffer_head **bhp)
{
	struct pitix_super_block *psb = pitix_sb(s);
	long inodes_per_block = pitix_inodes_per_block(s);
	sector_t block = psb->izone_block + ino / inodes_per_block;

	if (!(*bhp = sb_bread(s, block))) {
		pr_err("sb_bread failed for inode block %lu\n", ino);
		return NULL;
	}

	return (struct pitix_inode *)(*bhp)->b_data + ino % inodes_per_block;
}

struct inode *pitix_iget(struct super_block *s, ino_t ino)
{
	struct pitix_inode *pi;
	struct buffer_head *bh;
	struct inode *inode;

	inode = iget_locked(s, ino);
	if (!inode) {
		pr_err("iget_locked failed\n");
		return ERR_PTR(-ENOMEM);
	}

	if (!(inode->i_state & I_NEW))
		return inode;

	if (!(pi = read_inode_from_disk(s, ino, &bh))) {
		iget_failed(inode);
		return ERR_PTR(-EIO);
	}

	inode->i_sb = s;
	inode->i_mode = pi->mode;
	inode->i_size = pi->size;
	inode->i_mtime.tv_sec = inode->i_atime.tv_sec = inode->i_ctime.tv_sec
		= pi->time;
	inode->i_mtime.tv_nsec = 0;
	inode->i_atime.tv_nsec = 0;
	inode->i_ctime.tv_nsec = 0;
	i_uid_write(inode, pi->uid);
	i_gid_write(inode, pi->gid);
	inode->i_blocks = 0;
	inode->i_private = pi;
	inode->i_mapping->a_ops = &pitix_aops;

	if (S_ISREG(inode->i_mode)) {
		inode->i_op = &pitix_file_inode_operations;
		inode->i_fop = &pitix_file_operations;
	} else if (S_ISDIR(inode->i_mode)) {
		inode->i_op = &pitix_dir_inode_operations;
		inode->i_fop = &pitix_dir_operations;
	}

	// TODO: for-ul asta:
	// https://elixir.bootlin.com/linux/v5.10.14/source/fs/minix/inode.c#L507

	brelse(bh);
	unlock_new_inode(inode);

	return inode;
}

int pitix_fill_super(struct super_block *s, void *data, int silent)
{
	struct pitix_super_block *psb, *disk_psb;
	struct inode *root_inode;
	struct dentry *root_dentry;
	struct buffer_head *bh;
	int ret = -EINVAL;

	psb = kzalloc(sizeof(*psb), GFP_KERNEL);
	if (!psb)
		return -ENOMEM;
	s->s_fs_info = psb;

	if (!sb_set_blocksize(s, PITIX_SUPER_BLOCK_SIZE))
		goto out_kfree_psb;

	if (!(bh = sb_bread(s, PITIX_SUPER_BLOCK)))
		goto out_kfree_psb;

	disk_psb = (struct pitix_super_block *)bh->b_data;
	if (disk_psb->magic != PITIX_MAGIC
			|| disk_psb->version != PITIX_VERSION
			|| !disk_psb->imap_block || !disk_psb->dmap_block)
		goto out_brelease_bh;

	memcpy(psb, disk_psb, sizeof(*psb));

	if (!sb_set_blocksize(s, POW2(psb->block_size_bits)))
		goto out_brelease_bh;

	s->s_magic = psb->magic;
	s->s_op = &pitix_ops;

	psb->sb_bh = bh;
	if(!(psb->imap_bh = sb_bread(s, psb->imap_block))) {
		pr_err("failed to read imap block");
		goto out_brelease_bh;
	}
	psb->imap = psb->imap_bh->b_data;

	if(!(psb->dmap_bh = sb_bread(s, psb->dmap_block))) {
		pr_err("failed to read dmap block");
		goto out_brelease_imap_bh;
	}
	psb->dmap = psb->dmap_bh->b_data;

	root_inode = pitix_iget(s, PITIX_ROOT_INODE_OFFSET);
	if (!root_inode)
		goto out_brelease_dmap_bh;

	root_dentry = d_make_root(root_inode);
	if (!root_dentry)
		goto out_iput;
	s->s_root = root_dentry;

	return 0;

out_iput:
	iput(root_inode);
out_brelease_dmap_bh:
	brelse(psb->dmap_bh);
out_brelease_imap_bh:
	brelse(psb->imap_bh);
out_brelease_bh:
	brelse(bh);
out_kfree_psb:
	kfree(psb);

	return ret;
}

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
