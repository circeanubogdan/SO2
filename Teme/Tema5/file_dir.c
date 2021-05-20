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


static int pitix_readdir(struct file *filp, struct dir_context *ctx)
{
	struct pitix_dir_entry *pde;
	struct inode *inode = file_inode(filp);
	struct pitix_inode *pi = pitix_i(inode);
	struct super_block *sb = inode->i_sb;
	loff_t num_dentries = dir_entries_per_block(sb);
	struct buffer_head *bh = sb_bread(sb, pi->direct_data_blocks[0]);

	if (!bh) {
		pr_err("failed to read dentry block\n");
		return -ENOMEM;
	}

	for (; ctx->pos != num_dentries; ++ctx->pos) {
		pde = (struct pitix_dir_entry *)bh->b_data + ctx->pos;
		if (!pde->ino)
			continue;

		if (dir_emit(ctx, pde->name, sizeof(pde->name), pde->ino,
				DT_UNKNOWN)) {
			++ctx->pos;
			break;
		}
	}

	brelse(bh);

	return 0;
}

static struct pitix_dir_entry *
pitix_find_entry(struct dentry *dentry, struct buffer_head **bhp)
{
	struct inode *dir = dentry->d_parent->d_inode;
	struct pitix_inode *pi = pitix_i(dir);
	struct super_block *sb = dir->i_sb;
	struct pitix_super_block *psb = pitix_sb(sb);
	int i, num_dentries = dir_entries_per_block(sb);
	const char *name = dentry->d_name.name;
	struct pitix_dir_entry *pde;
	struct buffer_head *bh = sb_bread(sb, psb->dzone_block
		+ pi->direct_data_blocks[0]);

	if (!bh)
		return NULL;
	*bhp = bh;

	for (i = 0; i != num_dentries; ++i) {
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

	return NULL;
}

static int pitix_add_link(struct dentry *dentry, struct inode *inode)
{
	struct inode *dir = dentry->d_parent->d_inode;
	struct super_block *sb = dir->i_sb;
	struct pitix_inode *pi = pitix_i(inode);
	struct pitix_dir_entry *pde = NULL;
	int i, ret = 0, max_entries = dir_entries_per_block(sb);
	struct buffer_head *dir_bh = sb_bread(sb, pi->direct_data_blocks[0]);

	if (!dir_bh) {
		pr_err("failed to read directoty block\n");
		return -ENOMEM;
	}

	for (i = 0; i != max_entries; ++i) {
		pde = (struct pitix_dir_entry *)dir_bh->b_data + i;
		if (!pde->ino)
			break;
	}

	if (!pde) {
		ret = -ENOSPC;
		pr_err("directory full\n");
		goto out_brelse;
	}

	pde->ino = inode->i_ino;
	memcpy(pde->name, dentry->d_name.name, PITIX_NAME_LEN);
	dir->i_mtime = dir->i_ctime = current_time(inode);

	mark_buffer_dirty(dir_bh);

out_brelse:
	brelse(dir_bh);
	return ret;
}

static int
pitix_create(struct inode *dir, struct dentry *dentry, umode_t mode, bool excl)
{
	int ret;
	struct super_block *sb = dir->i_sb;
	struct pitix_inode *pi;
	struct inode *inode = inode = pitix_new_inode(sb);

	if (!inode) {
		pr_err("error allocationg new inode\n");
		return -ENOMEM;
	}

	pi = kzalloc(sizeof(*pi), GFP_KERNEL);
	if (!pi)
		goto out_iput;

	if (S_ISREG(mode)) {
		inode->i_op = &pitix_file_inode_operations;
		inode->i_fop = &pitix_file_operations;
	} else if (S_ISDIR(mode)) {
		inode->i_op = &pitix_dir_inode_operations;
		inode->i_fop = &pitix_dir_operations;
		inode->i_size = sb->s_blocksize;
	}
	inode->i_mapping->a_ops = &pitix_aops;

	inode->i_mode = mode;
	inode->i_private = pi;
	init_pitix_info(pi, inode);

	ret = pitix_add_link(dentry, inode);
	if (ret) {
		pr_err("failed to add inode %lu to dentry %s",
			inode->i_ino, dentry->d_name.name);
		goto out_kfree;
	}

	d_instantiate(dentry, inode);
	mark_inode_dirty(inode);

	return 0;

out_kfree:
	kfree(pi);
out_iput:
	iput(inode);
	return ret;
}

static int pitix_mkdir(struct inode *dir, struct dentry *dentry, umode_t mode)
{
	return pitix_create(dir, dentry, mode | S_IFDIR, false);
}

static int pitix_unlink(struct inode *dir, struct dentry *dentry)
{
	struct pitix_super_block *psb = pitix_sb(d_inode(dentry)->i_sb);

	++psb->ffree;
	++psb->bfree;

	return 0;
}

static int pitix_rmdir(struct inode *dir, struct dentry *dentry)
{
	struct pitix_super_block *psb = pitix_sb(d_inode(dentry)->i_sb);

	++psb->ffree;
	++psb->bfree;

	return 0;
}

struct file_operations pitix_dir_operations = {
	.read = generic_read_dir,
	.iterate = pitix_readdir,
	.llseek = generic_file_llseek,
	.fsync = generic_file_fsync
};

struct inode_operations pitix_dir_inode_operations = {
	.lookup = pitix_lookup,
	.create = pitix_create,
	.mkdir = pitix_mkdir,
	.rmdir = pitix_rmdir,
	.unlink = pitix_unlink,
	.getattr = simple_getattr
};

struct file_operations pitix_file_operations = {
	.read_iter = generic_file_read_iter,
	.write_iter = generic_file_write_iter,
	.mmap = generic_file_mmap,
	.llseek = generic_file_llseek,
	.fsync = generic_file_fsync,
	.splice_read = generic_file_splice_read,
	.open = generic_file_open
};

struct inode_operations pitix_file_inode_operations = {
	.getattr = simple_getattr,
	.setattr = simple_setattr
};
