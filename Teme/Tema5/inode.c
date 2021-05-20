// SPDX-License-Identifier: GPL-2.0+

/*
 * pitix.c - PITIX-2 Filesystem
 *
 * Author: Teodor Dutu <teodor.dutu@gmail.com>
 */
#include <linux/buffer_head.h>
#include <linux/cred.h>
#include <linux/statfs.h>
#include <linux/fs.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/pagemap.h>
#include <linux/sched.h>
#include <linux/slab.h>

#include "pitix.h"
#include "pitix_info.h"


static void pitix_put_super(struct super_block *sb)
{
	struct pitix_super_block *psb = sb->s_fs_info;
	struct pitix_super_block *aux = (struct pitix_super_block *)psb->sb_bh->b_data;

	psb->sb_bh = sb_bread(sb, PITIX_SUPER_BLOCK);

	pr_info("[pitix_put_super]: mag = %lu; v = %hhu; bs = %hhu; imap = %hhu; dmap = %hhu; izone = %hhu; dzone = %hhu; bfree = %hu; ffree = %hu;\n",
		psb->magic, psb->version, psb->block_size_bits, psb->imap_block,
		psb->dmap_block, psb->izone_block, psb->dzone_block, aux->bfree,
		aux->ffree);

	memcpy(psb->sb_bh->b_data, psb, sizeof(*psb));

	mark_buffer_dirty(psb->sb_bh);
	mark_buffer_dirty(psb->dmap_bh);
	mark_buffer_dirty(psb->imap_bh);

	brelse(psb->sb_bh);
	brelse(psb->dmap_bh);
	brelse(psb->imap_bh);
}

static struct inode *pitix_allocate_inode(struct super_block *s)
{
	struct inode *inode = kzalloc(sizeof(*inode), GFP_KERNEL);

	if (!inode)
		return NULL;

	inode_init_once(inode);

	return inode;
}

void pitix_evict_inode(struct inode *inode)
{
	// TODO: repara iput + kfree(pi)
	// TODO: elibereaza din imap
	mark_inode_dirty(inode);
	kfree(inode);
}

int pitix_write_inode(struct inode *inode, struct writeback_control *wbc)
{
	struct pitix_inode *pi, *orig_pi = pitix_i(inode);
	struct pitix_super_block *psb = pitix_sb(inode->i_sb);
	long inodes_per_block = pitix_inodes_per_block(inode->i_sb);
	ulong block = inode->i_ino / inodes_per_block + psb->izone_block;
	struct buffer_head *bh = sb_bread(inode->i_sb, block);

	if (!bh)
		return -ENOMEM;

	pi = (struct pitix_inode *)bh->b_data + inode->i_ino % inodes_per_block;

	init_pitix_info(pi, inode);
	pi->indirect_data_block = orig_pi->indirect_data_block;
	memcpy(pi->direct_data_blocks, orig_pi->direct_data_blocks,
		sizeof(pi->direct_data_blocks));

	mark_buffer_dirty(bh);
	brelse(bh);

	return 0;
}

static int pitix_statfs(struct dentry *dentry, struct kstatfs *statfs)
{
	struct super_block *sb = dentry->d_inode->i_sb;
	struct pitix_super_block *psb = pitix_sb(sb);

	simple_statfs(dentry, statfs);

	statfs->f_bfree = psb->bfree;
	statfs->f_ffree = psb->ffree;
	statfs->f_blocks = get_blocks(sb);
	statfs->f_files = get_inodes(sb);

	return 0;
}

static const struct super_operations pitix_ops = {
	.statfs = pitix_statfs,
	.put_super = pitix_put_super,
	.alloc_inode = pitix_allocate_inode,
	.destroy_inode = pitix_evict_inode,
	.write_inode = pitix_write_inode,
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

	if (!(inode = iget_locked(s, ino))) {
		pr_err("iget_locked failed\n");
		return ERR_PTR(-ENOMEM);
	}

	if (!(inode->i_state & I_NEW))
		return inode;

	if (!(pi = read_inode_from_disk(s, ino, &bh))) {
		iget_failed(inode);
		return ERR_PTR(-EIO);
	}
	inode->i_private = pi;

	inode->i_sb = s;
	inode->i_mode = pi->mode;
	inode->i_size = pi->size;
	inode->i_mtime = inode->i_atime= inode->i_ctime = current_time(inode);
	i_uid_write(inode, pi->uid);
	i_gid_write(inode, pi->gid);
	inode->i_blocks = 0;
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
	struct pitix_super_block *psb = pitix_sb(s);
	struct inode *root_inode;
	struct dentry *root_dentry;
	struct buffer_head *bh;
	int ret = -EINVAL;

	pr_info("[pitix_fill_super]\n");
	if (psb) {
		brelse(psb->sb_bh);
		brelse(psb->imap_bh);
		brelse(psb->dmap_bh);
	}

	if (!sb_set_blocksize(s, PITIX_SUPER_BLOCK_SIZE))
		goto out_kfree_psb;

	if (!(bh = sb_bread(s, PITIX_SUPER_BLOCK)))
		goto out_kfree_psb;

	psb = (struct pitix_super_block *)bh->b_data;
	pr_info("[pitix_fill_super]: mag = %lu; v = %hhu; bs = %hhu; imap = %hhu; dmap = %hhu; izone = %hhu; dzone = %hhu; bfree = %hu; ffree = %hu;\n",
		psb->magic, psb->version, psb->block_size_bits, psb->imap_block,
		psb->dmap_block, psb->izone_block, psb->dzone_block, psb->bfree,
		psb->ffree);

	if (psb->magic != PITIX_MAGIC
			|| psb->version != PITIX_VERSION
			|| !psb->imap_block || !psb->dmap_block)
		goto out_brelease_bh;

	if (!sb_set_blocksize(s, POW2(psb->block_size_bits)))
		goto out_brelease_bh;

	s->s_magic = psb->magic;
	s->s_op = &pitix_ops;
	s->s_fs_info = psb;
	psb->sb_bh = bh;

	// if(!(psb->imap_bh = sb_bread(s, psb->imap_block))) {
	// 	pr_err("failed to read imap block");
	// 	goto out_brelease_bh;
	// }
	// psb->imap = psb->imap_bh->b_data;

	// if(!(psb->dmap_bh = sb_bread(s, psb->dmap_block))) {
	// 	pr_err("failed to read dmap block");
	// 	goto out_brelease_imap_bh;
	// }
	// psb->dmap = psb->dmap_bh->b_data;

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


struct inode *pitix_new_inode(struct super_block *sb)
{
	struct inode *inode;
	struct pitix_inode *pi;
	struct buffer_head *bh;
	struct pitix_super_block *psb = pitix_sb(sb);
	int idx = pitix_alloc_inode(sb);
	int inodes_per_block = pitix_inodes_per_block(sb);
	
	if (idx == -ENOSPC)
		return NULL;

	if (!(bh = sb_bread(sb, psb->izone_block + idx / inodes_per_block))) {
		pr_err("failed to read izone block %d\n", idx);
		// TODO: pune la loc bitul idx in imap
		return NULL;
	}
	pi = (struct pitix_inode *)bh->b_data + idx % inodes_per_block;

	inode = new_inode(sb);
	inode->i_uid = current_fsuid();
	inode->i_gid = current_fsgid();
	inode->i_ino = idx;
	inode->i_mtime = inode->i_atime = inode->i_ctime = current_time(inode);
	inode->i_blocks = 0;
	inode->i_size = 0;
	inode->i_private = pi;

	init_pitix_info(pi, inode);
	insert_inode_hash(inode);

	mark_buffer_dirty(bh);
	brelse(bh);

	return inode;
}
