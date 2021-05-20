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


static sector_t
check_unallocated_block(__u16 *initial_blp, struct super_block *sb, bool create)
{
	__u16 block = *initial_blp;

	if (block != U16_MAX)
		return block;

	if (!create)
		return -EIO;

	block = pitix_alloc_block(sb);
	*initial_blp = block;
	return block;
}

int pitix_get_block(struct inode *inode, sector_t block,
		struct buffer_head *bh_result, int create)
{
	struct pitix_inode *pi = pitix_i(inode);
	struct super_block *sb = inode->i_sb;
	struct pitix_super_block *psb = pitix_sb(sb);
	__u8 dzone_block = psb->dzone_block;
	__u16 *indirect_block;
	struct buffer_head *indir_bh;
	int idx;
	bool new_indir = false;

	if (block >= get_blocks(sb))
		return -EINVAL;

	if (block < INODE_DIRECT_DATA_BLOCKS)
		block = check_unallocated_block(pi->direct_data_blocks + block,
			sb, create);
	else {
		if (pi->indirect_data_block == U16_MAX) {
			idx = pitix_alloc_block(sb);
			if (idx < 0)
				return idx;

			pi->indirect_data_block = idx;
			new_indir = true;
		}

		indir_bh = sb_bread(sb, dzone_block + pi->indirect_data_block);
		if (!indir_bh)
			return -ENOMEM;

		idx = block - INODE_DIRECT_DATA_BLOCKS;
		indirect_block = (__u16 *)indir_bh->b_data;
		if (new_indir)
			memset(indirect_block, U8_MAX, sb->s_blocksize);

		block = check_unallocated_block(indirect_block + idx, sb,
			create);

		mark_buffer_dirty(indir_bh);
		brelse(indir_bh);
	}

	map_bh(bh_result, inode->i_sb, dzone_block + block);

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
	return block_write_begin(mapping, pos, len, flags, pagep,
		pitix_get_block);
}

struct address_space_operations pitix_aops = {
	.readpage = pitix_readpage,
	.writepage = pitix_writepage,
	.write_begin = pitix_write_begin,
	.write_end = generic_write_end
};
