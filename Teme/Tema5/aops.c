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


int pitix_get_block(struct inode *inode, sector_t block,
		struct buffer_head *bh_result, int create)
{
	struct pitix_inode *pi = pitix_i(inode);
	struct super_block *sb = inode->i_sb;
	__u8 dzone_block = pitix_sb(sb)->dzone_block;
	struct buffer_head *indir_bh;

	if (block >= get_blocks(sb))
		return -EINVAL;

	if (block < INODE_DIRECT_DATA_BLOCKS)
		block = pi->direct_data_blocks[block];
	else {
		indir_bh = sb_bread(sb, dzone_block + pi->indirect_data_block);
		if (!indir_bh)
			return -ENOMEM;

		block -= INODE_DIRECT_DATA_BLOCKS;
		block = ((__u16 *)indir_bh->b_data)[block];

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
	// int ret;

	return block_write_begin(mapping, pos, len, flags, pagep,
		pitix_get_block);
	// if (unlikely(ret))
	// 	minix_write_failed(mapping, pos + len);

	// return ret;
}

struct address_space_operations pitix_aops = {
	.readpage = pitix_readpage,
	.writepage = pitix_writepage,
	.write_begin = pitix_write_begin,
	.write_end = generic_write_end,
};
