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


int pitix_alloc_block(struct super_block *sb)
{
	struct pitix_super_block *psb = pitix_sb(sb);
	long max_blocks = get_blocks(sb);
	int idx;

	psb->dmap_bh = sb_bread(sb, psb->dmap_block);
	if (!psb->dmap_bh) {
		pr_err("unable to read DMAP\n");
		return -ENOMEM;
	}

	psb->dmap = psb->dmap_bh->b_data;
	idx = find_first_zero_bit((ulong *)psb->dmap, max_blocks);

	if (idx == max_blocks) {
		pr_err("DMAP full\n");
		return -ENOSPC;
	}

	__test_and_set_bit(idx, (ulong *)psb->dmap);
	mark_buffer_dirty(psb->dmap_bh);
	// brelse(psb->dmap_bh);
	--psb->bfree;

	return idx;
}

void pitix_free_block(struct super_block *sb, int block)
{
	struct pitix_super_block *psb = pitix_sb(sb);
	
	++psb->bfree;
	// TODO
}

int pitix_alloc_inode(struct super_block *sb)
{
	struct pitix_super_block *psb = pitix_sb(sb);
	long max_inodes = get_inodes(sb);
	int idx;

	psb->imap_bh = sb_bread(sb, psb->imap_block);
	if (!psb->imap_bh) {
		pr_err("unable to read IMAP\n");
		return -ENOMEM;
	}

	psb->imap = psb->imap_bh->b_data;
	idx = find_first_zero_bit((ulong *)psb->imap, max_inodes);

	if (idx == max_inodes) {
		pr_err("IMAP full\n");
		return -ENOSPC;
	}

	__test_and_set_bit(idx, (ulong *)psb->imap);
	mark_buffer_dirty(psb->imap_bh);
	// brelse(psb->dmap_bh);
	--psb->ffree;

	return idx;
}

void pitix_free_inode(struct super_block *sb, int ino)
{
	struct pitix_super_block *psb = pitix_sb(sb);
	
	++psb->ffree;
	// TODO
}
