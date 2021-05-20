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

#ifndef _PITIX_INFO_H_
#define _PITIX_INFO_H_

#define PITIX_NAME			"pitix"
#define PITIX_VERSION			2

#define PITIX_SUPER_BLOCK		0
#define PITIX_ROOT_INODE_OFFSET		0
#define PITIX_SUPER_BLOCK_SIZE		4096
#define POW2(bits)			(1 << (bits))


static inline void init_pitix_info(struct pitix_inode *pi, struct inode *inode)
{
	pi->mode = inode->i_mode;
	pi->uid = i_uid_read(inode);
	pi->gid = i_gid_read(inode);
	pi->size = inode->i_size;
	pi->time = inode->i_mtime.tv_sec;
	pi->indirect_data_block = U16_MAX;
	memset(pi->direct_data_blocks, U8_MAX, sizeof(pi->direct_data_blocks));
}

#endif  /* _PITIX_INFO_H_ */
