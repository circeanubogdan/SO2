// SPDX-License-Identifier: GPL-2.0+

/*
 * ssr.c - Simple Software Raid
 *
 * Author:
 *	Adina Smeu <adina.smeu@gmail.com>,
 *	Teodor Dutu <teodor.dutu@gmail.com>
 */

#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/module.h>

#include <linux/blk_types.h>
#include <linux/blkdev.h>
#include <linux/blk-mq.h>

#include <linux/workqueue.h>

#include "ssr.h"


#define LOGICAL_DISK_BASE_NAME	"ssr"
#define NUM_PHYS_DEV		2

#define NR_HW_QUEUES		1
#define QUEUE_DEPTH		128
#define CMD_SIZE		0


struct work_info {
	int devno;
	struct bio *bio;
	struct work_struct work;
};

static struct ssr_phys_bdev {
	struct block_device *bdev;
} phys_bdev[NUM_PHYS_DEV];

static struct ssr_dev {
	size_t size;
	u8 *data;
	struct request_queue *queue;
	struct gendisk *gd;
	struct work_struct work;
	struct blk_mq_tag_set tag_set;
} g_dev;

static void ssr_work_handler(struct work_struct *work)
{
}

static int ssr_open(struct block_device *bdev, fmode_t mode)
{
	return 0;
}

static void ssr_release(struct gendisk *gd, fmode_t mode)
{
}

static struct bio *create_bio(struct bio *bio)
{
	return bio;
}

static struct work_info
*create_work_info(int devno, struct bio *bio)
{
	struct work_info *info = kmalloc(sizeof(*info), GFP_KERNEL);
	if (!info) {
		pr_err("Cannot allocate work_info\n");
		return NULL;
	}

	info->devno = devno;
	info->bio = create_bio(bio);

	return info;
}

static blk_qc_t ssr_submit_bio(struct bio *bio)
{
	pr_info("Dir: %d\n", bio->bi_opf);
	if (bio_data_dir(bio) == WRITE)
		pr_info("Write\n");
	else if (bio_data_dir(bio) == READ)
		pr_info("Read\n");

	// schedule_work(&g_dev.work);

	return BLK_QC_T_NONE;
}

static const struct block_device_operations ssr_block_ops = {
	.owner = THIS_MODULE,
	.open = ssr_open,
	.release = ssr_release,
	.submit_bio = ssr_submit_bio,
};

static blk_status_t
ssr_request(struct blk_mq_hw_ctx *hctx, const struct blk_mq_queue_data *bd)
{
	// TODO: alt return?
	return BLK_STS_OK;
}

static struct blk_mq_ops ssr_queue_ops = {
	.queue_rq = ssr_request,
};

static int create_block_device(struct ssr_dev *dev)
{
	int err;

	dev->size = LOGICAL_DISK_SECTORS * KERNEL_SECTOR_SIZE;
	dev->data = vmalloc(dev->size);
	if (dev->data == NULL) {
		pr_err("vmalloc: out of memory\n");
		err = -ENOMEM;
		goto out_vmalloc;
	}

	/* Initialize tag set. */
	dev->tag_set.ops = &ssr_queue_ops;
	dev->tag_set.nr_hw_queues = NR_HW_QUEUES;
	dev->tag_set.queue_depth = QUEUE_DEPTH;
	dev->tag_set.numa_node = NUMA_NO_NODE;
	dev->tag_set.cmd_size = CMD_SIZE;
	dev->tag_set.flags = BLK_MQ_F_SHOULD_MERGE;
	err = blk_mq_alloc_tag_set(&dev->tag_set);
	if (err) {
		pr_err("blk_mq_alloc_tag_set: can't allocate tag set\n");
		goto out_alloc_tag_set;
	}

	/* Allocate queue. */
	dev->queue = blk_mq_init_queue(&dev->tag_set);
	if (IS_ERR(dev->queue)) {
		pr_err("blk_mq_init_queue: out of memory\n");
		err = -ENOMEM;
		goto out_blk_init;
	}
	blk_queue_logical_block_size(dev->queue, KERNEL_SECTOR_SIZE);
	dev->queue->queuedata = dev;

	/* Initialize the gendisk structure. */
	dev->gd = alloc_disk(SSR_NUM_MINORS);
	if (!dev->gd) {
		pr_err("alloc_disk: failure\n");
		err = -ENOMEM;
		goto out_alloc_disk;
	}

	dev->gd->major = SSR_MAJOR;
	dev->gd->first_minor = SSR_FIRST_MINOR;
	dev->gd->fops = &ssr_block_ops;
	dev->gd->queue = dev->queue;
	dev->gd->private_data = dev;
	memcpy(
		dev->gd->disk_name,
		LOGICAL_DISK_BASE_NAME,
		sizeof(LOGICAL_DISK_BASE_NAME)
	);
	set_capacity(dev->gd, LOGICAL_DISK_SECTORS);

	add_disk(dev->gd);

	INIT_WORK(&dev->work, ssr_work_handler);

	return 0;

out_alloc_disk:
	blk_cleanup_queue(dev->queue);
out_blk_init:
	blk_mq_free_tag_set(&dev->tag_set);
out_alloc_tag_set:
	vfree(dev->data);
out_vmalloc:
	return err;
}

static void delete_block_device(struct ssr_dev *dev)
{
	cancel_work_sync(&dev->work);

	if (dev->gd) {
		del_gendisk(dev->gd);
		put_disk(dev->gd);
	}

	if (dev->queue)
		blk_cleanup_queue(dev->queue);
	if (dev->tag_set.tags)
		blk_mq_free_tag_set(&dev->tag_set);
	if (dev->data)
		vfree(dev->data);
}

static void close_disk(struct block_device *bdev)
{
	blkdev_put(bdev, FMODE_READ | FMODE_WRITE | FMODE_EXCL);
}

static void close_disks(void)
{
	int i;

	for (i = 0; i < NUM_PHYS_DEV; ++i)
		close_disk(phys_bdev[i].bdev);
}

static struct block_device *open_disk(char *name)
{
	struct block_device *bdev;

	// TODO scapa de apelul de functie daca te scarbeste
	/* Get block device in exclusive mode. */
	bdev = blkdev_get_by_path(
		name,
		FMODE_READ | FMODE_WRITE | FMODE_EXCL,
		THIS_MODULE);

	return bdev;
}

static int open_disks(void)
{
	// TODO generalizare?
	phys_bdev[0].bdev = open_disk(PHYSICAL_DISK1_NAME);
	if (phys_bdev[0].bdev == NULL) {
		pr_err("No such device: %s\n", PHYSICAL_DISK1_NAME);
		return -EINVAL;
	}

	phys_bdev[1].bdev = open_disk(PHYSICAL_DISK2_NAME);
	if (phys_bdev[1].bdev == NULL) {
		pr_err("No such device: %s\n", PHYSICAL_DISK2_NAME);
		goto out_close_disk;
	}

	return 0;

out_close_disk:
	close_disk(phys_bdev[0].bdev);

	return -EINVAL;
}

static int __init ssr_init(void)
{
	int err = 0;

	err = open_disks();
	if (err < 0)
		return err;

	err = register_blkdev(SSR_MAJOR, LOGICAL_DISK_NAME);
	if (err < 0) {
		pr_err(
			"Unable to register %s block device\n",
			LOGICAL_DISK_NAME
		);
		goto out_close_disks;
	}

	err = create_block_device(&g_dev);
	if (err) {
		pr_err("Unable to create block device\n");
		goto out;
	}

	return 0;

out:
	unregister_blkdev(SSR_MAJOR, LOGICAL_DISK_NAME);
out_close_disks:
	close_disks();

	return err;
}

static void __exit ssr_exit(void)
{
	delete_block_device(&g_dev);
	unregister_blkdev(SSR_MAJOR, LOGICAL_DISK_NAME);
	close_disks();
}

module_init(ssr_init);
module_exit(ssr_exit);


MODULE_DESCRIPTION("Simple Software Raid");
MODULE_AUTHOR(
	"Adina Smeu <adina.smeu@gmail.com>, Teodor Dutu <teodor.dutu@gmail.com>"
);
MODULE_LICENSE("GPL v2");
