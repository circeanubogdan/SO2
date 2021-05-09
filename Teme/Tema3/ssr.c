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

#include <linux/crc32.h>

#include "ssr.h"


#define LOGICAL_DISK_BASE_NAME	"ssr"
#define NUM_PHYS_DEV		2

#define NR_HW_QUEUES		1
#define QUEUE_DEPTH		128
#define CMD_SIZE		0


struct work_info {
	int devno;  // TODO: de scos
	struct bio *bio;
	struct work_struct work;
};

static struct block_device *phys_bdev[NUM_PHYS_DEV];
static char* phys_disk_names[] = {PHYSICAL_DISK1_NAME, PHYSICAL_DISK2_NAME};

static DEFINE_MUTEX(lock_dev0);
static DEFINE_MUTEX(lock_dev1);

static struct ssr_dev {
	size_t size;
	u8 *data;
	struct request_queue *queue;
	struct gendisk *gd;
	struct blk_mq_tag_set tag_set;
} g_dev;


static struct bio *duplicate_bio(struct bio *bio, unsigned int devno)
{
	// TODO: dar bio_clone?
	struct bio_vec bvec;
	struct bvec_iter i;
	struct bio *new_bio = bio_alloc(GFP_NOIO, bio->bi_vcnt);

	if (!new_bio) {
		pr_err("failed to allocate bio\n");
		return NULL;
	}

	new_bio->bi_disk = phys_bdev[devno]->bd_disk;
	new_bio->bi_opf = bio->bi_opf;
	new_bio->bi_iter.bi_sector = bio->bi_iter.bi_sector;

	bio_for_each_segment(bvec, bio, i)
		if (!bio_add_page(new_bio, bvec.bv_page, bvec.bv_len,
				bvec.bv_offset)) {
			pr_err("bio_add_page failed\n");
			bio_put(new_bio);
			return NULL;
		}

	return new_bio;
}

static struct bio *
create_one_sector_bio(struct gendisk *bdev, sector_t sector, unsigned int dir)
{
	struct page *pg;
	struct bio *bio = bio_alloc(GFP_NOIO, 1);

	if (!bio) {
		pr_err("bio_alloc failed\n");
		return NULL;
	}

	pg = alloc_page(GFP_NOIO);
	if (!pg) {
		pr_err("alloc_page failed\n");
		goto err_alloc_page;
	}

	if (!bio_add_page(bio, pg, PAGE_SIZE, 0)) {
		pr_err("bio_add_page failed\n");
		goto err_bio_add_page;
	}

	bio->bi_disk = bdev;
	bio->bi_iter.bi_sector = sector;
	bio->bi_opf = dir;

	return bio;

err_bio_add_page:
	free_page((ulong)pg);
err_alloc_page:
	bio_put(bio);

	return NULL;
}


static bool copy_sector_data(char *buff, struct page *pg, unsigned int dir)
{
	bool ret = true;
	char *pg_buff = kmap_atomic(pg);

	if (!pg_buff) {
		pr_err("kmap_atomic failed\n");
		return false;
	}

	if (dir == WRITE)
		memcpy(pg_buff, buff, PAGE_SIZE);
	else if (dir == READ)
		memcpy(buff, pg_buff, PAGE_SIZE);
	else {
		pr_err("unknown data direction 0x%X\n", dir);
		ret = false;
	}

	kunmap_atomic(pg_buff);

	return ret;
}

// TODO: merge cu functiile de mai sus?
static void
handle_sector(char *buff, sector_t sector, struct gendisk *bdev,
		unsigned int dir)
{
	struct bio *bio = create_one_sector_bio(bdev, sector, dir);

	if (!bio) {
		pr_err("failed to create read bio\n");
		return;
	}

	if (!copy_sector_data(buff, bio->bi_io_vec->bv_page, dir)) {
		pr_err("failed to copy data to buffer\n");
		goto err_copy_sector_data;
	}

	submit_bio_wait(bio);

err_copy_sector_data:
	__free_page(bio->bi_io_vec->bv_page);
	bio_put(bio);
}

static inline void read_sector(char *buff, sector_t sector, struct gendisk *bdev)
{
	handle_sector(buff, sector, bdev, READ);
}

static inline void write_sector(char *buff, sector_t sector, struct gendisk *bdev)
{
	handle_sector(buff, sector, bdev, WRITE);
}

static void write_crc(struct bio *bio)
{
	bool written = false;
	u32 crc, i;
	size_t num_crc_sect = KERNEL_SECTOR_SIZE / sizeof(crc);
	sector_t crc_sect = bio->bi_iter.bi_sector / num_crc_sect
		+ LOGICAL_DISK_SECTORS;
	size_t crc_idx = (bio->bi_iter.bi_sector % num_crc_sect) * sizeof(crc);
	struct bio_vec bvec;
	struct bvec_iter it;
	char *buff, *prev_crc_buff;
	char *crc_buff = kmalloc(PAGE_SIZE, GFP_KERNEL);

	if (!crc_buff) {
		pr_err("kmalloc crc_buff failed\n");
		return;
	}

	// pr_info("initial: idx = %zu; crc_sect = %lld", crc_idx, crc_sect);
	read_sector(crc_buff, crc_sect, bio->bi_disk);
	// pr_info("crc citit:\n");
	// for (i = 0; i != 64; i += 4)
	// 	pr_info("0x%X\n", *(u32 *)(crc_buff + i));

	bio_for_each_segment(bvec, bio, it) {
		// pr_err("write_crc bl_len %d, bv_off %d\n", bvec.bv_len, bvec.bv_offset);
		buff = kmap_atomic(bvec.bv_page);
		if (!buff) {
			pr_err("kmap_atomic failed\n");
			continue;
		}
		// pr_info("Bio sector %lld; len = %u\n", it.bi_sector, bvec.bv_len);

		for (i = 0; i != bvec.bv_len; i += KERNEL_SECTOR_SIZE) {
			crc = crc32(0, buff + i, KERNEL_SECTOR_SIZE);
			// pr_info("0x%X\n", crc);
			*(u32 *)(crc_buff + crc_idx) = crc;

			crc_idx += sizeof(crc);
			if (crc_idx == PAGE_SIZE) {
				// pr_info("Write sector: %lld\n", crc_sect);
				write_sector(crc_buff,
					crc_sect,
					bio->bi_disk);

				crc_idx = 0;
				++crc_sect;
				written = true;
			}
		}

		kunmap_atomic(buff);
	}

	if (crc_idx) {
		if (written) {
			prev_crc_buff = kmalloc(PAGE_SIZE, GFP_KERNEL);
			if (!prev_crc_buff) {
				pr_err("kmalloc prev_crc_buff failed\n");
				goto err_prev_crc_buff;
			}

			read_sector(prev_crc_buff, crc_sect, bio->bi_disk);
			// for (i = 0; i != 32; i += 4)
			// 	pr_info("0x%X 0x%X 0x%X 0x%X",
			// 		*(int *)(prev_crc_buff + i),
			// 		*(int *)(prev_crc_buff + i + 1),
			// 		*(int *)(prev_crc_buff + i + 2),
			// 		*(int *)(prev_crc_buff + i + 3));
			memcpy(prev_crc_buff, crc_buff, crc_idx);
			// // pr_info("prev_crc:\n");
			// for (i = 0; i != 32; i += 4)
			// 	pr_info("0x%X 0x%X 0x%X 0x%X",
			// 		*(int *)(prev_crc_buff + i),
			// 		*(int *)(prev_crc_buff + i + 1),
			// 		*(int *)(prev_crc_buff + i + 2),
			// 		*(int *)(prev_crc_buff + i + 3));
			// pr_info("crc:\n");
			// for (i = 0; i != 32; i += 4)
			// 	pr_info("0x%X 0x%X 0x%X 0x%X",
			// 		*(int *)(crc_buff + i),
			// 		*(int *)(crc_buff + i + 1),
			// 		*(int *)(crc_buff + i + 2),
			// 		*(int *)(crc_buff + i + 3));
			// pr_info("Write final sector: %lld to idx %d\n", crc_sect, crc_idx);
			write_sector(prev_crc_buff, crc_sect, bio->bi_disk);

			kfree(prev_crc_buff);
		} else {
			// pr_info("crc scris:\n");
			// for (i = 0; i != 64; i += 4)
				// pr_info("0x%X\n", *(u32 *)(crc_buff + i));
			write_sector(crc_buff, crc_sect, bio->bi_disk);	
		}
	}
		

err_prev_crc_buff:
	kfree(crc_buff);
}

static void write_bio_with_crc(struct bio *bio)
{
	struct bio *bio_dev0 = duplicate_bio(bio, 0);
	struct bio *bio_dev1 = duplicate_bio(bio, 1);

	mutex_lock(&lock_dev0);
	write_crc(bio_dev0);
	mutex_unlock(&lock_dev0);
	submit_bio_wait(bio_dev0);
	bio_put(bio_dev0);

	mutex_lock(&lock_dev1);
	write_crc(bio_dev1);
	mutex_unlock(&lock_dev1);
	submit_bio_wait(bio_dev1);
	bio_put(bio_dev1);
}

static bool has_valid_crc(struct bio *bio)
{
	return true;
}

static void read_bio(struct bio *bio)
{
	// TODO: (poate) schimba la n dispozitive? merita?
	struct bio *bio_dev0 = duplicate_bio(bio, 0);
	struct bio *bio_dev1 = duplicate_bio(bio, 1);

	submit_bio_wait(bio_dev0);
	submit_bio_wait(bio_dev1);

	bio_put(bio_dev0);
	bio_put(bio_dev1);
}

static void ssr_work_handler(struct work_struct *work)
{
	struct work_info *wi = container_of(work, struct work_info, work);
	struct bio *bio = wi->bio;

	switch (bio_data_dir(bio))
	{
	case WRITE:
		write_bio_with_crc(bio);
		break;
	case READ:
		read_bio(bio);
		break;
	default:
		pr_err("unkown data directection\n");
		break;
	}

	bio_endio(bio);
	kfree(wi);
}


static int ssr_open(struct block_device *bdev, fmode_t mode)
{
	return 0;
}

static void ssr_release(struct gendisk *gd, fmode_t mode)
{
}

// TODO: de redenumit in create_work_info
static struct work_info *create_work_info_same_bio(struct bio *bio)
{
	struct work_info *info = kmalloc(sizeof(*info), GFP_KERNEL);
	if (!info) {
		pr_err("Cannot allocate work_info\n");
		return NULL;
	}

	INIT_WORK(&info->work, ssr_work_handler);
	info->devno = NUM_PHYS_DEV;
	info->bio = bio;

	return info;
}

// TODO: de sters
static struct work_info *create_work_info(int devno, struct bio *bio)
{
	struct work_info *info = create_work_info_same_bio(bio);

	info->bio = duplicate_bio(bio, devno);
	if (!info->bio) {
		pr_err("duplicate_bio failed\n");
		kfree(info);
		return NULL;
	}

	info->devno = devno;

	return info;
}

static blk_qc_t ssr_submit_bio(struct bio *bio)
{
	if(!schedule_work(&create_work_info_same_bio(bio)->work))
		pr_err("schedule_work failed\n");

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
	if (!dev->data) {
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
		close_disk(phys_bdev[i]);
}

static struct block_device *open_disk(char *name)
{
	/* Get block device in exclusive mode. */
	return blkdev_get_by_path(
		name,
		FMODE_READ | FMODE_WRITE | FMODE_EXCL,
		THIS_MODULE);
}

static int open_disks(void)
{
	int i, j;

	for (i = 0; i != NUM_PHYS_DEV; ++i) {
		phys_bdev[i] = open_disk(phys_disk_names[i]);
		if (!phys_bdev[i]) {
			pr_err("No such device: %s\n", phys_disk_names[i]);
			goto out_close_disks;
		}
	}

	return 0;

out_close_disks:
	for (j = 0; j != i; ++j)
		close_disk(phys_bdev[j]);

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
