/*
 * SO2 Lab - Block device drivers (#7)
 * Linux - Exercise #4, #5 (Relay disk - bio)
 */

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/fs.h>
#include <linux/wait.h>
#include <linux/sched.h>
#include <linux/genhd.h>
#include <linux/blkdev.h>

MODULE_AUTHOR("SO2");
MODULE_DESCRIPTION("Relay disk");
MODULE_LICENSE("GPL");

#define KERN_LOG_LEVEL		KERN_ALERT

#define PHYSICAL_DISK_NAME	"/dev/vdb"
#define KERNEL_SECTOR_SIZE	512

#define BIO_WRITE_MESSAGE	"manele 2021"


/* pointer to physical device structure */
static struct block_device *phys_bdev;

static void send_test_bio(struct block_device *bdev, int dir)
{
	blk_qc_t ret;
	struct bio *bio = bio_alloc(GFP_NOIO, 1);
	struct page *page;
	char *buf;

	/* TODO 4: fill bio (bdev, sector, direction) */
	bio->bi_disk = bdev->bd_disk;
	bio->bi_iter.bi_sector = 0;
	bio->bi_opf = dir;

	page = alloc_page(GFP_NOIO);
	bio_add_page(bio, page, KERNEL_SECTOR_SIZE, 0);

	/* TODO 5: write message to bio buffer if direction is write */
	if (dir == WRITE) {
		buf = kmap_atomic(page);
		if (!buf) {
			pr_err("kmap failed\n");
			goto out;
		}

		memcpy(buf, BIO_WRITE_MESSAGE, sizeof(BIO_WRITE_MESSAGE));

		kunmap_atomic(buf);
	}

	/* TODO 4: submit bio and wait for completion */
	ret = submit_bio_wait(bio);
	if (ret == BLK_QC_T_NONE) {
		pr_err("Failed to submit bio\n");
		goto out;
	}

	/* TODO 4: read data (first 3 bytes) from bio buffer and print it */
	buf = kmap_atomic(page);
	if (!buf) {
		pr_err("kmap failed\n");
		goto out;
	}

	pr_info("0x%02X 0x%02X 0x%02X\n", buf[0], buf[1], buf[2]);
	kunmap_atomic(buf);

	bio_put(bio);

out:
	__free_page(page);
}

static struct block_device *open_disk(char *name)
{
	/* TODO 4: get block device in exclusive mode */
	return blkdev_get_by_path(
		name,
		FMODE_READ | FMODE_WRITE | FMODE_EXCL,
		THIS_MODULE
	);
}

static int __init relay_init(void)
{
	phys_bdev = open_disk(PHYSICAL_DISK_NAME);
	if (phys_bdev == NULL) {
		printk(KERN_ERR "[relay_init] No such device\n");
		return -EINVAL;
	}

	send_test_bio(phys_bdev, REQ_OP_READ);

	return 0;
}

static void close_disk(struct block_device *bdev)
{
	/* TODO 4: put block device */
	blkdev_put(bdev, FMODE_READ | FMODE_WRITE | FMODE_EXCL);
}

static void __exit relay_exit(void)
{
	/* TODO 5: send test write bio */
	send_test_bio(phys_bdev, REQ_OP_WRITE);

	close_disk(phys_bdev);
}

module_init(relay_init);
module_exit(relay_exit);
