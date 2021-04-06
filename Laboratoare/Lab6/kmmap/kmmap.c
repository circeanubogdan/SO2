/*
 * PSO - Memory Mapping Lab(#11)
 *
 * Exercise #1: memory mapping using kmalloc'd kernel areas
 */

#include <linux/version.h>
#include <linux/init.h>
#include <linux/module.h>
#include <linux/fs.h>
#include <linux/cdev.h>
#include <linux/slab.h>
#include <linux/vmalloc.h>
#include <asm/pgtable.h>
#include <linux/sched/mm.h>
#include <linux/sched.h>
#include <asm/io.h>
#include <asm/highmem.h>
#include <linux/rmap.h>
#include <asm/uaccess.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>

#include "../test/mmap-test.h"

MODULE_DESCRIPTION("simple mmap driver");
MODULE_AUTHOR("PSO");
MODULE_LICENSE("Dual BSD/GPL");

#define MY_MAJOR	42
/* how many pages do we actually kmalloc */
#define NPAGES		16

/* character device basic structure */
static struct cdev mmap_cdev;

/* pointer to kmalloc'd area */
static void *kmalloc_ptr;

/* pointer to the kmalloc'd area, rounded up to a page boundary */
static char *kmalloc_area;

static int my_open(struct inode *inode, struct file *filp)
{
	return 0;
}

static int my_release(struct inode *inode, struct file *filp)
{
	return 0;
}

static int my_read(struct file *file, char __user *user_buffer,
		size_t size, loff_t *offset)
{
	/* TODO 2: check size doesn't exceed our mapped area size */
	ssize_t to_read = min(size, (NPAGES + 2) * (size_t)PAGE_SIZE);
	if (to_read <= 0)
		return 0;

	/* TODO 2: copy from mapped area to user buffer */
	if (copy_to_user(user_buffer, kmalloc_ptr, to_read))
		return -EFAULT;

	return to_read;
}

static int my_write(struct file *file, const char __user *user_buffer,
		size_t size, loff_t *offset)
{
	/* TODO 2: check size doesn't exceed our mapped area size */
	ssize_t to_write = min(size, (NPAGES + 2) * (size_t)PAGE_SIZE);
	if (to_write <= 0)
		return 0;

	/* TODO 2: copy from user buffer to mapped area */
	if (copy_from_user(kmalloc_ptr, user_buffer, to_write))
		return -EFAULT;

	return to_write;
}

static int my_mmap(struct file *filp, struct vm_area_struct *vma)
{
	int ret;
	long length = vma->vm_end - vma->vm_start;

	/* do not map more than we can */
	if (length > NPAGES * PAGE_SIZE)
		return -EIO;

	/* TODO 1: map the whole physically contiguous area in one piece */
	ret = remap_pfn_range(
		vma,
		vma->vm_start,
		virt_to_phys(kmalloc_area) >> PAGE_SHIFT,
		length,
		vma->vm_page_prot
	);
	if (ret)
		pr_err(
			"Failed to remap page from address %p and length %ld\n",
			kmalloc_area,
			length
		);

	return ret;
}

static const struct file_operations mmap_fops = {
	.owner = THIS_MODULE,
	.open = my_open,
	.release = my_release,
	.mmap = my_mmap,
	.read = my_read,
	.write = my_write
};

static int my_seq_show(struct seq_file *seq, void *v)
{
	struct mm_struct *mm;
	struct vm_area_struct *vma_iter;
	unsigned long total = 0;

	/* TODO 3: Get current process' mm_struct */
	mm = get_task_mm(current);

	/* TODO 3: Iterate through all memory mappings */
	for (vma_iter = mm->mmap; vma_iter; vma_iter = vma_iter->vm_next) {
		pr_info("[0x%lX, %lX]\n", vma_iter->vm_start, vma_iter->vm_end);
		total += vma_iter->vm_end - vma_iter->vm_start;
	}

	/* TODO 3: Release mm_struct */
	mmput(mm);

	/* TODO 3: write the total count to file  */
	seq_printf(seq, "%lu", total);

	return 0;
}

static int my_seq_open(struct inode *inode, struct file *file)
{
	/* TODO 3: Register the display function */
	return single_open(file, my_seq_show, NULL);
}

static const struct proc_ops my_proc_ops = {
	.proc_open    = my_seq_open,
	.proc_read    = seq_read,
	.proc_lseek   = seq_lseek,
	.proc_release = single_release,
};

static int __init my_init(void)
{
	char *p;
	int ret = 0;
	int i;
	struct proc_dir_entry *proc;

	/* TODO 3: create a new entry in procfs */
	proc = proc_create(PROC_ENTRY_NAME, 0, NULL, &my_proc_ops);
	if (!proc) {
		pr_err("Failed to create procfs entry\n");
		goto out;
	}

	ret = register_chrdev_region(MKDEV(MY_MAJOR, 0), 1, "mymap");
	if (ret < 0) {
		pr_err("could not register region\n");
		goto out_no_chrdev;
	}

	/* TODO 1: allocate NPAGES+2 pages using kmalloc */
	kmalloc_ptr = kmalloc(PAGE_SIZE * (NPAGES + 2), GFP_KERNEL);

	/* TODO 1: round kmalloc_ptr to nearest page start address */
	kmalloc_area = (char *)PAGE_ALIGN((unsigned long)kmalloc_ptr);

	/* TODO 1: mark pages as reserved */
	/* TODO 1: write data in each page */
	for (i = 0, p = kmalloc_area; i != NPAGES + 2; ++i, p += PAGE_SIZE) {
		SetPageReserved(virt_to_page(p));
		*(int *)p = 0xddccbbaa;
	}

	/* Init device. */
	cdev_init(&mmap_cdev, &mmap_fops);
	ret = cdev_add(&mmap_cdev, MKDEV(MY_MAJOR, 0), 1);
	if (ret < 0) {
		pr_err("could not add device\n");
		goto out_kfree;
	}

	return 0;

out_kfree:
	kfree(kmalloc_ptr);
out_unreg:
	unregister_chrdev_region(MKDEV(MY_MAJOR, 0), 1);
out_no_chrdev:
	remove_proc_entry(PROC_ENTRY_NAME, NULL);
out:
	return ret;
}

static void __exit my_exit(void)
{
	int i;

	cdev_del(&mmap_cdev);

	/* TODO 1: clear reservation on pages and free mem. */
	for (i = 0; i != NPAGES + 2; ++i)
		ClearPageReserved(virt_to_page(kmalloc_area + i * PAGE_SIZE));
	kfree(kmalloc_ptr);

	unregister_chrdev_region(MKDEV(MY_MAJOR, 0), 1);
	/* TODO 3: remove proc entry */
	remove_proc_entry(PROC_ENTRY_NAME, NULL);
}

module_init(my_init);
module_exit(my_exit);
