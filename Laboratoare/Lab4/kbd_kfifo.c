#include <linux/module.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/fs.h>
#include <linux/cdev.h>
#include <asm/io.h>
#include <linux/uaccess.h>
#include <linux/ioport.h>
#include <linux/interrupt.h>
#include <linux/spinlock.h>
#include <linux/kfifo.h>

MODULE_DESCRIPTION("KBD");
MODULE_AUTHOR("Kernel Hacker");
MODULE_LICENSE("GPL");

#define MODULE_NAME		"kbd-kfifo"

#define KBD_MAJOR		42
#define KBD_MINOR		0
#define KBD_NR_MINORS		1

#define I8042_KBD_IRQ		1
#define I8042_STATUS_REG	0x64
#define I8042_DATA_REG		0x60

#define BUFFER_SIZE		1024
#define SCANCODE_RELEASED_MASK	0x80

struct kbd {
	struct cdev cdev;
	char buf[BUFFER_SIZE];
	struct kfifo fifo;
	spinlock_t lock;
} devs[1];

/*
 * Checks if scancode corresponds to key press or rele	ase.
 */
static int is_key_press(unsigned int scancode)
{
	return !(scancode & SCANCODE_RELEASED_MASK);
}

/*
 * Return the character of the given scancode.
 * Only works for alphanumeric/space/enter; returns '?' for other
 * characters.
 */
static int get_ascii(unsigned int scancode)
{
	static char *row1 = "1234567890";
	static char *row2 = "qwertyuiop";
	static char *row3 = "asdfghjkl";
	static char *row4 = "zxcvbnm";

	scancode &= ~SCANCODE_RELEASED_MASK;
	if (scancode >= 0x02 && scancode <= 0x0b)
		return *(row1 + scancode - 0x02);
	if (scancode >= 0x10 && scancode <= 0x19)
		return *(row2 + scancode - 0x10);
	if (scancode >= 0x1e && scancode <= 0x26)
		return *(row3 + scancode - 0x1e);
	if (scancode >= 0x2c && scancode <= 0x32)
		return *(row4 + scancode - 0x2c);
	if (scancode == 0x39)
		return ' ';
	if (scancode == 0x1c)
		return '\n';
	return '?';
}

static irqreturn_t kbd_interrupt_handler(int irq_no, void *arg)
{
	ulong flags;
	u8 scancode = inb(I8042_DATA_REG);
	int pressed = is_key_press(scancode);
	char key = get_ascii(scancode);
	struct kbd *data = (struct kbd*)arg;

	pr_info(
		"IRQ: %d, scancode = 0x%X (%u) pressed=%d ch=%c\n",
		irq_no,
		scancode,
		scancode,
		pressed,
		key
	);

	spin_lock_irqsave(&data->lock, flags);
	kfifo_in(&data->fifo, &key, 1);
	spin_unlock_irqrestore(&data->lock, flags);

	return IRQ_NONE;
}

static int kbd_open(struct inode *inode, struct file *file)
{
	struct kbd *data = container_of(inode->i_cdev, struct kbd, cdev);

	file->private_data = data;
	pr_info("%s opened\n", MODULE_NAME);
	return 0;
}

static int kbd_release(struct inode *inode, struct file *file)
{
	pr_info("%s closed\n", MODULE_NAME);
	return 0;
}

static ssize_t kbd_write(struct file *file, const char __user *user_buffer,
			 size_t size, loff_t *offset)
{
	kfifo_reset(&((struct kbd *)file->private_data)->fifo);
	return size;
}

static ssize_t kbd_read(struct file *file, char __user *user_buffer,
			size_t size, loff_t *offset)
{	
	static char buff[BUFFER_SIZE];
	ulong flags;
	struct kbd *data = (struct kbd *)file->private_data;
	size_t to_read = min((loff_t)size, sizeof(buff) - *offset);
	size_t total_read;

	spin_lock_irqsave(&data->lock, flags);
	total_read = kfifo_out(&data->fifo, buff, to_read);
	spin_unlock_irqrestore(&data->lock, flags);

	if (!total_read)
		return 0;

	if (copy_to_user(user_buffer, data->buf + *offset, total_read))
		return -EFAULT;

	*offset += total_read;

	return total_read;
}

static const struct file_operations kbd_fops = {
	.owner = THIS_MODULE,
	.open = kbd_open,
	.release = kbd_release,
	.read = kbd_read,
	.write = kbd_write
};

static int kbd_init(void)
{
	int err;
	struct resource *res;

	err = register_chrdev_region(MKDEV(KBD_MAJOR, KBD_MINOR),
				     KBD_NR_MINORS, MODULE_NAME);
	if (err != 0) {
		pr_err("register_region failed: %d\n", err);
		goto out;
	}

	res = request_region(I8042_STATUS_REG + 1, 1, MODULE_NAME);
	if (!res) {
		pr_err("request failed for register 0x%X\n", I8042_STATUS_REG);
		err = -EBUSY;
		goto out_unregister;
	}

	res = request_region(I8042_DATA_REG + 1, 1, MODULE_NAME);
	if (!res) {
		pr_err("request failed for register 0x%X\n", I8042_DATA_REG);
		err = -EBUSY;
		goto out_release_status_reg;
	}

	spin_lock_init(&devs->lock);

	err = request_irq(
		I8042_KBD_IRQ,
		kbd_interrupt_handler,
		IRQF_SHARED,
		MODULE_NAME,
		devs
	);
	if (err) {
		pr_err("IRQ request failed\n");
		goto out_release_data_reg;
	}

	kfifo_init(&devs->fifo, devs->buf, sizeof(devs->buf));

	cdev_init(&devs[0].cdev, &kbd_fops);
	cdev_add(&devs[0].cdev, MKDEV(KBD_MAJOR, KBD_MINOR), 1);

	pr_notice("Driver %s loaded\n", MODULE_NAME);
	return 0;

out_release_data_reg:
	release_region(I8042_DATA_REG, 1);

out_release_status_reg:
	release_region(I8042_STATUS_REG, 1);

out_unregister:
	unregister_chrdev_region(MKDEV(KBD_MAJOR, KBD_MINOR),
				 KBD_NR_MINORS);
out:
	return err;
}

static void kbd_exit(void)
{
	cdev_del(&devs[0].cdev);

	free_irq(I8042_KBD_IRQ - 1, devs);

	release_region(I8042_DATA_REG, 1);
	release_region(I8042_STATUS_REG, 1);

	unregister_chrdev_region(MKDEV(KBD_MAJOR, KBD_MINOR),
				 KBD_NR_MINORS);
	pr_notice("Driver %s unloaded\n", MODULE_NAME);
}

module_init(kbd_init);
module_exit(kbd_exit);
