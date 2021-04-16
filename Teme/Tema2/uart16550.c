// SPDX-License-Identifier: GPL-2.0+

/*
 * uart16550.c - UART Driver
 *
 * Author:
 *	Adina Smeu <adina.smeu@gmail.com>,
 *	Teodor Dutu <teodor.dutu@gmail.com>
 */
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/fs.h>
#include <linux/cdev.h>
#include <linux/ioport.h>
#include <linux/interrupt.h>
#include <linux/kfifo.h>
#include <linux/wait.h>

#include "uart16550.h"

#define MODULE_NAME	"uart16550"

#define DEFAULT_MAJOR	42

#define REGION_SIZE	8

#define SINGLE_MINOR	1
#define ALL_MINORS	2

#define KFIFO_SIZE	1024

#define DLL(base_addr)	(base_addr + 0)
#define DLH(base_addr)	(base_addr + 1)
#define IIR(base_addr)	(base_addr + 2)
#define LCR(base_addr)	(base_addr + 3)

#define DLAB		(1 << 7)

enum coms {COM1 = 0, COM2};

/* The base address, interrupt request number and minor for COM1 and COM2. */
static const int addr[] = {0x3f8, 0x2f8};
static const int iqr_no[] = {0x04, 0x03};
static const int minor[] = {0, 1};

static struct com_dev {
	struct cdev cdev;

	enum coms com_no;

	spinlock_t rx_lock;
	wait_queue_head_t rx_wq;
	DECLARE_KFIFO(rx_fifo, char, KFIFO_SIZE);

	spinlock_t tx_lock;
	wait_queue_head_t tx_wq;
	DECLARE_KFIFO(tx_fifo, char, KFIFO_SIZE);

	// TODO: erori daca nu e configurat
} devs[ALL_MINORS];


static int major = DEFAULT_MAJOR;
static int option = OPTION_BOTH;

// TODO: Verifica permisiuni
module_param(major, int, 0);
MODULE_PARM_DESC(major, "The major with which the device must be registered");
module_param(option, int, 0);
MODULE_PARM_DESC(option, "The registered serial ports");

static int uart_open(struct inode *inode, struct file *file)
{
	struct com_dev *data = container_of(
		inode->i_cdev,
		struct com_dev,
		cdev
	);

	file->private_data = data;

	return 0;
}

static ssize_t uart_read(
	struct file *file,
	char __user *user_buffer,
	size_t size,
	loff_t *offset
)
{
	struct com_dev *dev = (struct com_dev *) file->private_data;

	// TODO:

	// alte configurari

	// char *buf = kmalloc(sizeof(*buf) * size, GFP_KERNEL);
	// if (!buf)
	// 	return -ENOMEM;

	// sau fara buf, cu spin_lock_irqsave, kfifo_to_user,
	// spin_unlock_irqrestore

	// wait_event_interruptible(dev->tx_wq, ?)

	// kfifo_out_spinlocked(dev->tx_fifo, buf, to_read, dev->tx_lock)

	// copy_to_user(user_buffer, buf, to_read);

	// kfree(buf);

	return 0;
}

static ssize_t uart_write(
	struct file *file,
	const char __user *user_buffer,
	size_t size,
	loff_t *offset
)
{
	struct com_dev *dev = (struct com_dev *) file->private_data;

	// TODO:

	// alte configurari

	// char *buf = kmalloc(sizeof(*buf) * size, GFP_KERNEL);
	// if (!buf)
	// 	return -ENOMEM;

	// sau fara buf, cu spin_lock_irqsave, kfifo_from_user,
	// spin_unlock_irqrestore

	// copy_from_user(buf, user_buffer, to_write);

	// wait_event_interruptible(dev->rx_wq, ?)

	// kfifo_in_spinlocked(dev->rx_fifo, buf, to_write, dev->rx_lock)

	// kfree(buf);

	return 0;
}

static long uart_ioctl(
	struct file *file,
	unsigned int cmd,
	unsigned long arg
)
{
	int ret = 0;
	struct uart16550_line_info info;
	struct com_dev *dev = (struct com_dev *) file->private_data;

	if (copy_from_user(&info, (void *)arg, sizeof(info))) {
		pr_err("Invalid address: 0x%lX\n", arg);
		return -EFAULT;
	}

	switch (cmd) {
	case UART16550_IOCTL_SET_LINE:
		pr_info("New parameters:\n");
		pr_info("Baud: %d, len: %d\n", info.baud, info.len);
		pr_info("Par: %d, stop: %d\n", info.par, info.stop);

		/* LCR = {1b'{dlab}, 1b'{}, 3b'{par}, 1b'{stop}, 2b'{len}} */
		outb(
			DLAB | info.par | info.stop | info.len,
			LCR(addr[dev->com_no])
		);

		/*
		 * {DLH, DLL} = baud. We set DLH to 0 since `baud` from
		 * `struct uart16550_line_info` has only 8 bits.
		 */
		outb(info.baud, DLL(addr[dev->com_no]));
		outb(0, DLH(addr[dev->com_no]));

		pr_info(
			"Config: %d, Baud: %d\n",
			inb(LCR(addr[dev->com_no])),
			inb(DLL(addr[dev->com_no]))
		);

		outb(
			~DLAB & (info.par | info.stop | info.len),
			LCR(addr[dev->com_no])
		);

		// TODO: alte configurari

		break;

	default:
		ret = -EINVAL;
	}

	return ret;
}

static const struct file_operations uart_fops = {
	.owner = THIS_MODULE,
	.open = uart_open,
	.read = uart_read,
	.write = uart_write,
	.unlocked_ioctl = uart_ioctl,
};

// TODO: https://en.wikibooks.org/wiki/Serial_Programming/8250_UART_Programming
static irqreturn_t com_interrupt_handler(int irq_no, void *dev_id)
{
	// TODO:
	// verifica IIR
	// IIR 0 Enable Received Data Available Interrupt
	// IIR 1 Enable Transmitter Holding Register Empty Interrupt
	// IIR 2 Enable Receiver Line Status Interrupt

	// alte configurari

	// wake_up

	return IRQ_NONE;
}

static int add_device(enum coms com_no)
{
	int ret;

	spin_lock_init(&devs[com_no].rx_lock);
	init_waitqueue_head(&devs[com_no].rx_wq);

	spin_lock_init(&devs[com_no].tx_lock);
	init_waitqueue_head(&devs[com_no].tx_wq);

	devs[com_no].com_no = com_no;

	cdev_init(&devs[com_no].cdev, &uart_fops);
	ret = cdev_add(
		&devs[com_no].cdev,
		MKDEV(major, minor[com_no]),
		SINGLE_MINOR
	);
	if (ret)
		pr_err("cdev_add failed: %d\n", ret);

	// TODO: alte configurari

	return ret;
}

static int com_init(enum coms com_no)
{
	int ret = 0;
	struct resource *res = request_region(
		addr[com_no],
		REGION_SIZE,
		MODULE_NAME);

	if (!res) {
		ret = -ENODEV;
		pr_err("request_region 0x%X failed\n", addr[com_no]);
		goto out_com_init_err;
	}

	ret = request_irq(
		iqr_no[com_no],
		com_interrupt_handler,
		IRQF_SHARED,
		MODULE_NAME,
		&devs[com_no]
	);
	if (ret < 0) {
		pr_err("request_irq failed: %d\n", ret);
		goto out_release_region;
	}

	ret = add_device(com_no);
	if (ret)
		goto out_free_irq;

	return 0;

out_free_irq:
	free_irq(iqr_no[com_no], &devs[com_no]);
out_release_region:
	release_region(addr[com_no], REGION_SIZE);
out_com_init_err:
	return ret;
}

static void com_cleanup(enum coms com_no)
{
	cdev_del(&devs[com_no].cdev);
	free_irq(iqr_no[com_no], &devs[com_no]);
	release_region(addr[com_no], REGION_SIZE);
}

static int __init uart_init(void)
{
	int ret = 0;
	int region_minor = minor[COM1];
	int region_no = SINGLE_MINOR;

	pr_info("option: %d\n", option);

	// TODO: arata naspa
	if (option == OPTION_COM2)
		region_minor = minor[COM2];
	else if (option == OPTION_BOTH)
		region_no = ALL_MINORS;

	ret = register_chrdev_region(
		MKDEV(major, region_minor),
		region_no,
		MODULE_NAME
	);
	if (ret) {
		pr_err("register_chrdev_region failed: %d\n", ret);
		goto out_init_err;
	}

	switch (option) {
	case OPTION_COM1:
		ret = com_init(COM1);
		if (ret)
			goto out_unregister_region;
		break;
	case OPTION_COM2:
		ret = com_init(COM2);
		if (ret)
			goto out_unregister_region;
		break;
	case OPTION_BOTH:
		ret = com_init(COM1);
		if (ret)
			goto out_unregister_region;

		ret = com_init(COM2);
		if (ret)
			goto out_cleanup_com1;
		break;
	default:
		pr_err("unknown option: %d\n", option);
		ret = -EINVAL;
		goto out_unregister_region;
	}

	return 0;

out_cleanup_com1:
	com_cleanup(COM1);
out_unregister_region:
	unregister_chrdev_region(MKDEV(major, region_minor), region_no);
out_init_err:
	return ret;
}

static void __exit uart_exit(void)
{
	switch (option) {
	case OPTION_COM1:
		com_cleanup(COM1);
		unregister_chrdev_region(MKDEV(major, minor[COM1]), SINGLE_MINOR);
		break;
	case OPTION_COM2:
		com_cleanup(COM2);
		unregister_chrdev_region(MKDEV(major, minor[COM2]), SINGLE_MINOR);
		break;
	case OPTION_BOTH:
		com_cleanup(COM1);
		com_cleanup(COM2);
		unregister_chrdev_region(MKDEV(major, minor[COM1]), ALL_MINORS);
		break;
	default:
		pr_err("unknown option: %d\n", option);
	}
}

module_init(uart_init);
module_exit(uart_exit);

MODULE_DESCRIPTION("UART Driver");
MODULE_AUTHOR(
	"Adina Smeu <adina.smeu@gmail.com>, Teodor Dutu <teodor.dutu@gmail.com>"
);
MODULE_LICENSE("GPL v2");
