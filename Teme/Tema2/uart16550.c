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

#define MODULE_NAME		"uart16550"

#define DEFAULT_MAJOR		42

#define REGION_SIZE		8

#define SINGLE_MINOR		1
#define ALL_MINORS		2

#define KFIFO_SIZE		512

#define THR(base_addr)		(base_addr + 0)
#define RBR(base_addr)		(base_addr + 0)
#define DLL(base_addr)		(base_addr + 0)
#define DLH(base_addr)		(base_addr + 1)
#define IER(base_addr)		(base_addr + 1)
#define IIR(base_addr)		(base_addr + 2)
#define LCR(base_addr)		(base_addr + 3)
#define MCR(base_addr)		(base_addr + 4)

#define IIR_INT_TYPE(reg)	(reg & 0x0e)

#define IPF			0

#define RDAI			0
#define THREI			1

#define DLAB			7

#define AO2			3

#define RDAI_BITS		1
#define THREI_BITS		2

#define GET_BIT(reg, idx)	(reg & (1 << idx))
#define SET_BIT(reg, idx)	(reg | (1 << idx))
#define CLEAR_BIT(reg, idx)	(reg & ~(1 << idx))

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
) {
	int ret;
	size_t to_read, len;
	char buff[KFIFO_SIZE];
	struct com_dev *dev = (struct com_dev *) file->private_data;

	pr_info("Let's wait\n");

	ret = wait_event_interruptible(
		dev->rx_wq,
		!kfifo_is_empty_spinlocked(&dev->rx_fifo, &dev->rx_lock)
	);
	if (ret)
		return -EINVAL;  // TODO: alta eroare?

	pr_info("Read up\n");

	len = kfifo_len(&dev->rx_fifo);
	to_read = size < len ? size : len;

	kfifo_out_spinlocked(&dev->rx_fifo, buff, to_read, &dev->rx_lock);

	if (copy_to_user(user_buffer, buff, to_read))
		return -EFAULT;

	/* Reenable RDAI */
	outb(
		SET_BIT(inb(IER(addr[dev->com_no])), RDAI),
		IER(addr[dev->com_no])
	);

	*offset += to_read;  // TODO: mai e nevoie? nu-l folosesc
	return to_read;
}

static ssize_t uart_write(
	struct file *file,
	const char __user *user_buffer,
	size_t size,
	loff_t *offset
) {
	int ret;
	size_t to_write, len;
	char buff[KFIFO_SIZE];
	struct com_dev *dev = (struct com_dev *) file->private_data;

	ret = wait_event_interruptible(
		dev->rx_wq,
		!kfifo_is_full(&dev->tx_fifo)
	);
	if (ret)
		return -EINVAL;  // TODO: alta eroare?

	len = kfifo_len(&dev->tx_fifo);
	to_write = size < len ? size : len;

	if (copy_from_user(buff, user_buffer, to_write))
		return -EFAULT;

	kfifo_in_spinlocked(&dev->tx_fifo, buff, to_write, &dev->tx_lock);

	/* Reenable THREI */
	outb(
		SET_BIT(inb(IER(addr[dev->com_no])), THREI),
		IER(addr[dev->com_no])
	);

	*offset += to_write;  // TODO: mai e nevoie? nu-l folosesc
	return to_write;
}

static long uart_ioctl(
	struct file *file,
	unsigned int cmd,
	unsigned long arg
) {
	int ret = 0;
	char config;
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

		config = info.par | info.stop | info.len;

		/* LCR = {1b'{dlab}, 1b'{}, 3b'{par}, 1b'{stop}, 2b'{len}} */
		outb(SET_BIT(config, DLAB), LCR(addr[dev->com_no]));

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

		outb(CLEAR_BIT(config, DLAB), LCR(addr[dev->com_no]));

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

static irqreturn_t com_interrupt_handler(int irq_no, void *dev_id)
{
	struct com_dev *dev = (struct com_dev *) dev_id;

	char iir = inb(IIR(addr[dev->com_no]));
	char type = IIR_INT_TYPE(iir);
	char byte;

	// if (GET_BIT(iir, IPF))
	// 	return IRQ_NONE;

	pr_info("Irq %d, %d\n", irq_no, dev->com_no);

	if (type == RDAI_BITS) {
		pr_info("RDAI\n");
		byte = inb(RBR(addr[dev->com_no]));
		kfifo_in_spinlocked_noirqsave(
			&dev->rx_fifo,
			&byte,
			1,
			&dev->rx_lock
		);

		if (kfifo_is_full(&dev->rx_fifo))
			outb(
				CLEAR_BIT(inb(IER(addr[dev->com_no])), RDAI),
				IER(addr[dev->com_no])
			);

		pr_info("Let's wake up\n");

		wake_up(&dev->rx_wq);
	}

	if (type == THREI_BITS) {
		kfifo_out_spinlocked_noirqsave(
			&dev->tx_fifo,
			&byte,
			1,
			&dev->tx_lock
		);
		outb(byte, THR(addr[dev->com_no]));

		if (kfifo_is_empty_spinlocked_noirqsave(
			&dev->tx_fifo,
			&dev->tx_lock
		))
			outb(
				CLEAR_BIT(inb(IER(addr[dev->com_no])), THREI),
				IER(addr[dev->com_no])
			);

		wake_up(&dev->tx_wq);
	}

	return IRQ_HANDLED;
}

static int add_device(enum coms com_no)
{
	int ret;
	char config = 0;

	spin_lock_init(&devs[com_no].rx_lock);
	init_waitqueue_head(&devs[com_no].rx_wq);

	spin_lock_init(&devs[com_no].tx_lock);
	init_waitqueue_head(&devs[com_no].tx_wq);

	devs[com_no].com_no = com_no;

	/* Enable interrupts */
	outb(SET_BIT(config, AO2), MCR(addr[com_no]));

	/* Enable RDAI and THREI */
	config = 0;
	outb(SET_BIT(SET_BIT(config, RDAI), THREI), IER(addr[com_no]));

	cdev_init(&devs[com_no].cdev, &uart_fops);
	ret = cdev_add(
		&devs[com_no].cdev,
		MKDEV(major, minor[com_no]),
		SINGLE_MINOR
	);
	if (ret)
		pr_err("cdev_add failed: %d\n", ret);

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

// TODO: lungime linii
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
