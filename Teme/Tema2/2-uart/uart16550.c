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

#include "uart16550.h"

#define DEFAULT_MAJOR	42

#define REGION_SIZE	8

#define COM1		0x3f8
#define COM2		0x2f8

#define IRQ_COM1	0x04
#define IRQ_COM2	0x03

#define COM1_MINOR	0
#define COM2_MINOR	1

#define SINGLE_MINOR	1
#define ALL_MINORS	2

#define BUFFER_SIZE	1024

#define MODULE_NAME	"uart16550"

static int major = DEFAULT_MAJOR;
static int option = OPTION_BOTH;

// TODO: Verifica permisiuni
module_param(major, int, 0);
MODULE_PARM_DESC(major, "The major with which the device must be registered");
module_param(option, int, 0);
MODULE_PARM_DESC(option, "The registered serial ports");

struct com_port {
	struct cdev cdev;
	spinlock_t lock;
	struct kfifo fifo;
	char buf[BUFFER_SIZE];
} devs[ALL_MINORS];

static ssize_t uart_write(
	struct file *file,
	const char __user *user_buffer,
	size_t size,
	loff_t *offset
)
{
	return 0;
}

static ssize_t uart_read(
	struct file *file,
	char __user *user_buffer,
	size_t size,
	loff_t *offset)
{
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

	if (copy_from_user(&info, (void *)arg, sizeof(info))) {
		pr_err("Invalid address: 0x%X\n", arg);
		return -EFAULT;
	}

	switch (cmd) {
	case UART16550_IOCTL_SET_LINE:
		pr_info("New parameters:\n");
		pr_info("Baud: %d, len: %d\n", info.baud, info.len);
		pr_info("Par: %d, stop: %d\n", info.par, info.stop);

		break;

	default:
		ret = -EINVAL;
	}

	return ret;
}

static const struct file_operations uart_fops = {
	.owner = THIS_MODULE,
	.read = uart_read,
	.write = uart_write,
	.unlocked_ioctl = uart_ioctl,
};

static int request_port(int port)
{
	int ret = 0;

	int res = request_region(
		(struct resource *)port,
		REGION_SIZE,
		MODULE_NAME);

	if (!res) {
		ret = -ENODEV;
		pr_err("request_region 0x%X failed: %d\n", port, ret);
	}

	return ret;
}

static int request_ports(void)
{
	int ret;

	switch (option) {
	case OPTION_COM1:
		ret = request_port(COM1);
		break;
	case OPTION_COM2:
		ret = request_port(COM2);
		break;
	case OPTION_BOTH:
		ret = request_port(COM1);
		if (ret)
			goto out_req_err;

		ret = request_port(COM2);
		if (ret)
			goto out_cleanup_com1;

		break;
	default:
		pr_err("unknown option: %d\n", option);
		ret = -EINVAL;
	}

	return ret;

out_cleanup_com1:
	release_region(COM1, REGION_SIZE);
out_req_err:
	return ret;
}

static void release_regions(void)
{
	switch (option) {
	case OPTION_COM1:
		release_region(COM1, REGION_SIZE);
		break;
	case OPTION_COM2:
		release_region(COM2, REGION_SIZE);
		break;
	case OPTION_BOTH:
		release_region(COM1, REGION_SIZE);
		release_region(COM2, REGION_SIZE);
		break;
	default:
		pr_err("unknown option: %d\n", option);
	}
}

static int register_regions(void)
{
	int ret;

	switch (option) {
	case OPTION_COM1:
		ret = register_chrdev_region(
			MKDEV(major, COM1_MINOR),
			SINGLE_MINOR,
			MODULE_NAME
		);
		if (ret)
			pr_err("register_region failed: %d\n", ret);
		break;
	case OPTION_COM2:
		ret = register_chrdev_region(
			MKDEV(major, COM2_MINOR),
			SINGLE_MINOR,
			MODULE_NAME
		);
		if (ret)
			pr_err("register_region failed: %d\n", ret);
		break;
	case OPTION_BOTH:
		ret = register_chrdev_region(
			MKDEV(major, COM1_MINOR),
			ALL_MINORS,
			MODULE_NAME
		);
		if (ret)
			pr_err("register_region failed: %d\n", ret);
		break;
	default:
		pr_err("unknown option: %d\n", option);
		ret = -EINVAL;
	}

	return ret;
}

static void unregister_regions(void)
{
	switch (option) {
	case OPTION_COM1:
		unregister_chrdev_region(
			MKDEV(major, COM1_MINOR),
			SINGLE_MINOR
		);
		break;
	case OPTION_COM2:
		unregister_chrdev_region(
			MKDEV(major, COM2_MINOR),
			SINGLE_MINOR
		);
		break;
	case OPTION_BOTH:
		unregister_chrdev_region(
			MKDEV(major, COM1_MINOR),
			ALL_MINORS
		);
		break;
	default:
		pr_err("unknown option: %d\n", option);
	}
}

static irqreturn_t com_interrupt_handler(int irq_no, void *dev_id)
{
	return IRQ_NONE;
}

static int register_irq_handler(int irq_no, int index)
{
	int ret = request_irq(
		irq_no,
		com_interrupt_handler,
		IRQF_SHARED,
		MODULE_NAME,
		&devs[index]
	);
	if (ret < 0)
		pr_err("request_irq failed: %d\n", ret);

	return ret;
}

static int register_irq_handlers(void)
{
	int ret;

	switch (option) {
	case OPTION_COM1:
		ret = register_irq_handler(IRQ_COM1, COM1_MINOR);
		break;
	case OPTION_COM2:
		ret = register_irq_handler(IRQ_COM2, COM2_MINOR);
		break;
	case OPTION_BOTH:
		ret = register_irq_handler(IRQ_COM1, COM1_MINOR);
		if (ret)
			goto out_irq_err;

		ret = register_irq_handler(IRQ_COM2, COM2_MINOR);
		if (ret)
			goto unregister_com1_irq;
		break;
	default:
		pr_err("unknown option: %d\n", option);
		ret = -EINVAL;
	}

	return ret;

unregister_com1_irq:
	free_irq(IRQ_COM1, &devs[COM1_MINOR]);
out_irq_err:
	return ret;
}

static void free_irqs(void)
{
	switch (option) {
	case OPTION_COM1:
		free_irq(IRQ_COM1, &devs[COM1_MINOR]);
		break;
	case OPTION_COM2:
		free_irq(IRQ_COM2, &devs[COM2_MINOR]);
		break;
	case OPTION_BOTH:
		free_irq(IRQ_COM1, &devs[COM1_MINOR]);
		free_irq(IRQ_COM2, &devs[COM2_MINOR]);
		break;
	default:
		pr_err("unknown option: %d\n", option);
	}
}

static int add_device(int minor)
{
	int ret;

	cdev_init(&devs[minor].cdev, &uart_fops);
	ret = cdev_add(
		&devs[minor].cdev,
		MKDEV(major, minor),
		SINGLE_MINOR
	);
	if (ret)
		pr_err("cdev_add failed: %d\n", ret);

	return ret;
}

static int add_devices(void)
{
	int ret;

	switch (option) {
	case OPTION_COM1:
		ret = add_device(COM1_MINOR);
		break;
	case OPTION_COM2:
		ret = add_device(COM2_MINOR);
		break;
	case OPTION_BOTH:
		ret = add_device(COM1_MINOR);
		if (ret)
			goto out_add_dev_err;

		ret = add_device(COM2_MINOR);
		if (ret)
			goto unregister_com1_dev;
		break;
	default:
		pr_err("unknown option: %d\n", option);
		ret = -EINVAL;
	}

	return ret;

unregister_com1_dev:
	cdev_del(&devs[COM1_MINOR].cdev);
out_add_dev_err:
	return ret;
}

static void del_devices(void)
{
	switch (option) {
	case OPTION_COM1:
		cdev_del(&devs[COM1_MINOR].cdev);
		break;
	case OPTION_COM2:
		cdev_del(&devs[COM2_MINOR].cdev);
		break;
	case OPTION_BOTH:
		cdev_del(&devs[COM1_MINOR].cdev);
		cdev_del(&devs[COM2_MINOR].cdev);
		break;
	default:
		pr_err("unknown option: %d\n", option);
	}
}

static int __init uart_init(void)
{
	int ret = 0;

	pr_info("option: %d\n", option);

	ret = register_regions();
	if (ret)
		goto out_init_err;

	ret = request_ports();
	if (ret)
		goto out_unregister_region;

	ret = register_irq_handlers();
	if (ret)
		goto out_release_regions;

	ret = add_devices();
	if (ret)
		goto out_free_irqs;

	return 0;

out_free_irqs:
	free_irqs();
out_release_regions:
	release_regions();
out_unregister_region:
	unregister_regions();
out_init_err:
	return ret;
}

static void __exit uart_exit(void)
{
	del_devices();
	free_irqs();
	release_regions();
	unregister_regions();
}

module_init(uart_init);
module_exit(uart_exit);

MODULE_DESCRIPTION("UART Driver");
MODULE_AUTHOR(
	"Adina Smeu <adina.smeu@gmail.com>, Teodor Dutu <teodor.dutu@gmail.com>"
);
MODULE_LICENSE("GPL v2");
