// SPDX-License-Identifier: GPL-2.0+

/*
 * af_stp.c - SO2 Transport Protocol
 *
 * Author:
 *	Adina Smeu <adina.smeu@gmail.com>,
 *	Teodor Dutu <teodor.dutu@gmail.com>
 */

#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/module.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/net.h>
#include <linux/in.h>
#include <linux/fs.h>
#include <net/sock.h>

#include "stp.h"

// TODO: ce ne trebuie?
struct aux_sock {
	struct sock sk;
};

static struct proc_dir_entry *proc_stp;


static int stp_proc_show(struct seq_file *m, void *v)
{
	seq_puts(m, "RxPkts HdrErr CsumErr NoSock NoBuffs TxPkts\n");

	return 0;
}

static int stp_read_open(struct inode *inode, struct file *file)
{
	return single_open(file, stp_proc_show, NULL);
}

static const struct proc_ops r_pops = {
	.proc_open	= stp_read_open,
	.proc_read	= seq_read,
	.proc_release	= single_release,
};

static int stp_release(struct socket *sock)
{
	return 0;
}

static int stp_bind(struct socket *sock, struct sockaddr *myaddr,
		int sockaddr_len)
{
	return 0;
}

static int stp_connect(struct socket *sock, struct sockaddr *vaddr,
		int sockaddr_len, int flags)
{
	return 0;
}

static int stp_sendmsg(struct socket *sock, struct msghdr *m, size_t total_len)
{
	return total_len;
}

static int stp_recvmsg(struct socket *sock, struct msghdr *m, size_t total_len,
		int flags)
{
	return 0;
}

static const struct proto_ops stp_ops = {
	.family = PF_STP,
	.owner = THIS_MODULE,
	.release = stp_release,
	.bind = stp_bind,
	.connect = stp_connect,
	.socketpair = sock_no_socketpair,
	.accept = sock_no_accept,
	.getname = sock_no_getname,
	.poll = datagram_poll,
	.ioctl = sock_no_ioctl,
	.listen = sock_no_listen,
	.shutdown = sock_no_shutdown,
	// .setsockopt = sock_no_setsockopt,
	// .getsockopt = sock_no_getsockopt,
	.sendmsg = stp_sendmsg,
	.recvmsg = stp_recvmsg,
	.mmap = sock_no_mmap,
	.sendpage = sock_no_sendpage,
};

static struct proto stp_proto = {
	.name		= STP_PROTO_NAME,
	.owner		= THIS_MODULE,
	// TODO: ce size?
	.obj_size	= sizeof(struct aux_sock),
};

static int stp_create_socket(struct net *net, struct socket *sock, int protocol,
			int kern)
{
	struct sock *sk;

	sk = sk_alloc(net, PF_STP, GFP_KERNEL, &stp_proto, kern);
	if (!sk) {
		pr_err("failed to allocate socket.\n");
		return -ENOMEM;
	}

	sock_init_data(sock, sk);
	sk->sk_family = PF_STP;
	sk->sk_protocol = protocol;

	sock->ops = &stp_ops;
	sock->state = SS_UNCONNECTED;

	/* Do the protocol specific socket object initialization */
	return 0;
};

static const struct net_proto_family stp_family = {
	.family = PF_STP,
	.create = stp_create_socket,
	.owner = THIS_MODULE,
};

static int __init stp_init(void)
{
	int err;

	err = sock_register(&stp_family);
	if (err)
		return err;

	proc_stp = proc_create(
		STP_PROC_NET_FILENAME,
		0000,
		init_net.proc_net,
		&r_pops);
	if (!proc_stp) {
		err = -EINVAL;
		goto out_sock_unregister;
	}

	return 0;

out_sock_unregister:
	sock_unregister(PF_STP);
	return err;
}

static void __exit stp_exit(void)
{
	proc_remove(proc_stp);
	sock_unregister(AF_STP);
}

module_init(stp_init);
module_exit(stp_exit);


MODULE_DESCRIPTION("SO2 Transport Protocol");
MODULE_AUTHOR(
	"Adina Smeu <adina.smeu@gmail.com>, Teodor Dutu <teodor.dutu@gmail.com>"
);
MODULE_LICENSE("GPL v2");
