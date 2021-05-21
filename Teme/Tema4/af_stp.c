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

static struct stp_stats {
	int rx_pkts;
	int hdr_err;
	int csum_err;
	int no_sock;
	int no_buffs;
	int tx_pkts;
} stats;

static struct proc_dir_entry *proc_stp;


static int stp_proc_show(struct seq_file *m, void *v)
{
	seq_puts(m, "RxPkts HdrErr CsumErr NoSock NoBuffs TxPkts\n");
	seq_printf(
		m,
		"%d %d %d %d %d %d\n",
		stats.rx_pkts,
		stats.hdr_err,
		stats.csum_err,
		stats.no_sock,
		stats.no_buffs,
		stats.tx_pkts
	);

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
	struct sock *sk = sock->sk;

	if (!sk) {
		pr_err("Socket already released.\n");
		return -EINVAL;
	}

	sock_put(sk);
	sock->sk = NULL;

	return 0;
}

static int stp_bind(struct socket *sock, struct sockaddr *saddr,
		int sockaddr_len)
{
	struct sock *sk = sock->sk;
	struct sockaddr_stp *addr = (struct sockaddr_stp *)saddr;

	if (sk->sk_prot->bind)
		return sk->sk_prot->bind(sk, saddr, sockaddr_len);

	if (sockaddr_len < sizeof(struct sockaddr_stp))
		return -EINVAL;

	if (addr->sas_family != AF_STP || !addr->sas_port)
		return -EAFNOSUPPORT;

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

	if (sock->type != SOCK_DGRAM) {
		pr_err("Invalid socket type %d\n", sock->type);
		return -EINVAL;
	}

	if (protocol) {
		pr_err("Invalid protocol %d\n", protocol);
		return -EINVAL;
	}

	sk = sk_alloc(net, AF_STP, GFP_KERNEL, &stp_proto, kern);
	if (!sk) {
		pr_err("Failed to allocate socket.\n");
		return -ENOMEM;
	}

	sock_init_data(sock, sk);
	sk->sk_family = AF_STP;
	sk->sk_protocol = protocol;

	sock->ops = &stp_ops;
	sock->state = SS_UNCONNECTED;

	// TODO: Do the protocol specific socket object initialization
	return 0;
};

static const struct net_proto_family stp_family = {
	.family = AF_STP,
	.create = stp_create_socket,
	.owner = THIS_MODULE,
};


// TODO: cf?
static struct packet_type stp_packet_type;


static int __init stp_init(void)
{
	int err;

	err = sock_register(&stp_family);
	if (err)
		return err;

	err = proto_register(&stp_proto, 0);
	if (err < 0)
		goto out_sock_unregister;

	dev_add_pack(&stp_packet_type);

	proc_stp = proc_create(
		STP_PROC_NET_FILENAME,
		0000,
		init_net.proc_net,
		&r_pops);
	if (!proc_stp) {
		pr_err("Failed to create proc entry.\n");
		err = -EINVAL;
		goto out_proto_unregister;
	}

	return 0;

out_proto_unregister:
	proto_unregister(&stp_proto);
out_sock_unregister:
	sock_unregister(AF_STP);
	return err;
}

static void __exit stp_exit(void)
{
	proc_remove(proc_stp);
	dev_remove_pack(&stp_packet_type);
	proto_unregister(&stp_proto);
	sock_unregister(AF_STP);
}

module_init(stp_init);
module_exit(stp_exit);


MODULE_DESCRIPTION("SO2 Transport Protocol");
MODULE_AUTHOR(
	"Adina Smeu <adina.smeu@gmail.com>, Teodor Dutu <teodor.dutu@gmail.com>"
);
MODULE_LICENSE("GPL v2");
