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


#define MAC_BYTES	6
#define STP_HT_BITS	12


struct stp_sock {
	struct sock sk;
	__be16 src_port;
	__be16 dst_port;
	int idx;
	__u8 mac[MAC_BYTES];
	struct socket *sock;
	struct hlist_node node;
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

static DEFINE_HASHTABLE(binds, STP_HT_BITS);
static spinlock_t locks[1 << STP_HT_BITS];


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
	.proc_open = stp_read_open,
	.proc_read = seq_read,
	.proc_release = single_release,
};


static inline struct stp_sock *stp_sk(struct socket *sock)
{
	return (struct stp_sock *)sock->sk;
}

static void unbind(struct stp_sock *sk)
{
	spin_lock(locks + hash_min(sk->dst_port, HASH_BITS(locks)));
	hash_del_rcu(&sk->node);
	spin_unlock(locks + hash_min(sk->dst_port, HASH_BITS(locks)));
	synchronize_rcu();
}

static struct stp_sock *port_sk(__u16 port)
{
	struct stp_sock *sk;

	hash_for_each_possible_rcu(binds, sk, node, port)
		if (sk->src_port == port)
			return sk;
	return NULL;
}

static bool find_port_if(__be16 port, int idx)
{
	struct stp_sock *stat;

	hash_for_each_possible_rcu(binds, stat, node, port)
		if (stat->src_port == port
				&& (stat->idx == idx || !stat->idx || !idx))
			return true;
	return false;
}


static int stp_release(struct socket *sock)
{
	struct stp_sock *sk = stp_sk(sock);

	if (!sk)
		return -EINVAL;

	if (sock->state != SS_FREE && sock->state != SS_UNCONNECTED)
		unbind(sk);

	sock->state = SS_FREE;
	sock_put(&sk->sk);
	sock->sk = NULL;

	return 0;
}

static void init_stp_sock(struct sockaddr_stp *addr, struct socket *sock)
{
	struct stp_sock *sk = (struct stp_sock *)sock->sk;

	sk->src_port = addr->sas_port;
	sk->idx = addr->sas_ifindex;
	sk->sock = sock;

	spin_lock(locks + hash_min(sk->src_port, HASH_BITS(locks)));
	hash_add_rcu(binds, &sk->node, sk->src_port);
	spin_unlock(locks + hash_min(sk->src_port, HASH_BITS(locks)));
}

static int
stp_bind(struct socket *sock, struct sockaddr *saddr, int sockaddr_len)
{
	struct stp_sock *sk = stp_sk(sock);
	struct sockaddr_stp *addr = (struct sockaddr_stp *)saddr;

	if (sk->sk.sk_prot->bind)
		return sk->sk.sk_prot->bind(&sk->sk, saddr, sockaddr_len);

	if (sockaddr_len < sizeof(*addr))
		return -EINVAL;

	if (addr->sas_family != AF_STP || !addr->sas_port)
		return -EAFNOSUPPORT;

	if (sock->state != SS_FREE && sock->state != SS_UNCONNECTED)
		return -EBUSY;

	if (find_port_if(addr->sas_port, addr->sas_ifindex))
		return -EBUSY;

	init_stp_sock(addr, sock);
	sock->state = SS_CONNECTING;

	return 0;
}

static int stp_connect(struct socket *sock, struct sockaddr *vaddr,
	int sockaddr_len, int flags)
{
	struct stp_sock *sk = stp_sk(sock);
	struct sockaddr_stp *addr = (struct sockaddr_stp *)vaddr;

	if (addr->sas_family != AF_STP || !addr->sas_port)
		return -EINVAL;

	sk->dst_port = addr->sas_port;
	memcpy(sk->mac, addr->sas_addr, sizeof(sk->mac));
	sock->state = SS_CONNECTED;

	return 0;
}

static __u8 csum(struct sk_buff *skb)
{
	char *p = skb_network_header(skb);
	char *fin = p + skb->data_len;
	__u8 cs = 0;

	for (; p != fin; cs ^= *p++)
		;

	return cs;
}

static int stp_sendmsg(struct socket *sock, struct msghdr *m, size_t total_len)
{
	struct stp_sock *sk = stp_sk(sock);
	struct sockaddr_stp *addr = (struct sockaddr_stp *)m->msg_name;
	struct net_device *dev;
	struct sk_buff *skb;
	struct stp_hdr *hdr;
	unsigned long hlen, dlen, offset;
	int err;

	if (!sk->idx)
		return -EINVAL;

	dev = dev_get_by_index(sock_net(&sk->sk), sk->idx);
	if (!dev)
		return -EINVAL;

	hlen = LL_RESERVED_SPACE(dev);
	dlen = total_len + sizeof(*hdr);
	skb = sock_alloc_send_pskb(&sk->sk, hlen, dlen,
		m->msg_flags & MSG_DONTWAIT, &err, 0);
	if (!skb)
		goto out_unlock;

	skb_reserve(skb, hlen);
	skb_reset_network_header(skb);

	offset = dev_hard_header(skb, dev, ETH_P_STP,
		sk->dst_port ? sk->mac : addr->sas_addr, NULL, dlen);
	if (offset < 0) {
		err = -EINVAL;
		goto out_free;
	}

	hdr = (struct stp_hdr *)skb_put(skb, dlen);
	hdr->dst = sk->dst_port ? sk->dst_port : addr->sas_port;
	hdr->src = sk->src_port;
	hdr->len = dlen;
	hdr->flags = m->msg_flags;
	hdr->csum = 0;

	skb->data_len = dlen;
	skb->len += dlen;
	skb->protocol = htons(ETH_P_STP);
	skb->dev = dev;
	skb->priority = sk->sk.sk_priority;

	err = skb_copy_datagram_from_iter(skb, offset + sizeof(*hdr),
		&m->msg_iter, total_len);
	if (err)
		goto out_free;

	hdr->csum = csum(skb);

	dev_queue_xmit(skb);
	dev_put(dev);

	++stats.tx_pkts;

	return total_len;

out_free:
	kfree_skb(skb);
out_unlock:
	if (dev)
		dev_put(dev);

	return err;

}

static int
stp_recvmsg(struct socket *sock, struct msghdr *m, size_t total_len, int flags)
{
	struct stp_sock *sk = stp_sk(sock);
	struct sk_buff *skb;
	struct stp_hdr *hdr;
	size_t msg_len;
	int err = 0;

	skb = skb_recv_datagram(&sk->sk, flags, flags & MSG_DONTWAIT, &err);
	if (!skb)
		return err;

	msg_len = skb->data_len - sizeof(*hdr);
	msg_len = min_t(size_t, msg_len, total_len);
	err = skb_copy_datagram_iter(skb, sizeof(*hdr), &m->msg_iter, msg_len);
	if (err) {
		kfree_skb(skb);
		return err;
	}

	++stats.rx_pkts;
	consume_skb(skb);

	return total_len;
}

static int stp_recv(struct sk_buff *skb, struct net_device *dev,
	struct packet_type *pt, struct net_device *orig_dev)
{
	struct stp_hdr *hdr = (struct stp_hdr *)skb_network_header(skb);
	struct stp_sock *sk;
	__u8 recv_cs;
	int ret;

	if (skb->data_len < sizeof(*hdr) || !hdr->src || !hdr->dst) {
		++stats.hdr_err;
		ret = -EINVAL;
		goto out;
	}

	recv_cs = hdr->csum;
	hdr->csum = 0;
	if (recv_cs != csum(skb)) {
		++stats.csum_err;
		ret = -EINVAL;
		goto out;
	}

	sk = port_sk(hdr->dst);
	if (!sk) {
		++stats.no_sock;
		ret = -ENOTSOCK;
		goto out;
	}

	ret = sock_queue_rcv_skb(&sk->sk, skb);
	if (ret) {
		++stats.no_buffs;
		goto out;
	}

	return NET_RX_SUCCESS;

out:
	kfree_skb(skb);
	return ret;
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
	.sendmsg = stp_sendmsg,
	.recvmsg = stp_recvmsg,
	.mmap = sock_no_mmap,
	.sendpage = sock_no_sendpage,
};

static struct proto stp_proto = {
	.name = STP_PROTO_NAME,
	.owner = THIS_MODULE,
	.obj_size = sizeof(struct stp_sock),
};

static int
stp_create_socket(struct net *net, struct socket *sock, int protocol, int kern)
{
	struct sock *sk;

	if (protocol != IPPROTO_IP || sock->type != SOCK_DGRAM)
		return -EINVAL;

	sk = sk_alloc(net, AF_STP, GFP_KERNEL, &stp_proto, kern);
	if (!sk)
		return -ENOMEM;

	sock_init_data(sock, sk);
	sk->sk_family = AF_STP;
	sk->sk_protocol = protocol;

	sock->ops = &stp_ops;
	sock->state = SS_FREE;

	return 0;
};

static const struct net_proto_family stp_family = {
	.family = AF_STP,
	.create = stp_create_socket,
	.owner = THIS_MODULE,
};

static struct packet_type stp_packet_type = {
	.type = htons(ETH_P_STP),
	.func = stp_recv,
};

static int __init stp_init(void)
{
	int i, err;

	for (i = 0; i != ARRAY_SIZE(locks); ++i)
		spin_lock_init(locks + i);

	err = sock_register(&stp_family);
	if (err)
		return err;

	err = proto_register(&stp_proto, 1);
	if (err < 0)
		goto out_sock_unregister;

	dev_add_pack(&stp_packet_type);

	proc_stp = proc_create(STP_PROC_NET_FILENAME, 0000, init_net.proc_net,
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

static void remove_binds(void)
{
	struct stp_sock *sk;
	struct hlist_node *tmp;
	size_t bkt;

	hash_for_each_safe(binds, bkt, tmp, sk, node) {
		hash_del(&sk->node);
		sk_free(&sk->sk);
	}
}

static void __exit stp_exit(void)
{
	proc_remove(proc_stp);
	dev_remove_pack(&stp_packet_type);
	proto_unregister(&stp_proto);
	sock_unregister(AF_STP);
	remove_binds();
}

module_init(stp_init);
module_exit(stp_exit);


MODULE_DESCRIPTION("SO2 Transport Protocol");
MODULE_AUTHOR(
	"Adina Smeu <adina.smeu@gmail.com>, Teodor Dutu <teodor.dutu@gmail.com>"
);
MODULE_LICENSE("GPL v2");
