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
#define STP_HT_BITS	4


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

static void unbind_hash(struct socket *sock)
{
	spin_lock(locks + hash_min((u32)sock, HASH_BITS(locks)));
	hash_del_rcu(&stp_sk(sock)->node);
	spin_unlock(locks + hash_min((u32)sock, HASH_BITS(locks)));
	synchronize_rcu();
}

static int stp_release(struct socket *sock)
{
	struct stp_sock *sk = stp_sk(sock);

	if (!sk) {
		pr_err("Socket already released.\n");
		return -EINVAL;
	}

	if (sock->state != SS_FREE && sock->state != SS_UNCONNECTED)
		unbind_hash(sock);

	sock->state = SS_FREE;
	sock_put(&sk->sk);
	sock->sk = NULL;

	return 0;
}

static bool find_port_if(__be16 port, int idx)
{
	size_t bkt;
	struct stp_sock *stat;

	hash_for_each_rcu(binds, bkt, stat, node)
		if (stat->src_port == port
				&& (stat->idx == idx || !stat->idx || !idx))
			return true;
	return false;
}

static void init_sk_sock(struct sockaddr_stp *addr, struct socket *sock)
{
	struct stp_sock *sk = (struct stp_sock *)sock->sk;

	sk->src_port = addr->sas_port;
	sk->idx = addr->sas_ifindex;
	sk->sock = sock;

	spin_lock(locks + hash_min((u32)sock, HASH_BITS(locks)));
	hash_add_rcu(binds, &sk->node, (u32)sock);
	spin_unlock(locks + hash_min((u32)sock, HASH_BITS(locks)));
}

static int
stp_bind(struct socket *sock, struct sockaddr *saddr, int sockaddr_len)
{
	struct stp_sock *sk = stp_sk(sock);
	struct sockaddr_stp *addr = (struct sockaddr_stp *)saddr;

	pr_info("[%s]: if = %d; port = %hu\n", __func__,
		addr->sas_ifindex, ntohs(addr->sas_port));

	if (sk->sk.sk_prot->bind)
		return sk->sk.sk_prot->bind(&sk->sk, saddr, sockaddr_len);

	if (sockaddr_len < sizeof(struct sockaddr_stp))
		return -EINVAL;

	if (addr->sas_family != AF_STP || !addr->sas_port)
		return -EAFNOSUPPORT;

	if (sock->state != SS_FREE && sock->state != SS_UNCONNECTED)
		return -EBUSY;

	if (find_port_if(addr->sas_port, addr->sas_ifindex))
		return -EBUSY;

	init_sk_sock(addr, sock);
	sock->state = SS_CONNECTING;

	return 0;
}

static int stp_connect(struct socket *sock, struct sockaddr *vaddr,
	int sockaddr_len, int flags)
{
	struct stp_sock *sk = stp_sk(sock);
	struct sockaddr_stp *addr = (struct sockaddr_stp *)vaddr;

	pr_info("[%s]: fam = %hhu; port = %hu; MAC = %hhX:%hhX:%hhX:%hhX:%hhX:%hhX\n",
		__func__, addr->sas_family, ntohs(addr->sas_port),
		addr->sas_addr[0], addr->sas_addr[1], addr->sas_addr[2],
		addr->sas_addr[3], addr->sas_addr[4], addr->sas_addr[5]);

	if (addr->sas_family != AF_STP || !addr->sas_port)
		return -EINVAL;

	sk->dst_port = addr->sas_port;
	memcpy(sk->mac, addr->sas_addr, sizeof(sk->mac));
	sock->state = SS_CONNECTED;

	return 0;
}

static void create_header(struct stp_hdr *hdr, struct stp_sock *sk, size_t len)
{
	hdr->dst = sk->dst_port;
	hdr->src = sk->src_port;
	hdr->flags = 0;
	hdr->len = htons(len + sizeof(*hdr));
}

static int stp_sendmsg(struct socket *sock, struct msghdr *m, size_t total_len)
{
	struct stp_sock *sk = stp_sk(sock);
	struct net_device *dev;
	struct sk_buff *skb;
	struct stp_hdr *hdr;
	unsigned long hlen, tlen, dlen, offset;
	int err;

	struct sockaddr_stp *addr = (struct sockaddr_stp *)m->msg_name;
	// pr_info("[stp_sendmsg m]: fam = %hhu; port = %hu; MAC = %hhX:%hhX:%hhX:%hhX:%hhX:%hhX\n",
	// 	addr->sas_family, ntohs(addr->sas_port), addr->sas_addr[0],
	// 	addr->sas_addr[1], addr->sas_addr[2], addr->sas_addr[3],
	// 	addr->sas_addr[4], addr->sas_addr[5]);

	pr_info("[%s]: src = %hu; dst = %hu; if = %d; MAC = %hhX:%hhX:%hhX:%hhX:%hhX:%hhX\n",
		__func__, ntohs(sk->src_port), ntohs(sk->dst_port), sk->idx,
		sk->mac[0], sk->mac[1], sk->mac[2], sk->mac[3], sk->mac[4],
		sk->mac[5]);

	if (!sk->idx) {
		pr_err("Unable to send packet without an interface.\n");
		return -EINVAL;
	}

	dev = dev_get_by_index(sock_net(&sk->sk), sk->idx);
	if (!dev) {
		pr_err("Failed to send obtain net device from index %d.\n",
			sk->idx);
		return -EINVAL;
	}

	pr_info("[%s]: dev = %X\n", __func__, dev);

	hlen = LL_RESERVED_SPACE(dev);
	tlen = dev->needed_tailroom;
	dlen = total_len + sizeof(*hdr);

	skb = sock_alloc_send_pskb(&sk->sk, hlen, dlen,
		m->msg_flags & MSG_DONTWAIT, &err, 0);
	// TODO: verifica err
	if (!skb) {
		pr_info("[%s]: skb = %X, err = %d\n", __func__, skb, err);
		goto out_unlock;
	}

	pr_info("[%s]: skb = %X, err = %d\n", __func__, skb, err);

	skb_reserve(skb, hlen);
	pr_info("[%s]: reserve skb = %X\n", __func__, skb);
	skb_reset_network_header(skb);
	pr_info("[%s]: reset skb = %X\n", __func__, skb);

	// TODO: dlen in loc de total_len?
	offset = dev_hard_header(skb, dev, ETH_P_STP, sk->dst_port ? sk->mac
		: addr->sas_addr, NULL, total_len);
	if (offset < 0) {
		err = -EINVAL;
		goto out_free;
	}

	pr_info("[%s]: offset = %d\n", __func__, offset);

	skb->protocol = htons(ETH_P_STP);
	skb->dev = dev;
	skb->priority = sk->sk.sk_priority;

	hdr = (struct stp_hdr *)skb_put(skb, dlen);
	pr_info("[%s]: hdr = %X\n", __func__, hdr);
	hdr->dst = sk->dst_port ? sk->dst_port : addr->sas_port;
	hdr->src = sk->src_port;
	hdr->len = total_len; // TODO: sau dlen?
	hdr->flags = 0;
	hdr->csum = 0;

	skb->data_len = dlen;
	skb->len += dlen;

	err = skb_copy_datagram_from_iter(skb, offset + sizeof(*hdr),
		&m->msg_iter, total_len);
	if (err)
		goto out_free;

	pr_info("[%s]: copy ok\n", __func__);

	dev_put(dev);
	pr_info("[%s]: dev_put ok\n", __func__);
	dev_queue_xmit(skb);
	pr_info("[%s]: xmit skb = %X\n", __func__, skb);

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
	// int err = 0;
	struct stp_sock *sk = stp_sk(sock);
	// struct sk_buff *skb;

	pr_info("[%s]: src = %hu; dst = %hu; if = %d; MAC = %hhX:%hhX:%hhX:%hhX:%hhX:%hhX\n",
		__func__, ntohs(sk->src_port), ntohs(sk->dst_port), sk->idx,
		sk->mac[0], sk->mac[1], sk->mac[2], sk->mac[3], sk->mac[4],
		sk->mac[5]);

	// do {
	// 	skb = skb_recv_datagram(&sk->sk, flags,
	// 		flags, &err);
	// } while (err == -ERESTARTSYS);
	// pr_info("[stp_recvmsg]: err = %d; skb = 0x%X\n", err, skb);

	++stats.rx_pkts;

	return total_len;
}

static int stp_recv(struct sk_buff *skb, struct net_device *dev,
	struct packet_type *pt, struct net_device *orig_dev)
{
	struct stp_hdr *hdr = (struct stp_hdr *)skb_network_header(skb);

	pr_info("[%s]: src = %hu; dst = %hu; len = %hu; flags = %hhX; csum = %hhX\n",
		__func__, ntohs(hdr->src), ntohs(hdr->dst), hdr->len,
		hdr->flags, hdr->csum);

	consume_skb(skb);
	return NET_RX_SUCCESS;
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
	.obj_size = sizeof(struct stp_sock)
};

static int
stp_create_socket(struct net *net, struct socket *sock, int protocol, int kern)
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

	return 0;
};

static const struct net_proto_family stp_family = {
	.family = AF_STP,
	.create = stp_create_socket,
	.owner = THIS_MODULE,
};

static struct packet_type stp_packet_type = {
	.type = htons(ETH_P_STP),
	.func = stp_recv
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

static void __exit stp_exit(void)
{
	proc_remove(proc_stp);
	dev_remove_pack(&stp_packet_type);
	proto_unregister(&stp_proto);
	sock_unregister(AF_STP);
	// TODO: scoate din hashtable?
}

module_init(stp_init);
module_exit(stp_exit);


MODULE_DESCRIPTION("SO2 Transport Protocol");
MODULE_AUTHOR(
	"Adina Smeu <adina.smeu@gmail.com>, Teodor Dutu <teodor.dutu@gmail.com>"
);
MODULE_LICENSE("GPL v2");
