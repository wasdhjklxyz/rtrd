// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2025 uiop <uiop@wasdhjkl.xyz>. All Rights Reserved.
 */

#include <linux/init.h>
#include <linux/module.h>
#include <linux/netdevice.h>
#include <linux/gfp_types.h>
#include <linux/skbuff.h>
#include <linux/if_arp.h>
#include <linux/device.h>
#include <linux/mutex.h>
#include <linux/in.h>
#include <linux/udp.h>
#include <linux/compiler_types.h>
#include <linux/rcupdate.h>
#include <linux/inet.h>
#include <linux/sysfs.h>
#include <net/ip_tunnels.h>
#include <net/rtnetlink.h>
#include <net/ip.h>
#include <net/udp_tunnel.h>
#include <net/sock.h>
#include <net/route.h>
#include <crypto/curve25519.h>

#define RTRD_PORT 12345
#define RTRD_KEY_LEN CURVE25519_KEY_SIZE

#define RTRD_DBG(fmt, ...)                                             \
	do {                                                           \
		printk(KERN_DEBUG "[%s:%d] %s(): " fmt "\n", __FILE__, \
		       __LINE__, __func__, ##__VA_ARGS__);             \
	} while (0)

#define RTRD_LOG(fmt, ...)                                          \
	do {                                                        \
		printk(KERN_INFO "rtrd: " fmt "\n", ##__VA_ARGS__); \
	} while (0)

struct rtrd_priv {
	struct mutex lock;
	struct net __rcu *net;
	struct socket __rcu *sock;
	struct net_device *dev;
	__be32 peer_addr;
	__be16 peer_port;
	u8 publ[RTRD_KEY_LEN];
	u8 priv[RTRD_KEY_LEN];
};

static ssize_t publ_read(struct file *filp, struct kobject *kobj,
			 struct bin_attribute *attr, char *buf, loff_t off,
			 size_t count)
{
	struct device *dev = kobj_to_dev(kobj);
	struct net_device *ndev = to_net_dev(dev);
	struct rtrd_priv *priv = netdev_priv(ndev);

	if (off >= RTRD_KEY_LEN) {
		RTRD_DBG("error: offset >= RTRD_KEY_LEN");
		return 0;
	}

	if (off + count > RTRD_KEY_LEN) {
		RTRD_DBG("warn: truncated public key");
		count = RTRD_KEY_LEN - off;
	}

	memcpy(buf, priv->publ + off, count);
	return count;
}

static ssize_t publ_write(struct file *filp, struct kobject *kobj,
			  struct bin_attribute *attr, char *buf, loff_t off,
			  size_t count)
{
	struct device *dev = kobj_to_dev(kobj);
	struct net_device *ndev = to_net_dev(dev);
	struct rtrd_priv *priv = netdev_priv(ndev);

	if (off != 0 || count != RTRD_KEY_LEN) {
		RTRD_DBG("error: invalid public key len");
		return -EINVAL;
	}

	memcpy(priv->publ, buf, RTRD_KEY_LEN);
	return count;
}

static ssize_t priv_read(struct file *filp, struct kobject *kobj,
			 struct bin_attribute *attr, char *buf, loff_t off,
			 size_t count)
{
	struct device *dev = kobj_to_dev(kobj);
	struct net_device *ndev = to_net_dev(dev);
	struct rtrd_priv *priv = netdev_priv(ndev);

	if (off >= RTRD_KEY_LEN) {
		RTRD_DBG("error: offset >= RTRD_KEY_LEN");
		return 0;
	}

	if (off + count > RTRD_KEY_LEN) {
		RTRD_DBG("warn: truncated privic key");
		count = RTRD_KEY_LEN - off;
	}

	memcpy(buf, priv->priv + off, count);
	return count;
}

static ssize_t priv_write(struct file *filp, struct kobject *kobj,
			  struct bin_attribute *attr, char *buf, loff_t off,
			  size_t count)
{
	struct device *dev = kobj_to_dev(kobj);
	struct net_device *ndev = to_net_dev(dev);
	struct rtrd_priv *priv = netdev_priv(ndev);

	if (off != 0 || count != RTRD_KEY_LEN) {
		RTRD_DBG("error: invalid privic key len");
		return -EINVAL;
	}

	memcpy(priv->priv, buf, RTRD_KEY_LEN);
	return count;
}

static ssize_t peer_show(struct device *d, struct device_attribute *attr,
			 char *buf)
{
	struct net_device *dev = to_net_dev(d);
	struct rtrd_priv *priv = netdev_priv(dev);

	if (priv->peer_addr == 0)
		return sprintf(buf, "(none)\n");

	return sprintf(buf, "%pI4:%u\n", &priv->peer_addr,
		       ntohs(priv->peer_port));
}

static ssize_t peer_store(struct device *dev, struct device_attribute *attr,
			  const char *buf, size_t len)
{
	struct net_device *ndev = to_net_dev(dev);
	struct rtrd_priv *priv = netdev_priv(ndev);
	__be32 addr;
	u16 port = RTRD_PORT;
	char ip_str[64];
	int ret;

	/* Parse "IP:PORT" or just "IP" */
	ret = sscanf(buf, "%63[^:]:%hu", ip_str, &port);
	if (ret < 1) {
		RTRD_DBG("failed to parse peer IP:PORT");
		return -EINVAL;
	}

	if (in4_pton(ip_str, -1, (u8 *)&addr, -1, NULL) == 0) {
		RTRD_DBG("failed to convert peer IP:PORT");
		return -EINVAL;
	}

	priv->peer_addr = addr;
	priv->peer_port = htons(port);

	return len;
}

static DEVICE_ATTR_RW(peer);
static BIN_ATTR_RW(publ, RTRD_KEY_LEN);
static BIN_ATTR_RW(priv, RTRD_KEY_LEN);

static struct attribute *rtrd_attrs[] = {
	&dev_attr_peer.attr,
	NULL,
};

static struct bin_attribute *rtrd_bin_attrs[] = {
	&bin_attr_publ,
	&bin_attr_priv,
	NULL,
};

static const struct attribute_group rtrd_attr_group = {
	.attrs = rtrd_attrs,
	.bin_attrs = rtrd_bin_attrs,
};

static int rtrd_rcv(struct sock *sk, struct sk_buff *skb)
{
	struct rtrd_priv *priv;
	struct net_device *dev;
	struct udphdr *udp;
	struct iphdr *inner_iph, *outer_iph;
	size_t off;

	priv = rcu_dereference_sk_user_data(sk);
	if (!priv) {
		RTRD_DBG("NULL user data");
		kfree_skb(skb);
		return 0;
	}

	dev = priv->dev;

	outer_iph = ip_hdr(skb);
	udp = udp_hdr(skb);
	RTRD_LOG("[RX-ENC] %pI4:%u <- %pI4:%u (%u bytes)", &outer_iph->saddr,
		 udp->source, &outer_iph->daddr, udp->dest, ntohs(udp->len));

	off = (u8 *)udp + sizeof(struct udphdr) - skb->data;

	__skb_pull(skb, off);
	skb_reset_network_header(skb);

	skb->dev = dev;
	skb->protocol = htons(ETH_P_IP);
	skb->pkt_type = PACKET_HOST;

	inner_iph = ip_hdr(skb);
	RTRD_LOG("[RX-TUN] %pI4 ← %pI4 (%u bytes)", &inner_iph->saddr,
		 &inner_iph->daddr, skb->len);

	netif_rx(skb);

	return 0;
}

static void rtrd_socket_free(struct socket *sock)
{
	if (!sock) {
		return;
	}
	if (sock->sk) {
		sk_clear_memalloc(sock->sk);
		udp_tunnel_sock_release(sock->sk->sk_socket);
	}
}

static int rtrd_socket_init(struct rtrd_priv *priv)
{
	struct net *net;
	struct socket *sock = NULL;
	struct socket *old_sock;
	int ret;

	struct udp_tunnel_sock_cfg cfg = {
		.sk_user_data = priv,
		.encap_type = 1,
		.encap_rcv = rtrd_rcv,
	};
	struct udp_port_cfg port = {
		.family = AF_INET,
		.local_ip.s_addr = htonl(INADDR_ANY),
		.local_udp_port = htons(RTRD_PORT),
		.use_udp_checksums = true,
	};

	mutex_lock(&priv->lock);

	rcu_read_lock();
	net = rcu_dereference(priv->net);
	if (!net) {
		rcu_read_unlock();
		RTRD_DBG("NULL net");
		ret = -ENOENT;
		goto out;
	}

	ret = udp_sock_create(net, &port, &sock);
	rcu_read_unlock();
	if (ret < 0) {
		RTRD_DBG("could not create socket");
		goto out;
	}

	sock->sk->sk_allocation = GFP_ATOMIC;
	sock->sk->sk_sndbuf = INT_MAX;
	sk_set_memalloc(sock->sk);
	setup_udp_tunnel_sock(net, sock, &cfg);

	old_sock = rcu_dereference_protected(priv->sock,
					     lockdep_is_held(&priv->lock));
	rcu_assign_pointer(priv->sock, sock);

	if (old_sock) {
		synchronize_rcu();
		rtrd_socket_free(old_sock);
	}

	ret = 0;
out:
	mutex_unlock(&priv->lock);
	return ret;
}

static void rtrd_socket_uninit(struct rtrd_priv *priv)
{
	struct socket *sock;

	mutex_lock(&priv->lock);

	sock = rcu_dereference_protected(priv->sock,
					 lockdep_is_held(&priv->lock));
	rcu_assign_pointer(priv->sock, NULL);

	mutex_unlock(&priv->lock);

	if (sock) {
		synchronize_rcu();
		rtrd_socket_free(sock);
	}
}

static int rtrd_open(struct net_device *dev)
{
	struct rtrd_priv *priv = netdev_priv(dev);
	int ret;

	ret = rtrd_socket_init(priv);
	if (ret < 0) {
		return ret;
	}

	netif_carrier_on(dev);
	netif_start_queue(dev);

	RTRD_LOG("device %s opened (peer: %pI4:%u)", dev->name,
		 &priv->peer_addr, ntohs(priv->peer_port));

	return 0;
}

static int rtrd_stop(struct net_device *dev)
{
	struct rtrd_priv *priv = netdev_priv(dev);

	RTRD_LOG("device %s stopped", dev->name);

	netif_carrier_off(dev);
	netif_stop_queue(dev);

	rtrd_socket_uninit(priv);

	return 0;
}

static netdev_tx_t rtrd_start_xmit(struct sk_buff *skb, struct net_device *dev)
{
	struct socket *sock;
	struct rtable *rt;
	u8 tos;
	int needed_headroom;
	__be32 peer_ip;

	struct iphdr *iph = ip_hdr(skb);
	struct rtrd_priv *priv = netdev_priv(dev);
	struct flowi4 fl = { 0 };

	RTRD_LOG("[TX-TUN] %pI4 -> %pI4 (%u bytes)", &iph->saddr, &iph->daddr,
		 skb->len);

	peer_ip = priv->peer_addr;
	if (!peer_ip) {
		RTRD_DBG("no peer configured for %s", dev->name);
		goto drop;
	}

	rcu_read_lock_bh();
	sock = rcu_dereference_bh(priv->sock);
	if (!sock) {
		rcu_read_unlock_bh();
		RTRD_DBG("socket not initialized");
		goto drop;
	}

	needed_headroom = LL_RESERVED_SPACE(dev) + sizeof(struct iphdr) +
			  sizeof(struct udphdr);

	if (skb_cow_head(skb, needed_headroom)) {
		rcu_read_unlock_bh();
		RTRD_DBG("no headroom");
		goto drop;
	}

	fl.daddr = peer_ip;
	fl.fl4_dport = priv->peer_port;
	fl.flowi4_proto = IPPROTO_UDP;

	rt = ip_route_output_flow(sock_net(sock->sk), &fl, sock->sk);
	if (IS_ERR(rt)) {
		rcu_read_unlock_bh();
		RTRD_DBG("route lookup failed");
		goto drop;
	}

	tos = ip_tunnel_get_dsfield(iph, skb);

	RTRD_LOG("[TX-ENC] %pI4:%u → %pI4:%u (%lu bytes)", &fl.saddr,
		 inet_sk(sock->sk)->inet_sport, &fl.daddr, priv->peer_port,
		 skb->len + sizeof(struct iphdr) + sizeof(struct udphdr));

	skb->ignore_df = 1;
	udp_tunnel_xmit_skb(rt, sock->sk, skb, fl.saddr, fl.daddr, tos,
			    ip4_dst_hoplimit(&rt->dst), 0,
			    inet_sk(sock->sk)->inet_sport, priv->peer_port,
			    false, false);

	rcu_read_unlock_bh();
	return NETDEV_TX_OK;
drop:
	dev_kfree_skb(skb);
	return NETDEV_TX_OK;
}

static const struct net_device_ops rtrd_netdev_ops = {
	.ndo_open = rtrd_open,
	.ndo_stop = rtrd_stop,
	.ndo_start_xmit = rtrd_start_xmit,
};

static const struct device_type rtrd_device_type = { .name = KBUILD_MODNAME };

static void rtrd_setup(struct net_device *dev)
{
	struct rtrd_priv *priv = netdev_priv(dev);
	enum {
		RTRD_NETDEV_FEATURES = NETIF_F_HW_CSUM | NETIF_F_RXCSUM |
				       NETIF_F_HIGHDMA | NETIF_F_SG
	};

	dev->netdev_ops = &rtrd_netdev_ops;
	dev->header_ops = &ip_tunnel_header_ops;
	dev->hard_header_len = 0;
	dev->addr_len = 0;
	dev->type = ARPHRD_NONE;
	dev->flags = IFF_POINTOPOINT | IFF_NOARP;
	dev->priv_flags = IFF_NO_QUEUE;
	dev->features |= RTRD_NETDEV_FEATURES;
	dev->hw_features |= RTRD_NETDEV_FEATURES;
	dev->hw_enc_features |= RTRD_NETDEV_FEATURES;
	dev->lltx = true;
	dev->mtu = ETH_DATA_LEN - sizeof(struct iphdr) - sizeof(struct udphdr);
	dev->needed_headroom =
		LL_MAX_HEADER + sizeof(struct iphdr) + sizeof(struct udphdr);
	dev->pcpu_stat_type = NETDEV_PCPU_STAT_TSTATS;

	SET_NETDEV_DEVTYPE(dev, &rtrd_device_type);

	memset(priv, 0, sizeof(struct rtrd_priv));
	mutex_init(&priv->lock);
}

static int rtrd_newlink(struct net *src_net, struct net_device *dev,
			struct nlattr *tb[], struct nlattr *data[],
			struct netlink_ext_ack *extack)
{
	struct rtrd_priv *priv = netdev_priv(dev);
	int ret;

	rcu_assign_pointer(priv->net, src_net);
	priv->dev = dev;
	priv->peer_addr = 0;
	priv->peer_port = htons(RTRD_PORT);

	ret = register_netdevice(dev);
	if (ret < 0) {
		RTRD_DBG("failed to register device");
		return ret;
	}

	ret = sysfs_create_group(&dev->dev.kobj, &rtrd_attr_group);
	if (ret < 0) {
		RTRD_DBG("failed to create sysfs group");
		unregister_netdevice(dev);
		return ret;
	}

	return 0;
}

static void rtrd_dellink(struct net_device *dev, struct list_head *head)
{
	struct rtrd_priv *priv = netdev_priv(dev);

	sysfs_remove_group(&dev->dev.kobj, &rtrd_attr_group);

	rtrd_socket_uninit(priv);

	rcu_assign_pointer(priv->net, NULL);

	unregister_netdevice_queue(dev, head);
}

static struct rtnl_link_ops rtrd_link_ops = {
	.kind = KBUILD_MODNAME,
	.priv_size = sizeof(struct rtrd_priv),
	.setup = rtrd_setup,
	.newlink = rtrd_newlink,
	.dellink = rtrd_dellink,
};

static int __init rtrd_init(void)
{
	int ret;

	ret = rtnl_link_register(&rtrd_link_ops);
	if (ret < 0) {
		printk(KERN_ERR "rtrd: Failed to register rtnl link ops\n");
		return ret;
	}

	return 0;
}

static void __exit rtrd_exit(void)
{
	rtnl_link_unregister(&rtrd_link_ops);
}

module_init(rtrd_init);
module_exit(rtrd_exit);

MODULE_LICENSE("GPL v2");
MODULE_AUTHOR("uiop <uiop@wasdhjkl.xyz>");
MODULE_DESCRIPTION("Rudimentary P2P UDP tunnel driver");
MODULE_VERSION("0.1.1");
