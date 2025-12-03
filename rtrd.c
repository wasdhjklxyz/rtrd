#include <linux/init.h>
#include <linux/module.h>
#include <linux/netdevice.h>
#include <linux/gfp_types.h>
#include <linux/skbuff.h>
#include <linux/if_arp.h>
#include <linux/netdevice.h>
#include <linux/mutex.h>
#include <linux/in.h>
#include <linux/udp.h>
#include <linux/compiler_types.h>
#include <linux/rcupdate.h>
#include <net/ip_tunnels.h>
#include <net/rtnetlink.h>
#include <net/ip.h>
#include <net/udp_tunnel.h>
#include <net/sock.h>
#include <net/route.h>

MODULE_LICENSE("GPL v2");

#define RTRD_PORT 12345

#define RTRD_DBG(fmt, ...)                                             \
	do {                                                           \
		printk(KERN_DEBUG "[%s:%d] %s(): " fmt "\n", __FILE__, \
		       __LINE__, __func__, ##__VA_ARGS__);             \
	} while (0)

struct rtrd_priv {
	struct mutex lock;
	struct net __rcu *net;
	struct socket __rcu *sock;
};

static int rtrd_rcv(struct sock *sk, struct sk_buff *skb)
{
	RTRD_DBG("hello world");
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
		RTRD_DBG("Could not create socket");
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

	RTRD_DBG("Device opened: %s", dev->name);

	return 0;
}

static int rtrd_stop(struct net_device *dev)
{
	struct rtrd_priv *priv = netdev_priv(dev);

	RTRD_DBG("Device stopped: %s", dev->name);

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

	struct iphdr *iph = ip_hdr(skb);
	struct rtrd_priv *priv = netdev_priv(dev);
	struct flowi4 fl = { 0 };

	RTRD_DBG("TX: proto=%u, src=%pI4, dst=%pI4, len=%u", iph->protocol,
		 &iph->saddr, &iph->daddr, skb->len);

	rcu_read_lock_bh();
	sock = rcu_dereference_bh(priv->sock);
	if (!sock) {
		rcu_read_unlock_bh();
		RTRD_DBG("Socket not initialized");
		goto drop;
	}

	/* FIXME: Hardcoded IP for testing. This should be configuration opt */
	__be32 peer_ip = htonl(0xC0000204); // 192.0.2.4

	fl.saddr = 0; // Let kernel choose source
	fl.daddr = peer_ip;
	fl.fl4_dport = htons(RTRD_PORT);
	fl.flowi4_proto = IPPROTO_UDP;

	rt = ip_route_output_flow(sock_net(sock->sk), &fl, sock->sk);
	if (IS_ERR(rt)) {
		rcu_read_unlock_bh();
		RTRD_DBG("Route lookup failed");
		goto drop;
	}

	tos = ip_tunnel_get_dsfield(iph, skb);

	skb->ignore_df = 1;
	udp_tunnel_xmit_skb(rt, sock->sk, skb, fl.saddr, fl.daddr, tos,
			    ip4_dst_hoplimit(&rt->dst), 0,
			    inet_sk(sock->sk)->inet_sport, htons(RTRD_PORT),
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
	dev->mtu = 1420;

	SET_NETDEV_DEVTYPE(dev, &rtrd_device_type);

	memset(priv, 0, sizeof(struct rtrd_priv));
	mutex_init(&priv->lock);
}

static int rtrd_newlink(struct net *src_net, struct net_device *dev,
			struct nlattr *tb[], struct nlattr *data[],
			struct netlink_ext_ack *extack)
{
	struct rtrd_priv *priv = netdev_priv(dev);

	rcu_assign_pointer(priv->net, src_net);

	RTRD_DBG("Creating new device: %s", dev->name);

	return register_netdevice(dev);
}

static void rtrd_dellink(struct net_device *dev, struct list_head *head)
{
	struct rtrd_priv *priv = netdev_priv(dev);

	RTRD_DBG("Deleting device: %s", dev->name);

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

	RTRD_DBG("Module loaded");

	return 0;
}

static void __exit rtrd_exit(void)
{
	rtnl_link_unregister(&rtrd_link_ops);
	RTRD_DBG("Module unloaded");
}

module_init(rtrd_init);
module_exit(rtrd_exit);
