#include <linux/init.h>
#include <linux/module.h>
#include <linux/netdevice.h>
#include <linux/gfp_types.h>
#include <linux/skbuff.h>
#include <linux/if_arp.h>
#include <linux/netdevice.h>
#include <linux/mutex.h>
#include <linux/icmp.h>
#include <net/ip_tunnels.h>
#include <net/rtnetlink.h>
#include <net/ip.h>
#include <net/icmp.h>

MODULE_LICENSE("GPL v2");

#define RTRD_DBG(fmt, ...)                                             \
	do {                                                           \
		printk(KERN_DEBUG "[%s:%d] %s(): " fmt "\n", __FILE__, \
		       __LINE__, __func__, ##__VA_ARGS__);             \
	} while (0)

struct rtrd_priv {
	struct mutex lock;
};

static int rtrd_open(struct net_device *dev)
{
	RTRD_DBG("Device opened: %s", dev->name);

	netif_carrier_on(dev);
	netif_start_queue(dev);

	return 0;
}

static int rtrd_stop(struct net_device *dev)
{
	RTRD_DBG("Device stopped: %s", dev->name);

	netif_carrier_off(dev);
	netif_stop_queue(dev);

	return 0;
}

static netdev_tx_t rtrd_start_xmit(struct sk_buff *skb, struct net_device *dev)
{
	struct iphdr *iph = ip_hdr(skb);
	struct sk_buff *rx_skb;
	struct icmphdr *icmph;
	__be32 tmp_addr;

	RTRD_DBG("TX: proto=%u, src=%pI4, dst=%pI4, len=%u", iph->protocol,
		 &iph->saddr, &iph->daddr, skb->len);

	/* NOTE: Only for educational purposes - this sucks */
	rx_skb = skb_clone(skb, GFP_ATOMIC);
	if (rx_skb) {
		iph = ip_hdr(rx_skb);
		tmp_addr = iph->saddr;
		iph->saddr = iph->daddr;
		iph->daddr = tmp_addr;

		ip_send_check(iph);

		if (iph->protocol == IPPROTO_ICMP) {
			icmph = icmp_hdr(rx_skb);
			if (icmph->type == ICMP_ECHO) {
				icmph->type = ICMP_ECHOREPLY;
				icmph->checksum = 0;
				icmph->checksum = ip_compute_csum(
					icmph, rx_skb->len - ip_hdrlen(rx_skb));
			}
		}

		rx_skb->dev = dev;
		rx_skb->protocol = htons(ETH_P_IP);
		rx_skb->pkt_type = PACKET_HOST;
		rx_skb->ip_summed = CHECKSUM_UNNECESSARY;

		skb_reset_mac_header(rx_skb);
		skb_reset_network_header(rx_skb);

		netif_rx(rx_skb);

		RTRD_DBG("RX: Injected reply packet");
	}

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
}

static int rtrd_newlink(struct net *src_net, struct net_device *dev,
			struct nlattr *tb[], struct nlattr *data[],
			struct netlink_ext_ack *extack)
{
	struct rtrd_priv *priv = netdev_priv(dev);

	mutex_init(&priv->lock);

	RTRD_DBG("Creating new device: %s", dev->name);

	return register_netdevice(dev);
}

static void rtrd_dellink(struct net_device *dev, struct list_head *head)
{
	RTRD_DBG("Deleting device: %s", dev->name);

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
