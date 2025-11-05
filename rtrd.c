#include <linux/init.h>
#include <linux/module.h>
#include <linux/netdevice.h>
#include <linux/etherdevice.h>
#include <linux/gfp_types.h>
#include <linux/skbuff.h>

MODULE_LICENSE("GPL-2.0");

#define RTRD_DBG(fmt, ...)                                             \
	do {                                                           \
		printk(KERN_DEBUG "[%s:%d] %s(): " fmt "\n", __FILE__, \
		       __LINE__, __func__, ##__VA_ARGS__);             \
	} while (0)

static struct net_device *rtrd_dev;

struct rtrd_priv {
	struct net_device_stats stats;
	spinlock_t lock;
};

static int rtrd_open(struct net_device *dev)
{
	eth_hw_addr_set(dev, "\0RTRD"); /* Set fake MAC address */
	netif_start_queue(dev);
	return 0;
}

static int rtrd_stop(struct net_device *dev)
{
	netif_stop_queue(dev);
	return 0;
}

static netdev_tx_t rtrd_start_xmit(struct sk_buff *skb, struct net_device *dev)
{
	struct rtrd_priv *priv = netdev_priv(dev);
	struct sk_buff *rx_skb;

	RTRD_DBG("TX packet len=%u", skb->len);

	priv->stats.tx_packets++;
	priv->stats.tx_bytes += skb->len;
	dev->stats.tx_packets++;
	dev->stats.tx_bytes += skb->len;

	/*
	 * Clone the packet and "receive" it back
	 * This makes the interface work like a loopback
	 */
	rx_skb = skb_clone(skb, GFP_ATOMIC);
	if (rx_skb) {
		rx_skb->dev = dev;
		rx_skb->protocol = eth_type_trans(rx_skb, dev);
		rx_skb->ip_summed = CHECKSUM_UNNECESSARY;

		netif_rx(rx_skb);

		priv->stats.rx_packets++;
		priv->stats.rx_bytes += skb->len;
		dev->stats.rx_packets++;
		dev->stats.rx_bytes += skb->len;

		RTRD_DBG("RX looped packet back");
	}

	dev_kfree_skb(skb);

	return NETDEV_TX_OK;
}

static const struct net_device_ops rtrd_netdev_ops = {
	.ndo_open = rtrd_open,
	.ndo_stop = rtrd_stop,
	.ndo_start_xmit = rtrd_start_xmit,
};

static void rtrd_probe(struct net_device *dev)
{
	struct rtrd_priv *priv;

	ether_setup(dev);

	dev->netdev_ops = &rtrd_netdev_ops;

	/*
	 * IFF_NOARP: We're not using ARP
	 * IFF_POINTOPOINT: This is a tunnel, not broadcast medium
	 */
	dev->flags |= IFF_NOARP | IFF_POINTOPOINT;
	dev->flags &= ~IFF_BROADCAST; /* Not a broadcast device */

	/* We handle our own checksums */
	dev->features |= NETIF_F_HW_CSUM | NETIF_F_HIGHDMA;

	/* Disable header caching - we're not a real Ethernet */
	dev->header_ops = NULL;

	/* WireGuard uses 1420 to fit in Ethernet */
	dev->mtu = 1420;

	priv = netdev_priv(dev);
	memset(priv, 0, sizeof(struct rtrd_priv));
	spin_lock_init(&priv->lock);
}

static int __init rtrd_init(void)
{
	int ret;

	rtrd_dev = alloc_netdev(sizeof(struct rtrd_priv), "rtrd%d",
				NET_NAME_UNKNOWN, rtrd_probe);
	if (!rtrd_dev) {
		RTRD_DBG("alloc_netdev failed");
		return -ENOMEM; /* FIXME: This is just assumption */
	}

	ret = register_netdev(rtrd_dev);
	if (ret < 0) {
		RTRD_DBG("register_netdev failed: %d", ret);
		free_netdev(rtrd_dev);
		return -ret;
	}

	RTRD_DBG("registered as %s", rtrd_dev->name);
	return 0;
}

static void __exit rtrd_exit(void)
{
	if (rtrd_dev) {
		unregister_netdev(rtrd_dev);
		free_netdev(rtrd_dev);
	}
}

module_init(rtrd_init);
module_exit(rtrd_exit);
