#include <linux/init.h>
#include <linux/module.h>
#include <linux/netdevice.h>
#include <linux/etherdevice.h>

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

static const struct net_device_ops rtrd_netdev_ops = {
	.ndo_open = rtrd_open,
	.ndo_stop = rtrd_stop,
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
