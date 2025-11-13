#include <linux/init.h>
#include <linux/module.h>
#include <linux/netdevice.h>
#include <linux/etherdevice.h>
#include <linux/gfp_types.h>
#include <linux/skbuff.h>
#include <linux/if_arp.h>
#include <linux/netdevice.h>
#include <linux/mutex.h>
#include <net/ip_tunnels.h>
#include <net/rtnetlink.h>

MODULE_LICENSE("GPL v2");

#define RTRD_DBG(fmt, ...)                                             \
	do {                                                           \
		printk(KERN_DEBUG "[%s:%d] %s(): " fmt "\n", __FILE__, \
		       __LINE__, __func__, ##__VA_ARGS__);             \
	} while (0)

struct rtrd_priv {
	struct mutex lock;
	struct napi_struct napi;
	struct sk_buff_head rx_queue;
};

static int rtrd_poll(struct napi_struct *napi, int budget)
{
	int work_done = 0;
	struct rtrd_priv *priv = container_of(napi, struct rtrd_priv, napi);

	while (work_done < budget) {
		struct sk_buff *skb = skb_dequeue(&priv->rx_queue);
		if (!skb) {
			break;
		}

		RTRD_DBG("RX sk_buff len=%d", skb->len);

		skb->protocol = eth_type_trans(skb, napi->dev);
		skb->ip_summed = CHECKSUM_UNNECESSARY;

		napi_gro_receive(napi, skb);
		work_done++;
	}

	if (work_done < budget) {
		napi_complete_done(napi, work_done);
	}

	RTRD_DBG("Poll done, work_done=%d", work_done);

	return work_done;
}

static int rtrd_open(struct net_device *dev)
{
	struct rtrd_priv *priv = netdev_priv(dev);
	static const u8 mac[ETH_ALEN] = { 0x00, 0x52, 0x54, 0x52, 0x44, 0x00 };

	eth_hw_addr_set(dev, mac);
	napi_enable(&priv->napi);

	netif_carrier_on(dev);
	netif_start_queue(dev);

	return 0;
}

static int rtrd_stop(struct net_device *dev)
{
	struct rtrd_priv *priv = netdev_priv(dev);

	napi_disable(&priv->napi);
	netif_carrier_off(dev);
	netif_stop_queue(dev);
	return 0;
}

static netdev_tx_t rtrd_start_xmit(struct sk_buff *skb, struct net_device *dev)
{
	struct sk_buff *rx_skb;
	struct rtrd_priv *priv = netdev_priv(dev);

	RTRD_DBG("TX sk_buff len=%u", skb->len);

	rx_skb = skb_clone(skb, GFP_ATOMIC);
	if (rx_skb) {
		skb_orphan(rx_skb);
		skb_queue_tail(&priv->rx_queue, rx_skb);
		napi_schedule(&priv->napi);
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
	skb_queue_head_init(&priv->rx_queue);
	netif_napi_add(dev, &priv->napi, rtrd_poll);

	return register_netdevice(dev);
}

static void rtrd_dellink(struct net_device *dev, struct list_head *head)
{
	struct rtrd_priv *priv = netdev_priv(dev);

	netif_napi_del(&priv->napi);
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
	return rtnl_link_register(&rtrd_link_ops);
}

static void __exit rtrd_exit(void)
{
	rtnl_link_unregister(&rtrd_link_ops);
}

module_init(rtrd_init);
module_exit(rtrd_exit);
