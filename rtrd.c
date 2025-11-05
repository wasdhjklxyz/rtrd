#include <linux/init.h>
#include <linux/module.h>
#include <linux/netdevice.h>

MODULE_LICENSE("GPL-2.0");

#define RTRD_DBG(fmt, ...)                                             \
	do {                                                           \
		printk(KERN_DEBUG "[%s:%d] %s(): " fmt "\n", __FILE__, \
		       __LINE__, __func__, ##__VA_ARGS__);             \
	} while (0)

static struct net_device *rtrd_dev;

static int __init rtrd_init(void)
{
	int ret;

	rtrd_dev = alloc_netdev(0, "rtrd%d", NET_NAME_UNKNOWN, NULL);
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
