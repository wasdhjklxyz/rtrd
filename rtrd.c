#include <linux/init.h>
#include <linux/module.h>

MODULE_LICENSE("GPL-2.0");

#define RTRD_DBG(fmt, ...)                                             \
	do {                                                           \
		printk(KERN_DEBUG "[%s:%d] %s(): " fmt "\n", __FILE__, \
		       __LINE__, __func__, ##__VA_ARGS__);             \
	} while (0)

static int rtrd_init(void)
{
	RTRD_DBG("hello world");
	return 0;
}

static void rtrd_exit(void)
{
	RTRD_DBG("goodbye");
}

module_init(rtrd_init);
module_exit(rtrd_exit);
