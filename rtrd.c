#include <linux/init.h>
#include <linux/module.h>

MODULE_LICENSE("GPL-2.0");

static int rtrd_init(void)
{
	printk(KERN_ALERT "hello world\n");
	return 0;
}

static void rtrd_exit(void)
{
	printk(KERN_ALERT "goodbye\n");
}

module_init(rtrd_init);
module_exit(rtrd_exit);
