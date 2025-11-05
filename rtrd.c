#include <linux/init.h>
#include <linux/module.h>

#include "rtrd.h"

MODULE_LICENSE("GPL-2.0");

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
