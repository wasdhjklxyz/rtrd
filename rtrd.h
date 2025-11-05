#ifndef RTRD_INTERNAL_H
#define RTRD_INTERNAL_H

#define RTRD_DBG(fmt, ...)                                             \
	do {                                                           \
		printk(KERN_DEBUG "[%s:%d] %s(): " fmt "\n", __FILE__, \
		       __LINE__, __func__, ##__VA_ARGS__);             \
	} while (0)

#endif /* RTRD_INTERNAL_H */
