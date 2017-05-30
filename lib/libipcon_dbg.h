#ifndef __LIBIPCON_DEBUG_H__

#define __LIBIPCON_DEBUG_H__

#define ipcon_dbg(fmt, ...)	\
	fprintf(stderr, "[libipcon] %s-%d DEBUG: "fmt,\
			__func__, __LINE__, ##__VA_ARGS__)
#define ipcon_info(fmt, ...) \
	fprintf(stderr, "[libipcon] %s-%d INFO: "fmt, \
			__func__, __LINE__, ##__VA_ARGS__)
#define ipcon_warn(fmt, ...) \
	fprintf(stderr, "[libipcon] %s-%d WARN: "fmt, \
			__func__, __LINE__, ##__VA_ARGS__)
#define ipcon_err(fmt, ...) \
	fprintf(stderr, "[libipcon] %s-%d ERROR: "fmt, \
			__func__, __LINE__, ##__VA_ARGS__)

#endif
