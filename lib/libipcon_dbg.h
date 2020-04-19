#ifndef __LIBIPCON_DEBUG_H__

#define __LIBIPCON_DEBUG_H__

#include <stdio.h>

extern char libipcon_log_level;

#define	LIBIPCONF_LOG_LEVEL_ERROR		1
#define	LIBIPCONF_LOG_LEVEL_WARN		32
#define	LIBIPCONF_LOG_LEVEL_INFO		64
#define	LIBIPCONF_LOG_LEVEL_DEBUG		96

#define ipcon_dbg(fmt, ...)					\
{								\
	if (libipcon_log_level > 95)				\
		fprintf(stderr, "[libipcon] %s-%d DEBUG: "fmt,	\
			__func__, __LINE__, ##__VA_ARGS__);	\
}

#define ipcon_info(fmt, ...) \
{								\
	if (libipcon_log_level > 63)				\
		fprintf(stderr, "[libipcon] %s-%d INFO: "fmt,	\
			__func__, __LINE__, ##__VA_ARGS__);	\
}

#define ipcon_warn(fmt, ...) \
{								\
	if (libipcon_log_level > 31)				\
		fprintf(stderr, "[libipcon] %s-%d WARN: "fmt,	\
			__func__, __LINE__, ##__VA_ARGS__);	\
}

#define ipcon_err(fmt, ...) \
{								\
	if (libipcon_log_level > 0)				\
		fprintf(stderr, "[libipcon] %s-%d ERROR: "fmt,	\
			__func__, __LINE__, ##__VA_ARGS__);	\
}

void libipcon_dbg_init();
#endif
