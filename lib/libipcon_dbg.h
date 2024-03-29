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

#define dump_kevent(ik)								\
{										\
	do {									\
		if (!ik)							\
			break;							\
										\
		if ((ik->type == LIBIPCON_EVENT_PEER_ADD)) {			\
			ipcon_dbg("%s- %d LIBIPCON_EVENT_PEER_ADD %s\n",	\
				__func__, __LINE__,				\
				ik->peer.name);					\
			break;							\
		}								\
										\
		if ((ik->type == LIBIPCON_EVENT_PEER_REMOVE)) {			\
			ipcon_dbg("%s- %d LIBIPCON_EVENT_PEER_REMOVE %s\n",	\
				__func__, __LINE__,				\
				ik->peer.name);					\
			break;							\
		}								\
										\
		if ((ik->type == LIBIPCON_EVENT_GRP_ADD)) {			\
			ipcon_dbg("%s- %d LIBIPCON_EVENT_GRP_ADD %s.%s\n",	\
				__func__, __LINE__,				\
				ik->group.peer_name,				\
				ik->group.name);				\
			break;							\
		}								\
										\
		if ((ik->type == LIBIPCON_EVENT_GRP_REMOVE)) {			\
			ipcon_dbg("%s- %d LIBIPCON_EVENT_GRP_REMOVE %s.%s\n",	\
				__func__, __LINE__,				\
				ik->group.peer_name,				\
				ik->group.name);				\
			break;							\
		}								\
	} while (0);								\
}

void libipcon_dbg_init();
#endif
