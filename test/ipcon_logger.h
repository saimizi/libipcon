#ifndef __IPCON_LOGGER_H
#define __IPCON_LOGGER_H

#include <string.h>
#include <stdarg.h>
#include "timestamp_msg.h"

#define LOGGER_PEER_NAME	"ipcon_logger"
#define LOGGER_GROUP_NAME	"ipcon_logger"

#include <sys/time.h>
#include "libipcon.h"

#define LOGGER_MSG_LIMIT	(LIBIPCON_MAX_PAYLOAD_LEN - sizeof(struct timeval))
#define IPCON_LOGGER_MSG_LEN	LOGGER_MSG_LIMIT

struct logger_msg {
	struct timeval ts;
	char msg[IPCON_LOGGER_MSG_LEN];
};

static inline void ipcon_logger(IPCON_HANDLER handler, const char *fmt, ...)
{
	struct logger_msg lm;

	gettimeofday(&lm.ts, NULL);

	if (handler) {
		va_list arg;

		va_start(arg, fmt);
		vsprintf(lm.msg, fmt, arg);
		va_end(arg);

		lm.msg[IPCON_LOGGER_MSG_LEN - 1] = '\0';
		ipcon_send_unicast(handler, LOGGER_PEER_NAME, &lm, sizeof(lm));
	}
}
#endif
