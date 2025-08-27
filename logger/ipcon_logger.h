/*
 * This file is part of Libipcon
 * Copyright (C) 2017-2025 Seimizu Joukan
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
 * See the GNU Lesser General Public License for more details.
 */


#ifndef __IPCON_LOGGER_H
#define __IPCON_LOGGER_H

#include <string.h>
#include <stdarg.h>

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
