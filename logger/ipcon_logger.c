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


#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <netlink/netlink.h>
#include <netlink/socket.h>
#include <netlink/genl/genl.h>
#include <netlink/genl/ctrl.h>
#include <unistd.h>
#include <pthread.h>
#include <errno.h>
#include <string.h>
#include <assert.h>

#include "libipcon.h"
#include "ipcon_logger.h"

#define ipcon_dbg(fmt, ...)                                                    \
	fprintf(stderr, "[ipcon_logger] Debug: " fmt, ##__VA_ARGS__)
#define ipcon_info(fmt, ...)                                                   \
	fprintf(stderr, "[ipcon_logger] Info: " fmt, ##__VA_ARGS__)
#define ipcon_err(fmt, ...)                                                    \
	fprintf(stderr, "[ipcon_logger] Error: " fmt, ##__VA_ARGS__)

#define IPCON_LOGGER_FILE "/var/log/ipcon.log"

FILE *logfile = 0;

static void normal_msg_handler(IPCON_HANDLER handler, struct ipcon_msg *im)
{
	struct logger_msg *lm = (struct logger_msg *)im->buf;

	fprintf(logfile, "[%d.%06d] %s: %s\n", (int)lm->ts.tv_sec,
		(int)lm->ts.tv_usec, im->peer, lm->msg);
}

int main(int argc, char *argv[])
{
	int ret = 0;
	IPCON_HANDLER handler;
	int should_quit = 0;
	struct sched_param sp;

	/* Set FIFO scheduler for logger */
	sp.sched_priority = sched_get_priority_min(SCHED_FIFO);
	sched_setscheduler(0, SCHED_FIFO, &sp);

	logfile = fopen(IPCON_LOGGER_FILE, "a+");
	if (!logfile) {
		ipcon_err("Failed to open logfile\n");
		return 1;
	}

	setvbuf(logfile, NULL, _IONBF, 0);

	handler =
		ipcon_create_handler(LOGGER_PEER_NAME, LIBIPCON_FLG_USE_RCV_IF);
	if (!handler) {
		fclose(logfile);
		ipcon_err("Failed to create handler\n");
		return 1;
	}

	while (!should_quit) {
		struct ipcon_msg im;

		ret = ipcon_rcv(handler, &im);
		if (ret < 0) {
			ipcon_err("%s : %s (%d).\n", LOGGER_PEER_NAME,
				  strerror(-ret), -ret);
			continue;
		}

		if (im.type == LIBIPCON_NORMAL_MSG)
			normal_msg_handler(handler, &im);
	}

	ipcon_free_handler(handler);
	fclose(logfile);

	return ret;
}
