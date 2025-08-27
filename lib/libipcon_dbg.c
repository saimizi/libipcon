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


#include <stdlib.h>
#include <errno.h>
#include "libipcon_dbg.h"

char libipcon_log_level = 1;

void libipcon_dbg_init()
{
	long log_level = -1;
	char *log_level_env = getenv("LIBIPCON_LOG_LEVEL");

	do {
		if (!log_level_env)
			break;

		log_level = strtol(log_level_env, NULL, 10);
		if (errno == ERANGE)
			break;

		if (log_level <= 0) {
			libipcon_log_level = 0;
			break;
		}

		log_level %= 128;

		switch (log_level) {
		case 1 ... 31:
			libipcon_log_level = LIBIPCONF_LOG_LEVEL_ERROR;
			break;
		case 32 ... 63:
			libipcon_log_level = LIBIPCONF_LOG_LEVEL_WARN;
			break;
		case 64 ... 95:
			libipcon_log_level = LIBIPCONF_LOG_LEVEL_INFO;
			break;
		default:
			libipcon_log_level = LIBIPCONF_LOG_LEVEL_DEBUG;
			break;
		}
	} while (0);
}
