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
