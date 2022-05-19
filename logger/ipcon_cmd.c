#include <stdio.h>
#include <stdlib.h>
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
	fprintf(stderr, "[ipcon_cmd] Debug: " fmt, ##__VA_ARGS__)
#define ipcon_info(fmt, ...)                                                   \
	fprintf(stderr, "[ipcon_cmd] Info: " fmt, ##__VA_ARGS__)
#define ipcon_err(fmt, ...)                                                    \
	fprintf(stderr, "[ipcon_cmd] Error: " fmt, ##__VA_ARGS__)

#define PEER_NAME "ipcon_cmd"

void ipcon_cmd_usage(void)
{
	fprintf(stderr, "Usage: ipcon_cmd [lw] -p [peer name] -m <msg>\n");
}

#define IPCON_CMD_LOGGER_MESSAGE (1 << 0)
#define IPCON_CMD_WAIT_PEER (1 << 1)

struct ipcon_cmd_info {
	IPCON_HANDLER handler;
	char *peer;
	char *msg;
};

static void ipcon_cmd_peer_add(char *peer_name, void *data)
{
	struct ipcon_cmd_info *ici = data;

	assert(ici);

	if (!strcmp(peer_name, LOGGER_PEER_NAME)) {
		if (ici->msg)
			ipcon_logger(ici->handler, "%s", ici->msg);
	} else {
		if (ici->msg)
			ipcon_send_unicast(ici->handler, ici->peer, ici->msg,
					   strlen(ici->msg) + 1);
	}

	ipcon_async_rcv_stop(ici->handler);
}

int main(int argc, char *argv[])
{
	int ret = 0;
	int c;
	IPCON_HANDLER handler;
	char *peer = NULL;
	char *msg = NULL;
	unsigned long flag = 0;

	do {
		unsigned long flag = 0;

		while ((c = getopt(argc, argv, "lwhp:m:")) != -1) {
			switch (c) {
			case 'l':
				flag |= IPCON_CMD_LOGGER_MESSAGE;
				peer = LOGGER_PEER_NAME;
				break;
			case 'w':
				flag |= IPCON_CMD_WAIT_PEER;
				break;
			case 'p':
				peer = optarg;
				break;
			case 'm':
				msg = optarg;
				break;
			case 'h':
				ipcon_cmd_usage();
				exit(0);
			case '?':
				ipcon_err("Invalid Option \'-%c\'\n", optopt);
			default:
				abort();
			}
		}

		if (!peer) {
			ipcon_err("No peer specified.\n");
			break;
		}

		handler = ipcon_create_handler(NULL, LIBIPCON_FLG_DEFAULT);
		if (!handler) {
			ipcon_err("Failed to create handler\n");
			break;
		}

		if (!(flag & IPCON_CMD_WAIT_PEER)) {
			if (!is_peer_present(handler, peer)) {
				if (flag & IPCON_CMD_LOGGER_MESSAGE)
					ipcon_err("Logger not found.\n");
				else
					ipcon_err("%s not found.\n", peer);

				ret = -1;
				break;
			}

			if (flag & IPCON_CMD_LOGGER_MESSAGE) {
				if (msg)
					ipcon_logger(handler, "%s", msg);
			} else {
				if (msg)
					ret = ipcon_send_unicast(
						handler, peer, msg,
						strlen(msg) + 1);
			}
			break;
		}

		struct peer_group_info pgi;
		struct async_rcv_ctl arc;
		struct ipcon_cmd_info ici;

		memset(&pgi, 0, sizeof(pgi));
		memset(&arc, 0, sizeof(arc));

		pgi.peer_name = peer;
		arc.pgi = &pgi;
		arc.num = 1;
		arc.cb.peer_add = ipcon_cmd_peer_add;
		arc.cb.data = &ici;

		ici.handler = handler;
		ici.peer = peer;
		ici.msg = msg;

		ret = ipcon_async_rcv(handler, &arc);

	} while (0);

	ipcon_free_handler(handler);

	return ret < 0 ? -ret : ret;
}
