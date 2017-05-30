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

#include "libipcon.h"

#define ipcon_dbg(fmt, ...) \
	fprintf(stderr, "[ipcon_cmd] Debug: "fmt, ##__VA_ARGS__)
#define ipcon_info(fmt, ...) \
	fprintf(stderr, "[ipcon_cmd] Info: "fmt, ##__VA_ARGS__)
#define ipcon_err(fmt, ...) \
	fprintf(stderr, "[ipcon_cmd] Error: "fmt, ##__VA_ARGS__)

__u32 srv_port;
#define PEER_NAME	"ipcon_cmd"

void ipcon_cmd_usage(void)
{
	fprintf(stderr, "Usage: ipcon_cmd service msg\n");
}

int main(int argc, char *argv[])
{

	int ret = 0;
	IPCON_HANDLER	handler;

	if (argc < 2) {
		ipcon_cmd_usage();
		return 1;
	}

	handler = ipcon_create_handler(PEER_NAME);
	if (!handler) {
		ipcon_err("Failed to create handler\n");
		return 1;
	}

	do {
		ret = ipcon_find_peer(handler, argv[1], &srv_port);
		if (ret < 0) {
			ipcon_err("No service %s found.\n", argv[1]);
			break;
		}

		ipcon_info("Detected service %s@%lu\n",
				argv[1], (unsigned long)srv_port);

		ret = ipcon_send_unicast(handler,
					srv_port,
					argv[2],
					strlen(argv[2]) + 1);
		if (ret < 0)
			ipcon_err("Send msg error: %s(%d)\n.",
				strerror(-ret), -ret);
	} while (0);

	ipcon_free_handler(handler);

	return ret < 0 ? -ret : ret;
}
