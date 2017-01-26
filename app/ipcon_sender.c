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
	fprintf(stderr, "[ipcon_sender] Debug: "fmt, ##__VA_ARGS__)
#define ipcon_info(fmt, ...) \
	fprintf(stderr, "[ipcon_sender] Info: "fmt, ##__VA_ARGS__)
#define ipcon_err(fmt, ...) \
	fprintf(stderr, "[ipcon_sender] Error: "fmt, ##__VA_ARGS__)

#define srv_name	"ipcon_server"
__u32 srv_port;

int main(int argc, char *argv[])
{

	int ret = 0;
	IPCON_HANDLER	handler;

	handler = ipcon_create_handler();
	if (!handler) {
		ipcon_err("Failed to create handler\n");
		return 1;
	}

	do {
		ret = ipcon_find_service(handler, srv_name, &srv_port);
		if (ret < 0) {
			if (ret == -ENOENT)
				ipcon_info("Service %s not found.\n", srv_name);
			else
				ipcon_err("Failed to find service: %s (%d)\n",
					strerror(-ret), -ret);
		} else {
			ipcon_info("Service %s is found at %lu.\n",
				srv_name, (unsigned long)srv_port);

			if (argv[1]) {
				ipcon_info("Send %s to server %lu\n", argv[1],
					(unsigned long)srv_port);
				ret = ipcon_send_unicast(handler,
						srv_port,
						argv[1],
						strlen(argv[1]) + 1);

				if (ret < 0)
					ipcon_err("Send msg error: %s(%d)\n.",
						strerror(-ret), -ret);
			}
		}

	} while (0);

	ret = ipcon_free_handler(handler);

	return ret;
}
