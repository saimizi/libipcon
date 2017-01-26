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
	fprintf(stderr, "[ipcon_server] Debug: "fmt, ##__VA_ARGS__)
#define ipcon_info(fmt, ...) \
	fprintf(stderr, "[ipcon_server] Info: "fmt, ##__VA_ARGS__)
#define ipcon_err(fmt, ...) \
	fprintf(stderr, "[ipcon_server] Error: "fmt, ##__VA_ARGS__)

#define srv_name	"ipcon_server"

int main(int argc, char *argv[])
{

	int ret = 0;
	IPCON_HANDLER	handler;
	int should_quit = 0;

	handler = ipcon_create_handler();
	if (!handler) {
		ipcon_err("Failed to create handler\n");
		return 1;
	}

	do {
		ret = ipcon_register_service(handler, srv_name);
		if (ret < 0) {
			ipcon_err("Failed to register service: %s (%d)\n",
					strerror(-ret), -ret);
			break;
		}

		ipcon_info("Register service %s succeed.\n", srv_name);

		while (!should_quit) {
			int len = 0;
			char *buf = NULL;
			__u32 port;
			__u32 group;
			__u32 type = 0;

			len = ipcon_rcv(handler, &port, &group, &type,
					(void **)&buf);
			if (len < 0) {
				ipcon_err("Rcv mesg failed: %s(%d).\n",
					strerror(-ret), -ret);
				continue;
			}

			if (type == IPCON_NORMAL_MSG)  {
				ipcon_info("Msg from port %lu: %s.\n",
					(unsigned long)port, buf);

				if (!strcmp(buf, "bye"))
					should_quit = 1;

			} else if (type == IPCON_GROUP_MSG) {
				ipcon_info("Msg from group %lu: %s.\n",
					(unsigned long)group, buf);
			} else {
				ipcon_err("Invalid message type (%lu).\n",
					(unsigned long)type);
			}

			free(buf);

		}

		ret = ipcon_unregister_service(handler);
		if (ret < 0) {
			ipcon_err("Failed to unregister service: %s (%d)\n",
					strerror(-ret), -ret);
			break;
		}
		ipcon_info("Unregister service %s succeed.\n", srv_name);

	} while (0);

	ret = ipcon_free_handler(handler);

	return ret;
}
