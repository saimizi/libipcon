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

		ret = ipcon_register_service(handler, srv_name);
		if (ret < 0) {
			ipcon_err("Failed to re-register service: %s (%d)\n",
					strerror(-ret), -ret);
		} else {
			ipcon_info("Re-register service %s succeed.\n",
					srv_name);
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
