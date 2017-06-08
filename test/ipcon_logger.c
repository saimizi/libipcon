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

#define ipcon_dbg(fmt, ...) \
	fprintf(stderr, "[ipcon_logger] Debug: "fmt, ##__VA_ARGS__)
#define ipcon_info(fmt, ...) \
	fprintf(stderr, "[ipcon_logger] Info: "fmt, ##__VA_ARGS__)
#define ipcon_err(fmt, ...) \
	fprintf(stderr, "[ipcon_logger] Error: "fmt, ##__VA_ARGS__)


static int normal_msg_handler(IPCON_HANDLER handler, struct ipcon_msg *im)
{
	int ret = 0;
	struct logger_msg *lm = (struct logger_msg *)im->buf;

	if (!handler || !im)
		return -EINVAL;

	if (!strcmp(im->buf, "bye"))
		return 1;

	ipcon_info("%s: %s.\n", im->peer, lm->msg);

	ret = ipcon_send_multicast(handler, LOGGER_GROUP_NAME,
			im->buf, im->len);
	if (ret < 0)
		ipcon_err("%s: Failed to send mutlcast message:%s(%d).",
			LOGGER_PEER_NAME, strerror(-ret), -ret);

	return ret;
}

int main(int argc, char *argv[])
{

	int ret = 0;
	IPCON_HANDLER	handler;
	int should_quit = 0;

	handler = ipcon_create_handler(LOGGER_PEER_NAME, SERVICE_PUBLISHER);
	if (!handler) {
		ipcon_err("Failed to create handler\n");
		return 1;
	}

	do {
		ret = ipcon_register_group(handler, LOGGER_PEER_NAME);
		if (ret < 0) {
			ipcon_err("Failed to register group: %s (%d)\n",
					strerror(-ret), -ret);
			break;
		}

		ipcon_info("Register group %s succeed.\n", LOGGER_GROUP_NAME);

		while (!should_quit) {
			struct ipcon_msg im;

			ret = ipcon_rcv(handler, &im);
			if (ret < 0) {
				ipcon_err("%s : %s (%d).\n", LOGGER_PEER_NAME,
					strerror(-ret), -ret);
				continue;


			}

			if (im.type == IPCON_NORMAL_MSG)  {
				assert(strcmp(im.peer, LOGGER_PEER_NAME));

				ret = normal_msg_handler(handler, &im);
				if (ret == 1)
					should_quit = 1;

			}
		}

		ret = ipcon_unregister_group(handler, LOGGER_GROUP_NAME);
		if (ret < 0) {
			ipcon_err("Failed to unregister group: %s (%d)\n",
					strerror(-ret), -ret);
			break;
		}
		ipcon_info("Unregister group %s succeed.\n", LOGGER_GROUP_NAME);

	} while (0);

	ipcon_free_handler(handler);

	return ret;
}
